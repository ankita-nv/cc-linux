// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 NVIDIA Corporation. All rights reserved.
 *
 * ARMv8 Generic Timer Validation Module
 *
 * This module validates that the ARM generic timer (CNTPCT_EL0/CNTVCT_EL0) is:
 * 1. Never zero (ARMv8 spec requirement)
 * 2. Monotonically increasing on each CPU
 * 3. Synchronized across all CPUs using sync-point-based sampling
 * 4. Synchronized across all NUMA nodes (supports up to 8 nodes)
 *
 * Counter Selection:
 * - Physical Counter (CNTPCT_EL0): Default, for host/bare-metal testing
 * - Virtual Counter (CNTVCT_EL0): Set use_virtual_counter=1 for guest/VM testing
 * - ECV Support: Automatically uses self-synchronized counters on ARMv8.6+
 *
 * Usage:
 *   # Host/Bare-metal:
 *   insmod armv8_timer.ko
 *
 *   # Guest/VM:
 *   insmod armv8_timer.ko use_virtual_counter=1
 *
 *   # Run tests:
 *   echo 1 > /sys/kernel/debug/armv8_timer/trigger
 *   cat /sys/kernel/debug/armv8_timer/results
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/cpuhotplug.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/kthread.h>
#include <linux/topology.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/numa.h>
#include <clocksource/arm_arch_timer.h>
#include <asm/arch_timer.h>
#include <asm/cputype.h>
#include <asm/sysreg.h>
#include <asm/alternative.h>
#include <asm/cpufeature.h>
#include <asm/lse.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shanker Donthineni");
MODULE_DESCRIPTION("ARMv8 Generic Timer Validator");
MODULE_VERSION("1.0");

/* Maximum array sizes (compile-time) */
#define MAX_SAMPLES 8192
#define MAX_SYNC_TESTS 2048

/* Helper macros for time conversions */
#define ticks_to_us(ticks) div64_u64((u64)(ticks) * USEC_PER_SEC, timer_state.timer_freq_hz)
#define ticks_to_ns(ticks) div64_u64((u64)(ticks) * NSEC_PER_SEC, timer_state.timer_freq_hz)
#define ticks_to_us_frac(ticks) div64_u64((u64)(ticks) * USEC_PER_SEC * 1000, timer_state.timer_freq_hz)
#define us_frac_int(us_frac) ((us_frac) / 1000)
#define us_frac_dec(us_frac) ((us_frac) % 1000)

/* Helper macro for cpu_timer_data allocation size */
#define CPU_TIMER_DATA_SIZE(samples) \
	(sizeof(struct cpu_timer_data) + ((samples) * sizeof(u64)))

/* Runtime configurable parameters */
static int num_samples = 1024;  /* Actual samples to take (1 to MAX_SAMPLES) */
static int num_sync_tests = 256;  /* Actual sync tests to run (1 to MAX_SYNC_TESTS) */
static int sync_threshold_ticks = 2000;  /* Max acceptable skew between CPUs (fallback/global) */
static int intra_node_threshold = 1000;  /* Max acceptable skew within a NUMA node */
static int cross_node_threshold = 2000;  /* Max acceptable skew across NUMA nodes */
static unsigned long sample_delay_us = 100;  /* Delay between monotonic samples in microseconds */
static unsigned long sync_test_delay_us = 10000;  /* Delay between sync tests in microseconds */

/* Module parameters */
static int auto_run;
module_param(auto_run, int, 0644);
MODULE_PARM_DESC(auto_run, "Automatically run tests on module load (0=manual via sysfs, 1=auto)");

static int use_virtual_counter;
module_param(use_virtual_counter, int, 0644);
MODULE_PARM_DESC(use_virtual_counter, "Use virtual counter instead of physical (0=CNTPCT_EL0, 1=CNTVCT_EL0 for guest/VM)");

static int use_ecv = -1;  /* -1=auto-detect, 0=disabled, 1=enabled */

/* Forward declarations for parameter callbacks */
static int num_samples_set(const char *val, const struct kernel_param *kp);
static int num_sync_tests_set(const char *val, const struct kernel_param *kp);
static int use_ecv_set(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops num_samples_ops = {
	.set = num_samples_set,
	.get = param_get_int,
};

static const struct kernel_param_ops num_sync_tests_ops = {
	.set = num_sync_tests_set,
	.get = param_get_int,
};

static const struct kernel_param_ops use_ecv_ops = {
	.set = use_ecv_set,
	.get = param_get_int,
};

module_param_cb(use_ecv, &use_ecv_ops, &use_ecv, 0644);
MODULE_PARM_DESC(use_ecv, "Use ECV counters (-1=auto-detect from hardware, 0=force standard counters, 1=force ECV)");

module_param_cb(num_samples, &num_samples_ops, &num_samples, 0644);
MODULE_PARM_DESC(num_samples, "Number of samples per CPU for monotonic test (default: 1024)");

module_param_cb(num_sync_tests, &num_sync_tests_ops, &num_sync_tests, 0644);
MODULE_PARM_DESC(num_sync_tests, "Number of synchronization tests to run (default: 256)");

module_param(sync_threshold_ticks, int, 0644);
MODULE_PARM_DESC(sync_threshold_ticks, "Max acceptable skew between CPUs in timer ticks (default=500)");

module_param(sample_delay_us, ulong, 0644);
MODULE_PARM_DESC(sample_delay_us, "Delay between monotonic samples in microseconds (0-10000, default=100)");

module_param(sync_test_delay_us, ulong, 0644);
MODULE_PARM_DESC(sync_test_delay_us, "Delay between sync tests in microseconds (0-1000000, default=10000)");

module_param(intra_node_threshold, int, 0644);
MODULE_PARM_DESC(intra_node_threshold, "Max acceptable skew within a NUMA node in timer ticks (default=250)");

module_param(cross_node_threshold, int, 0644);
MODULE_PARM_DESC(cross_node_threshold, "Max acceptable skew across NUMA nodes in timer ticks (default=500)");

static int exclude_last_cpu;
module_param(exclude_last_cpu, int, 0644);
MODULE_PARM_DESC(exclude_last_cpu, "Exclude last CPU from skew analysis (0=include all CPUs, 1=exclude last CPU, default=0)");

/*
 * Read ARMv8 timer frequency from CNTFRQ_EL0 register
 * This register contains the clock frequency in Hz
 */
static inline u32 read_cntfrq(void)
{
	u32 freq;

	asm volatile("mrs %0, cntfrq_el0" : "=r" (freq));
	return freq;
}

/* Per-CPU sample data - allocated on local NUMA node for optimal performance */
struct per_cpu_sync_samples {
	u64 samples[MAX_SYNC_TESTS] ____cacheline_aligned;
};

/* Sequential test data */
struct cpu_timer_data {
	unsigned int cpu;
	int numa_node;
	bool monotonic;
	s64 max_delta;
	s64 min_delta;
	s64 avg_delta;
	int backward_idx;   /* Index of first backward jump, -1 if none */
	int zero_delta_idx; /* Index of first zero delta (same timer value), -1 if none */
	int zero_sample_idx;/* Index of first zero sample value (ARMv8 violation), -1 if none */
	s64 backward_delta; /* Delta value of backward jump */
	u64 samples[];  /* Flexible array member */
};

/*
 * Timer synchronization point structure with cache line optimization
 *
 * IMPORTANT: Interrupts must be disabled before calling timer_sync_wait()
 * to ensure truly simultaneous timer sampling. Otherwise, an interrupt
 * occurring between sync point release and timer read would break
 * synchronization and invalidate the test.
 *
 * OPTIMIZATION: Sense-reversing sync point with cache line alignment
 * to minimize cache line bouncing across all CPUs.
 * - counter: On its own cache line, all CPUs increment this
 * - sense: On its own cache line, CPUs spin-read this (read-only after increment)
 */
struct sync_point {
	atomic_t counter ____cacheline_aligned_in_smp;
	atomic_t sense ____cacheline_aligned_in_smp;
	int num_cpus ____cacheline_aligned_in_smp;
	int last_cpu ____cacheline_aligned_in_smp;  /* CPU that set sense=1 */
};

/* Per-sync-test results */
struct sync_test_result {
	int test_num;
	u64 min_val, max_val;
	int min_cpu, max_cpu;
	s64 max_skew;
	bool overall_pass;
	bool intra_node_pass;
	bool cross_node_pass;
	u64 test_duration_ns;
	int last_sense_cpu;  /* CPU that set sense=1 (last to arrive) */

	/* Per-node stats */
	int num_nodes;
	u64 node_min[MAX_NUMNODES];
	u64 node_max[MAX_NUMNODES];
	int node_count[MAX_NUMNODES];
	s64 node_variance[MAX_NUMNODES];

	/* Pairwise node skew matrix (for detailed analysis) */
	s64 pairwise_skew[MAX_NUMNODES][MAX_NUMNODES];
};

/* Overall test session results */
struct test_session_results {
	/* Results validity flag */
	bool valid;

	/* Zero value detection */
	int zero_count;

	/* Monotonic test results */
	int monotonic_pass_count;
	int monotonic_fail_count;
	u64 monotonic_test_duration_ns;

	/* Sync test results */
	int sync_pass_count;
	int sync_fail_count;
	u64 sync_test_duration_ns;
	u64 sync_test_min_ns;
	u64 sync_test_max_ns;

	/* NUMA node detection */
	int num_nodes;
	int node_cpu_count[MAX_NUMNODES];

	/* Array of sync test results */
	struct sync_test_result *sync_results;

	/* Test configuration snapshot - captures values used during test execution */
	int num_samples;       /* Number of samples used in this test run */
	int num_sync_tests;    /* Number of sync tests used in this test run */
	int num_cpus;          /* Number of CPUs that participated in this test */

	/* Overall status */
	bool overall_pass;
};

/*
 * Global state structure - consolidates all module state
 * This improves code organization and makes state management clearer
 */
struct armv8_timer_state {
	/* Core test infrastructure */
	struct cpu_timer_data **timer_data;  /* Array of pointers to NUMA-local allocations */
	struct per_cpu_sync_samples __percpu *sample;  /* Per-CPU memory */
	struct sync_point *sync_point;
	int num_cpus;
	u32 timer_freq_hz;  /* Cached timer frequency */
	struct cpumask target_cpus;  /* CPUs to include in tests */
	struct cpumask display_cpus;  /* CPUs to display in raw_samples (default: all online) */

	/* Memory management and data protection */
	struct mutex mutex;
	int allocated_num_samples;  /* Currently allocated sample count */
	int allocated_num_sync_tests;  /* Currently allocated sync test count */
	bool memory_allocated;  /* Track if memory has been allocated */

	/* CPU hotplug state management */
	enum cpuhp_state hp_state;

	/* Test session results storage - dynamically allocated */
	struct test_session_results *results;

	/* Debugfs interface */
	struct dentry *debugfs_dir;

	/* Barrier performance statistics */
	u64 total_latency_ns;
	u64 min_latency_ns;
	u64 max_latency_ns;
	u64 count;

	/* Test execution timing */
	u64 monotonic_test_ns;
	u64 sync_test_ns;

	/* Test results cache */
	int monotonic_pass;
	int monotonic_fail;
	int zero_found;
	int barrier_pass;
	int barrier_fail;
	char status[64];
};

/* Global state instance */
static struct armv8_timer_state timer_state;

/*
 * Use kernel's arch_timer_read_counter() to read cntpct_el0
 *
 * arch_timer_read_counter() is defined in <asm/arch_timer.h>
 * It works in both bare metal and virtual machines
 * It includes proper barriers and handles both physical and virtual counters
 */

/* Get NUMA node ID for a given CPU */
static inline int get_cpu_numa_node(unsigned int cpu)
{
	int node = cpu_to_node(cpu);

	/*
	 * cpu_to_node() returns -1 if NUMA is not configured or node is invalid
	 * Use 0 as fallback (treat all CPUs as single node)
	 */
	return (node >= 0 && node < MAX_NUMNODES) ? node : 0;
}

/* Clean & Invalidate */
static inline void dc_civac(unsigned long addr)
{
	asm volatile(
		"dc   civac, %0\n"
		"dsb  sy\n"
		: : "r" (addr) : "memory");
}

/* Initialize sense-reversing synchronization point */
static void timer_sync_point_init(struct armv8_timer_state *tms, struct sync_point *spoint)
{
	int num_cpus_for_test;

	/* Use target_cpus for sync point - only test specified CPUs */
	num_cpus_for_test = cpumask_weight(&tms->target_cpus);

	atomic_set(&spoint->counter, 0);
	atomic_set(&spoint->sense, 0);
	spoint->num_cpus = num_cpus_for_test;
	tms->num_cpus = num_cpus_for_test;

	dc_civac((unsigned long)&spoint->sense);
}

/*
 * Physical Counter
 *
 * Atomic Counter Increment:
 * - ARMv8.0: LL/SC (Load-Exclusive/Store-Exclusive) loop
 * - ARMv8.1+ LSE: LDADDAL (single atomic add, much faster under contention)
 *
 * Timer Counter Read:
 * - Standard: ISB + CNTPCT_EL0 (requires barrier)
 * - ARMv8.6+ ECV: CNTPCTSS_EL0 (self-synchronized, no ISB)
 *
 * Used for: Host/bare-metal environments
 */
static noinline u64 timer_sync_wait_sample_phys(struct sync_point *spoint)
{
	u64 timer_val;
	int num_cpus, counter_val, tmp, cpu_id;

	/* Read initial state */
	num_cpus = spoint->num_cpus;
	cpu_id = raw_smp_processor_id();

	asm volatile(
		/* Atomic increment - ALTERNATIVE between LL/SC and LSE */
		"	prfm   pstl1keep, %[counter]\n"
		"	prfm   pldl1keep, %[sense]\n"
		ALTERNATIVE(
			/* ARMv8.0: LL/SC loop (4 instructions) */
			"1:	ldaxr  %w[cnt], %[counter]\n"
			"	add    %w[cnt], %w[cnt], #1\n"
			"	stlxr  %w[tmp], %w[cnt], %[counter]\n"
			"	cbnz   %w[tmp], 1b\n",
			/* ARMv8.1+ LSE: Atomic add (4 instructions for equal size) */
			__LSE_PREAMBLE
			"	mov    %w[tmp], #1\n"
			"	ldaddal %w[tmp], %w[cnt], %[counter]\n"
			"	add    %w[cnt], %w[cnt], #1\n"
			"	nop\n",
			ARM64_HAS_LSE_ATOMICS)
		/* Check if last CPU */
		"	cmp    %w[cnt], %w[num_cpus]\n"
		"	b.ne   2f\n"
		/* LAST CPU PATH */
		"	str    %w[cpu_id], %[last_cpu]\n"
		"	dmb    sy\n"
		"	mov    %w[tmp], #1\n"
		"	stlr   %w[tmp], %[sense]\n"
		/* WAITING CPU PATH (all CPUs including last) */
		"2:	ldar   %w[tmp], %[sense]\n"
		"	cbz    %w[tmp], 2b\n"
		/* TIMER READ - ALTERNATIVE for ECV (2 instructions each) */
		ALTERNATIVE(
			/* Standard: ISB + CNTPCT_EL0 */
			"	isb\n"
			"	mrs    %[timer], cntpct_el0\n",
			/* ARMv8.6+ ECV: Self-synchronized counter (no ISB) */
			"	mrs    %[timer], S3_3_C14_C0_5\n"
			"	nop\n",
			ARM64_HAS_ECV)
		: [timer] "=r" (timer_val),
		  [cnt] "=&r" (counter_val),
		  [tmp] "=&r" (tmp)
		: [counter] "Q" (spoint->counter.counter),
		  [sense] "Q" (spoint->sense.counter),
		  [last_cpu] "Q" (spoint->last_cpu),
		  [num_cpus] "r" (num_cpus),
		  [cpu_id] "r" (cpu_id)
		: "cc", "memory"
	);

	/* Enforce ordering to prevent compiler/CPU reordering of counter read */
	arch_counter_enforce_ordering(timer_val);
	return timer_val;
}

/*
 * Virtual Counter
 *
 * Atomic Counter Increment:
 * - ARMv8.0: LL/SC (Load-Exclusive/Store-Exclusive) loop
 * - ARMv8.1+ LSE: LDADDAL (single atomic add, much faster under contention)
 *
 * Timer Counter Read:
 * - Standard: ISB + CNTVCT_EL0 (requires barrier)
 * - ARMv8.6+ ECV: CNTVCTSS_EL0 (self-synchronized, no ISB)
 *
 * Used for: Guest/VM environments
 */
static noinline u64 timer_sync_wait_sample_virt(struct sync_point *spoint)
{
	u64 timer_val;
	int num_cpus, counter_val, tmp, cpu_id;

	/* Read initial state */
	num_cpus = spoint->num_cpus;
	cpu_id = raw_smp_processor_id();

	asm volatile(
		/* Atomic increment - ALTERNATIVE between LL/SC and LSE */
		"	prfm   pstl1keep, %[counter]\n"
		"	prfm   pldl1keep, %[sense]\n"
		ALTERNATIVE(
			/* ARMv8.0: LL/SC loop (4 instructions) */
			"1:	ldaxr  %w[cnt], %[counter]\n"
			"	add    %w[cnt], %w[cnt], #1\n"
			"	stlxr  %w[tmp], %w[cnt], %[counter]\n"
			"	cbnz   %w[tmp], 1b\n",
			/* ARMv8.1+ LSE: Atomic add (4 instructions for equal size) */
			__LSE_PREAMBLE
			"	mov    %w[tmp], #1\n"
			"	ldaddal %w[tmp], %w[cnt], %[counter]\n"
			"	add    %w[cnt], %w[cnt], #1\n"
			"	nop\n",
			ARM64_HAS_LSE_ATOMICS)
		/* Check if last CPU */
		"	cmp    %w[cnt], %w[num_cpus]\n"
		"	b.ne   2f\n"
		/* LAST CPU PATH */
		"	str    %w[cpu_id], %[last_cpu]\n"
		"	dmb    sy\n"
		"	mov    %w[tmp], #1\n"
		"	stlr   %w[tmp], %[sense]\n"
		/* WAITING CPU PATH (all CPUs including last) */
		"2:	ldar   %w[tmp], %[sense]\n"
		"	cbz    %w[tmp], 2b\n"
		/* TIMER READ - ALTERNATIVE for ECV (2 instructions each) */
		ALTERNATIVE(
			/* Standard: ISB + CNTVCT_EL0 */
			"	isb\n"
			"	mrs    %[timer], cntvct_el0\n",
			/* ARMv8.6+ ECV: Self-synchronized counter (no ISB) */
			"	mrs    %[timer], S3_3_C14_C0_6\n"
			"	nop\n",
			ARM64_HAS_ECV)
		: [timer] "=r" (timer_val),
		  [cnt] "=&r" (counter_val),
		  [tmp] "=&r" (tmp)
		: [counter] "Q" (spoint->counter.counter),
		  [sense] "Q" (spoint->sense.counter),
		  [last_cpu] "Q" (spoint->last_cpu),
		  [num_cpus] "r" (num_cpus),
		  [cpu_id] "r" (cpu_id)
		: "cc", "memory"
	);

	/* Enforce ordering to prevent compiler/CPU reordering of counter read */
	arch_counter_enforce_ordering(timer_val);
	return timer_val;
}

/*
 * Wrapper function for counter type selection
 * Selects between physical and virtual counters based on module parameter
 */
static inline u64 timer_sync_sample(struct sync_point *spoint)
{
	if (use_virtual_counter)
		return timer_sync_wait_sample_virt(spoint);
	else
		return timer_sync_wait_sample_phys(spoint);
}

/* Per-CPU function: Sequential sampling for monotonic test */
static void sample_timer_on_cpu(void *info)
{
	struct armv8_timer_state *tms = &timer_state;
	unsigned int cpu = smp_processor_id();
	struct cpu_timer_data *data = tms->timer_data[cpu];
	int i;

	/* Guard against race condition if CPU came online after allocation */
	if (!data)
		return;

	data->cpu = cpu;
	/* Get NUMA node ID for this CPU */
	data->numa_node = get_cpu_numa_node(cpu);

	/* Take sequential samples for monotonic testing */
	for (i = 0; i < num_samples; i++) {
		data->samples[i] = arch_timer_read_counter();
		if (i < num_samples - 1)
			udelay(sample_delay_us);
	}
}

/* Per-CPU worker: Barrier-based synchronized timer sampling */
static void timer_sync_sample_worker(void *info)
{
	struct armv8_timer_state *tms = &timer_state;
	struct per_cpu_sync_samples *sample;
	int sample_idx = *(int *)info;
	unsigned long flags;

	/* Validate sample index to prevent buffer overflow */
	if (sample_idx < 0 || sample_idx >= MAX_SYNC_TESTS) {
		pr_err("Invalid sample_idx=%d (max=%d) on CPU%d\n",
		       sample_idx, MAX_SYNC_TESTS, raw_smp_processor_id());
		return;
	}

	/*
	 * Disable interrupts during critical sampling section
	 * This prevents CPUs from being scheduled out during synchronization
	 */
	local_irq_save(flags);

	/*
	 * Synchronization point for timer sampling:
	 *
	 * All CPUs wait at the barrier until the last CPU arrives.
	 * The barrier automatically absorbs IPI arrival variance - CPUs arriving
	 * early simply wait for late arrivals, then all release simultaneously.
	 *
	 * timer_sync_wait_sample() reads timer IMMEDIATELY after barrier release
	 * with ZERO branches, minimizing instruction latency for maximum accuracy.
	 *
	 * Write to per-CPU memory (local to this CPU's NUMA node) to avoid
	 * cross-socket memory traffic during critical sampling.
	 */
	sample = this_cpu_ptr(tms->sample);
	sample->samples[sample_idx] = timer_sync_sample(tms->sync_point);

	/*
	 * Re-enable interrupts - on_each_cpu() will ensure all CPUs complete
	 * before returning to the caller, so no additional synchronization needed.
	 */
	local_irq_restore(flags);
}

/* Validate that timer samples are monotonically increasing - stores results only */
static bool validate_monotonic_samples(struct cpu_timer_data *data)
{
	int i;
	s64 min_delta = S64_MAX;
	s64 max_delta = S64_MIN;
	s64 delta, total_delta = 0;
	int delta_count = 0;

	/* Initialize result fields */
	data->monotonic = true;
	data->backward_idx = -1;
	data->zero_delta_idx = -1;
	data->backward_delta = 0;

	for (i = 1; i < num_samples; i++) {
		delta = (s64)(data->samples[i] - data->samples[i-1]);

		if (delta < 0) {
			/* Timer went backward - store first occurrence only */
			data->monotonic = false;
			if (data->backward_idx == -1) {
				data->backward_idx = i;
				data->backward_delta = delta;
			}
		} else if (delta == 0) {
			/* Timer returned same value - store first occurrence only */
			data->monotonic = false;
			if (data->zero_delta_idx == -1)
				data->zero_delta_idx = i;
		}

		min_delta = min(min_delta, delta);
		max_delta = max(max_delta, delta);
		total_delta += delta;
		delta_count++;
	}

	data->min_delta = min_delta;
	data->max_delta = max_delta;
	data->avg_delta = (delta_count > 0) ? (total_delta / delta_count) : 0;

	return data->monotonic;
}

/* Analyze sync-point-synchronized samples - stores results only */
static bool analyze_synchronized_samples(struct armv8_timer_state *tms,
					 int test_num,
					 struct sync_test_result *result)
{
	struct per_cpu_sync_samples *cpu_samples;
	int cpu, node, min_cpu = -1, max_cpu = -1;
	int num_nodes = 0;
	int numa_node;
	u64 min_val = U64_MAX;
	u64 max_val = 0;
	u64 val;
	u64 global_min = U64_MAX;
	u64 global_max = 0;
	s64 max_skew, cross_node_skew, node_range;
	s64 min_diff, max_diff, pairwise_skew;
	bool sync_pass = true;
	bool cross_node_pass = true;
	int node1, node2;

	/* Initialize result structure */
	memset(result, 0, sizeof(*result));
	result->test_num = test_num;
	result->overall_pass = true;
	result->intra_node_pass = true;
	result->cross_node_pass = true;
	result->last_sense_cpu = tms->sync_point->last_cpu;

	/* Initialize node arrays in result structure */
	for (node = 0; node < MAX_NUMNODES; node++) {
		result->node_min[node] = U64_MAX;
		result->node_max[node] = 0;
		result->node_count[node] = 0;
		result->node_variance[node] = 0;
		for (node2 = 0; node2 < MAX_NUMNODES; node2++)
			result->pairwise_skew[node][node2] = 0;
	}

	/* Find min and max values across target CPUs (optionally exclude last CPU) */
	for_each_cpu(cpu, &tms->target_cpus) {
		/* Skip last CPU if exclude_last_cpu is enabled */
		if (exclude_last_cpu && cpu == tms->sync_point->last_cpu)
			continue;

		cpu_samples = per_cpu_ptr(tms->sample, cpu);
		val = cpu_samples->samples[test_num];

		if (val < min_val) {
			min_val = val;
			min_cpu = cpu;
		}
		if (val > max_val) {
			max_val = val;
			max_cpu = cpu;
		}
	}

	/* Safety check: Ensure we found at least one CPU */
	if (min_cpu < 0 || max_cpu < 0) {
		pr_err("ERROR: No online CPUs found during sync analysis\n");
		return false;
	}

	/* Store basic results */
	result->min_val = min_val;
	result->max_val = max_val;
	result->min_cpu = min_cpu;
	result->max_cpu = max_cpu;
	result->max_skew = (s64)(max_val - min_val);
	max_skew = result->max_skew;

	/* Check overall synchronization threshold */
	if (max_skew > sync_threshold_ticks) {
		sync_pass = false;
		result->overall_pass = false;
	}

	/* Collect per-node statistics for target CPUs (optionally exclude last CPU) */
	for_each_cpu(cpu, &tms->target_cpus) {
		if (!tms->timer_data[cpu])
			continue;

		/* Skip last CPU if exclude_last_cpu is enabled */
		if (exclude_last_cpu && cpu == tms->sync_point->last_cpu)
			continue;

		numa_node = tms->timer_data[cpu]->numa_node;
		cpu_samples = per_cpu_ptr(tms->sample, cpu);
		val = cpu_samples->samples[test_num];

		if (numa_node >= 0 && numa_node < MAX_NUMNODES) {
			result->node_min[numa_node] = min(result->node_min[numa_node], val);
			result->node_max[numa_node] = max(result->node_max[numa_node], val);
			if (result->node_count[numa_node] == 0)
				num_nodes++;
			result->node_count[numa_node]++;
		}
	}

	result->num_nodes = num_nodes;

	/* Calculate per-node variance and validate */
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (result->node_count[node] > 0) {
			node_range = result->node_max[node] - result->node_min[node];
			result->node_variance[node] = node_range;

			global_min = min(global_min, result->node_min[node]);
			global_max = max(global_max, result->node_max[node]);

			/* Check within-node threshold */
			if (node_range > intra_node_threshold) {
				cross_node_pass = false;
				result->intra_node_pass = false;
				result->overall_pass = false;
			}
		}
	}

	cross_node_skew = (s64)(global_max - global_min);

	/* Calculate pairwise node skew matrix */
	if (num_nodes > 1) {
		for (node1 = 0; node1 < MAX_NUMNODES; node1++) {
			if (result->node_count[node1] == 0)
				continue;
			for (node2 = node1 + 1; node2 < MAX_NUMNODES; node2++) {
				if (result->node_count[node2] == 0)
					continue;

				min_diff = (s64)(result->node_min[node2] - result->node_min[node1]);
				max_diff = (s64)(result->node_max[node2] - result->node_max[node1]);
				pairwise_skew = max(abs(min_diff), abs(max_diff));

				result->pairwise_skew[node1][node2] = pairwise_skew;
				result->pairwise_skew[node2][node1] = pairwise_skew;  /* Symmetric */

				if (pairwise_skew > cross_node_threshold) {
					cross_node_pass = false;
					result->cross_node_pass = false;
					result->overall_pass = false;
				}
			}
		}

		/* Check global cross-node threshold */
		if (cross_node_skew > cross_node_threshold) {
			cross_node_pass = false;
			result->cross_node_pass = false;
			result->overall_pass = false;
		}
	}

	return sync_pass && cross_node_pass;
}

/* Run sync-point-synchronized sampling tests - stores results only */
static void run_sync_tests(struct armv8_timer_state *tms)
{
	int test;
	bool test_passed;
	ktime_t start_time, end_time, test_start;
	u64 test_duration_ns, single_test_ns;
	u64 min_test_ns = U64_MAX, max_test_ns = 0;

	tms->results->sync_pass_count = 0;
	tms->results->sync_fail_count = 0;

	/* Allocate sync_results array - use kvmalloc for large allocations */
	tms->results->sync_results = kvmalloc_array(num_sync_tests,
						    sizeof(struct sync_test_result),
						    GFP_KERNEL);
	if (!tms->results->sync_results) {
		pr_err("Failed to allocate sync_results array\n");
		tms->results->sync_fail_count = num_sync_tests;
		tms->results->sync_pass_count = 0;
		tms->results->overall_pass = false;
		return;
	}

	/* Start overall timing */
	start_time = ktime_get();

	for (test = 0; test < num_sync_tests; test++) {
		/* Time individual test */
		test_start = ktime_get();

		/* Reset sync point for this test */
		timer_sync_point_init(tms, tms->sync_point);

		/* Trigger synchronized sampling on target CPUs only */
		on_each_cpu_mask(&tms->target_cpus, timer_sync_sample_worker, &test, 1);

		/* Measure test execution time */
		single_test_ns = ktime_to_ns(ktime_sub(ktime_get(), test_start));
		min_test_ns = min(min_test_ns, single_test_ns);
		max_test_ns = max(max_test_ns, single_test_ns);

		/* Store test duration */
		tms->results->sync_results[test].test_duration_ns = single_test_ns;

		/* Track sync point statistics (1 sync point per test) */
		tms->count += 1;
		tms->min_latency_ns = min(tms->min_latency_ns, single_test_ns);
		tms->max_latency_ns = max(tms->max_latency_ns, single_test_ns);
		tms->total_latency_ns += single_test_ns;

		/* Analyze the synchronized samples and store results */
		test_passed = analyze_synchronized_samples(tms, test, &tms->results->sync_results[test]);

		if (test_passed)
			tms->results->sync_pass_count++;
		else
			tms->results->sync_fail_count++;

		/* Brief delay between tests to allow system to settle */
		if (sync_test_delay_us > 0)
			udelay(sync_test_delay_us);
	}

	/* Calculate total test duration */
	end_time = ktime_get();
	test_duration_ns = ktime_to_ns(ktime_sub(end_time, start_time));
	tms->results->sync_test_duration_ns = test_duration_ns;
	tms->results->sync_test_min_ns = min_test_ns;
	tms->results->sync_test_max_ns = max_test_ns;
	tms->sync_test_ns = test_duration_ns;
}

/* Detect zero timer values (critical hardware bug) - stores results only */
static int check_zero_values(struct armv8_timer_state *tms)
{
	int cpu, i;
	int zero_count = 0;

	for_each_online_cpu(cpu) {
		if (!tms->timer_data[cpu])
			continue;

		/* Initialize zero sample index */
		tms->timer_data[cpu]->zero_sample_idx = -1;

		for (i = 0; i < num_samples; i++) {
			if (tms->timer_data[cpu]->samples[i] == 0) {
				/* Store first occurrence only */
				if (tms->timer_data[cpu]->zero_sample_idx == -1)
					tms->timer_data[cpu]->zero_sample_idx = i;
				zero_count++;
			}
		}
	}

	return zero_count;
}

/* Execute all tests - stores results without detailed reporting */
static int execute_all_tests(struct armv8_timer_state *tms)
{
	int cpu;
	int numa_node;
	ktime_t mono_start;

	/* Acquire lock to prevent concurrent memory reallocation during test */
	if (!mutex_trylock(&tms->mutex)) {
		snprintf(tms->status, sizeof(tms->status),
			 "BUSY - reallocation in progress");
		return -EBUSY;
	}

	/* Verify memory has been allocated */
	if (!tms->memory_allocated || !tms->timer_data || !tms->sample ||
	    !tms->sync_point || !tms->results) {
		pr_err("Memory not allocated - cannot run tests\n");
		mutex_unlock(&tms->mutex);
		snprintf(tms->status, sizeof(tms->status),
			 "ERROR - no memory");
		return -ENOMEM;
	}

	/* Verify parameters match allocated memory */
	if (num_samples != tms->allocated_num_samples ||
	    num_sync_tests != tms->allocated_num_sync_tests) {
		pr_err("Parameter mismatch: params=(samples=%d, sync=%d) allocated=(samples=%d, sync=%d)\n",
		       num_samples, num_sync_tests,
		       tms->allocated_num_samples, tms->allocated_num_sync_tests);
		mutex_unlock(&tms->mutex);
		snprintf(tms->status, sizeof(tms->status),
			 "ERROR - memory mismatch");
		return -EINVAL;
	}

	/* Clean up previous test results if any */
	if (tms->results->sync_results) {
		kvfree(tms->results->sync_results);
		tms->results->sync_results = NULL;
	}

	/* Initialize test results structure */
	memset(tms->results, 0, sizeof(struct test_session_results));
	tms->results->overall_pass = true;

	/* Snapshot current test configuration */
	tms->results->num_samples = num_samples;
	tms->results->num_sync_tests = num_sync_tests;
	tms->results->num_cpus = cpumask_weight(&tms->target_cpus);

	/* Sample timers on all CPUs in parallel for speed */
	mono_start = ktime_get();
	on_each_cpu(sample_timer_on_cpu, NULL, 1);
	tms->results->monotonic_test_duration_ns = ktime_to_ns(ktime_sub(ktime_get(), mono_start));
	tms->monotonic_test_ns = tms->results->monotonic_test_duration_ns;

	/* Analyze NUMA node distribution for target CPUs */
	for_each_cpu(cpu, &tms->target_cpus) {
		if (!tms->timer_data[cpu])
			continue;

		numa_node = tms->timer_data[cpu]->numa_node;
		if (numa_node >= 0 && numa_node < MAX_NUMNODES) {
			tms->results->node_cpu_count[numa_node]++;
			if (tms->results->node_cpu_count[numa_node] == 1)
				tms->results->num_nodes++;
		}
	}

	/* Check for zero values first (critical) */
	tms->results->zero_count = check_zero_values(tms);
	tms->zero_found = tms->results->zero_count;

	if (tms->results->zero_count > 0) {
		pr_err("ERROR: Found %d zero timer values!\n", tms->results->zero_count);
		tms->results->overall_pass = false;
	}

	/* Check monotonic behavior on each CPU */
	tms->results->monotonic_pass_count = 0;
	tms->results->monotonic_fail_count = 0;
	for_each_online_cpu(cpu) {
		if (!tms->timer_data[cpu])
			continue;

		if (validate_monotonic_samples(tms->timer_data[cpu])) {
			tms->results->monotonic_pass_count++;
		} else {
			tms->results->monotonic_fail_count++;
			tms->results->overall_pass = false;
		}
	}

	if (tms->results->monotonic_fail_count > 0)
		pr_err("ERROR: Monotonic test failed on %d CPUs\n",
		       tms->results->monotonic_fail_count);

	tms->monotonic_pass = tms->results->monotonic_pass_count;
	tms->monotonic_fail = tms->results->monotonic_fail_count;

	/* Run sync-point-synchronized tests */
	run_sync_tests(tms);

	tms->barrier_pass = tms->results->sync_pass_count;
	tms->barrier_fail = tms->results->sync_fail_count;

	if (tms->results->sync_fail_count > 0)
		tms->results->overall_pass = false;

	/* Update final status */
	if (tms->results->overall_pass)
		snprintf(tms->status, sizeof(tms->status), "PASS");
	else
		snprintf(tms->status, sizeof(tms->status), "FAIL");

	/* Mark results as valid - test completed successfully */
	tms->results->valid = true;

	/* Release lock to allow parameter changes */
	mutex_unlock(&tms->mutex);

	return 0;
}

/* Run all tests */
static int run_all_tests(struct armv8_timer_state *tms)
{
	int ret;

	/* Execute all tests and store results */
	ret = execute_all_tests(tms);
	return ret;
}

/* Sysfs attribute: trigger */
/* Debugfs: trigger - Trigger validation tests */
static ssize_t trigger_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct armv8_timer_state *tms = file->f_inode->i_private;
	char kbuf[16];
	int val, ret;

	if (count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtoint(kbuf, 10, &val) < 0)
		return -EINVAL;

	if (val == 1) {
		ret = run_all_tests(tms);
		if (ret < 0)
			return ret;
	}

	return count;
}

static int trigger_show(struct seq_file *m, void *v)
{
	seq_puts(m, "Write 1 to trigger timer validation tests\n");
	seq_puts(m, "\nUsage:\n");
	seq_puts(m, "  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n");
	return 0;
}

static int trigger_open(struct inode *inode, struct file *file)
{
	return single_open(file, trigger_show, NULL);
}

/* Debugfs: status */
static int status_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	char status_copy[64];

	/* Acquire lock to get consistent status */
	mutex_lock(&tms->mutex);
	memcpy(status_copy, tms->status, sizeof(status_copy));
	status_copy[sizeof(status_copy) - 1] = '\0';
	mutex_unlock(&tms->mutex);

	seq_printf(m, "%s\n", status_copy);
	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, status_show, inode->i_private);
}

/* Debugfs: summary_results - Simple summary (full details in results) */
static int summary_results_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;

	/* Acquire lock to get consistent test results */
	mutex_lock(&tms->mutex);

	/* Check if test results are valid */
	if (!tms->results || !tms->results->valid) {
		seq_printf(m,
			"========================================\n"
			"NO VALID TEST RESULTS\n"
			"========================================\n"
			"Reason: Configuration changed or no tests run yet\n"
			"\n"
			"Action required:\n"
			"  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n"
			"\n"
			"Note: Test results are invalidated when module\n"
			"parameters (num_samples, num_sync_tests) are changed.\n"
			"========================================\n");
		mutex_unlock(&tms->mutex);
		return 0;
	}

	seq_printf(m,
		"========================================\n"
		"ARMv8 TIMER VALIDATION - QUICK SUMMARY\n"
		"========================================\n"
		"Overall Status: %s\n"
		"\n"
		"Test Results:\n"
		"  Monotonic Test:     %s (%d/%d CPUs passed)\n"
		"  Sync Tests:         %d PASS, %d FAIL (out of %d)\n"
		"  Zero values:        %d found\n"
		"\n"
		"System Info:\n"
		"  CPUs tested:        %d (target: %*pbl)\n"
		"  NUMA nodes detected:  %d\n"
		"  Samples per CPU:    %d\n"
		"\n"
		"Performance:\n"
		"  Monotonic test:     %llu ms\n"
		"  Sync test:          %llu ms\n"
		"\n"
		"========================================\n"
		"CONFIGURATION (Module Parameters):\n"
		"  /sys/module/armv8_timer/parameters/\n"
		"    - num_samples\n"
		"    - num_sync_tests\n"
		"    - sync_threshold_ticks\n"
		"    - intra_node_threshold\n"
		"    - cross_node_threshold\n"
		"    - sample_delay_us\n"
		"    - sync_test_delay_us\n"
		"    - use_virtual_counter  (0=physical/host, 1=virtual/guest)\n"
		"\n"
		"Counter Type: %s\n"
		"\n"
		"FULL RESULTS (no size limit):\n"
		"  Debugfs: /sys/kernel/debug/armv8_timer/\n"
		"    - results           (complete test output)\n"
		"    - sync_results      (sync test tables)\n"
		"    - per_cpu_details   (detailed CPU stats)\n"
		"    - raw_samples       (all sample data)\n"
		"    - sync_overhead     (sync point performance)\n"
		"========================================\n"
		"To run tests: echo 1 > trigger\n",
		       tms->status,
		tms->results->monotonic_fail_count == 0 ? "PASS" : "FAIL",
		tms->results->monotonic_pass_count,
		tms->results->monotonic_pass_count + tms->results->monotonic_fail_count,
		tms->results->sync_pass_count,
		tms->results->sync_fail_count,
		tms->results->num_sync_tests,
		tms->results->zero_count,
		tms->results->num_cpus,
		cpumask_pr_args(&tms->target_cpus),
		tms->results->num_nodes,
		tms->results->num_samples,
		tms->results->monotonic_test_duration_ns / NSEC_PER_MSEC,
	       tms->sync_test_ns / NSEC_PER_MSEC,
	       use_virtual_counter ?
	       (use_ecv ? "Virtual (CNTVCT_EL0) with ECV" : "Virtual (CNTVCT_EL0)") :
	       (use_ecv ? "Physical (CNTPCT_EL0) with ECV" : "Physical (CNTPCT_EL0)"));

	mutex_unlock(&tms->mutex);
	return 0;
}

static int summary_results_open(struct inode *inode, struct file *file)
{
	return single_open(file, summary_results_show, inode->i_private);
}

/* Debugfs: num_cpus */
static int num_cpus_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", num_online_cpus());
	return 0;
}

static int num_cpus_open(struct inode *inode, struct file *file)
{
	return single_open(file, num_cpus_show, NULL);
}

/* Debugfs: memory_info */
static int memory_info_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	size_t per_cpu_size, total_timer_data, total_sample_data, total_allocated;
	int num_cpus_snapshot, num_samples_snapshot;

	/* Acquire lock to ensure consistent view of state */
	mutex_lock(&tms->mutex);

	num_cpus_snapshot = tms->num_cpus;
	num_samples_snapshot = num_samples;

	per_cpu_size = CPU_TIMER_DATA_SIZE(num_samples_snapshot);
	total_timer_data = per_cpu_size * num_cpus_snapshot;
	total_sample_data = sizeof(struct per_cpu_sync_samples) * num_cpus_snapshot;
	total_allocated = total_timer_data + total_sample_data + sizeof(struct sync_point);

	mutex_unlock(&tms->mutex);

	seq_printf(m,
		       "Memory Allocation Summary:\n"
		       "==========================\n"
		       "Per-CPU timer_data: %zu bytes x %d CPUs = %zu KB\n"
		       "Per-CPU sample: %zu bytes x %d CPUs = %zu KB\n"
		       "Sync point: %zu bytes\n"
		       "Total allocated: %zu KB (%zu MB)\n"
		       "\nAllocation strategy: NUMA-aware with flexible array members\n"
	       "Samples allocated: %d (max: %d)\n",
	       per_cpu_size, num_cpus_snapshot, total_timer_data / 1024,
	       sizeof(struct per_cpu_sync_samples), num_cpus_snapshot, total_sample_data / 1024,
	       sizeof(struct sync_point),
	       total_allocated / 1024, total_allocated / (1024 * 1024),
	       num_samples_snapshot, MAX_SAMPLES);
	return 0;
}

static int memory_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, memory_info_show, NULL);
}

/* Debugfs file operations for control and info interfaces */
static const struct file_operations trigger_fops = {
	.owner = THIS_MODULE,
	.open = trigger_open,
	.read = seq_read,
	.write = trigger_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations status_fops = {
	.owner = THIS_MODULE,
	.open = status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations summary_results_fops = {
	.owner = THIS_MODULE,
	.open = summary_results_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations num_cpus_fops = {
	.owner = THIS_MODULE,
	.open = num_cpus_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations memory_info_fops = {
	.owner = THIS_MODULE,
	.open = memory_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Helper function to free all allocated memory */
static void free_all_memory(struct armv8_timer_state *tms)
{
	int cpu;

	if (tms->results) {
		kvfree(tms->results->sync_results);
		tms->results->sync_results = NULL;
	}

	kfree(tms->sync_point);
	tms->sync_point = NULL;

	free_percpu(tms->sample);
	tms->sample = NULL;

	if (tms->timer_data) {
		for_each_possible_cpu(cpu) {
			kfree(tms->timer_data[cpu]);
			tms->timer_data[cpu] = NULL;
		}
		kfree(tms->timer_data);
		tms->timer_data = NULL;
	}

	tms->allocated_num_samples = 0;
	tms->allocated_num_sync_tests = 0;
	tms->memory_allocated = false;
}

/* Allocate memory for timer tests */
static int allocate_memory(struct armv8_timer_state *tms, int samples, int sync_tests)
{
	int cpu, first_cpu, node;
	size_t per_cpu_size, total_timer_data, total_sample_data, total_allocated;

	/* Allocate array of pointers for timer_data */
	tms->timer_data = kcalloc(tms->num_cpus, sizeof(*tms->timer_data),
				  GFP_KERNEL);
	if (!tms->timer_data)
		return -ENOMEM;

	/* Allocate NUMA-aware memory for each CPU */
	for_each_possible_cpu(cpu) {
		tms->timer_data[cpu] = kzalloc_node(CPU_TIMER_DATA_SIZE(samples),
						GFP_KERNEL, cpu_to_node(cpu));
		if (!tms->timer_data[cpu])
			goto cleanup_timer_data;
		tms->timer_data[cpu]->cpu = cpu;
		tms->timer_data[cpu]->numa_node = 0xFF;
	}

	/* Allocate per-CPU memory for sync point samples (NUMA-aware) */
	tms->sample = alloc_percpu(struct per_cpu_sync_samples);
	if (!tms->sample) {
		pr_err("ERROR: Failed to allocate per-CPU sample memory\n");
		goto cleanup_timer_data;
	}

	/* Allocate sync point structure on NUMA node of first target CPU */
	first_cpu = cpumask_first(&tms->target_cpus);
	node = cpu_to_node(first_cpu);
	tms->sync_point = kzalloc_node(sizeof(struct sync_point), GFP_KERNEL, node);
	if (!tms->sync_point) {
		pr_err("ERROR: Failed to allocate sync_point memory on node %d\n", node);
		goto cleanup_sample_data;
	}

	/* Calculate and report memory usage */
	per_cpu_size = CPU_TIMER_DATA_SIZE(samples);
	total_timer_data = per_cpu_size * tms->num_cpus;
	total_sample_data = sizeof(struct per_cpu_sync_samples) * tms->num_cpus;
	total_allocated = total_timer_data + total_sample_data + sizeof(struct sync_point);

	tms->allocated_num_samples = samples;
	tms->allocated_num_sync_tests = sync_tests;
	tms->memory_allocated = true;

	return 0;

cleanup_sample_data:
	free_percpu(tms->sample);
	tms->sample = NULL;

cleanup_timer_data:
	for_each_possible_cpu(cpu) {
		kfree(tms->timer_data[cpu]);
		tms->timer_data[cpu] = NULL;
	}
	kfree(tms->timer_data);
	tms->timer_data = NULL;

	return -ENOMEM;
}

/* Reallocate memory when parameters change */
static int reallocate_memory(struct armv8_timer_state *tms, int new_samples, int new_sync_tests)
{
	int ret;

	/* Check if reallocation is actually needed */
	if (new_samples == tms->allocated_num_samples &&
	    new_sync_tests == tms->allocated_num_sync_tests)
		return 0;

	pr_info("Reallocating memory: %dâ†’%d samples, %dâ†’%d sync_tests\n",
		tms->allocated_num_samples, new_samples,
		tms->allocated_num_sync_tests, new_sync_tests);

	/* Invalidate test results - old data is about to be freed */
	tms->results->valid = false;

	/* Free existing memory */
	if (tms->memory_allocated) {
		pr_info("Freeing old memory (samples=%d, sync_tests=%d)\n",
			tms->allocated_num_samples, tms->allocated_num_sync_tests);
		free_all_memory(tms);
	}

	/* Allocate new memory with updated sizes */
	ret = allocate_memory(tms, new_samples, new_sync_tests);
	if (ret < 0) {
		pr_err("ERROR: Failed to reallocate memory\n");
		return ret;
	}

	pr_info("Memory reallocation successful\n");
	return 0;
}

/* Parameter change callbacks */

/* Callback for use_ecv parameter */
static int use_ecv_set(const char *val, const struct kernel_param *kp)
{
	struct armv8_timer_state *tms = &timer_state;
	int new_value, ret;
	int hw_supports_ecv = cpus_have_final_cap(ARM64_HAS_ECV);

	/* Parse and validate new value */
	ret = kstrtoint(val, 10, &new_value);
	if (ret < 0) {
		pr_err("Invalid value for use_ecv: %s\n", val);
		return ret;
	}

	/* Validate range */
	if (new_value < -1 || new_value > 1) {
		pr_err("use_ecv must be -1 (auto), 0 (disabled), or 1 (enabled)\n");
		return -EINVAL;
	}

	/* Validate hardware support */
	if (new_value > 0 && !hw_supports_ecv) {
		pr_err("Cannot enable ECV: hardware does not support it\n");
		return -EINVAL;
	}

	/* Auto-detect if requested */
	if (new_value < 0)
		new_value = hw_supports_ecv ? 1 : 0;

	/* Update the parameter value */
	*(int *)kp->arg = new_value;

	/* Invalidate results if memory is already allocated */
	if (tms->memory_allocated && tms->results) {
		mutex_lock(&tms->mutex);
		tms->results->valid = false;
		mutex_unlock(&tms->mutex);
	}

	return 0;
}

/* Callback for num_samples parameter */
static int num_samples_set(const char *val, const struct kernel_param *kp)
{
	struct armv8_timer_state *tms = &timer_state;
	int new_value, ret;

	/* Parse and validate new value */
	ret = kstrtoint(val, 10, &new_value);
	if (ret < 0) {
		pr_err("Invalid value for num_samples: %s\n", val);
		return ret;
	}

	/* Clamp to valid range */
	if (new_value < 1) {
		pr_warn("num_samples=%d too small, clamping to 1\n", new_value);
		new_value = 1;
	}
	if (new_value > MAX_SAMPLES) {
		pr_warn("num_samples=%d exceeds MAX_SAMPLES=%d, clamping\n",
			new_value, MAX_SAMPLES);
		new_value = MAX_SAMPLES;
	}

	/* If memory hasn't been allocated yet (during module init), just set value */
	if (!tms->memory_allocated) {
		*(int *)kp->arg = new_value;
		return 0;
	}

	/* Acquire lock to prevent concurrent tests during reallocation */
	if (!mutex_trylock(&tms->mutex)) {
		pr_warn("Cannot change num_samples: test in progress or memory being reallocated\n");
		return -EBUSY;
	}

	/* Reallocate memory with new size */
	ret = reallocate_memory(tms, new_value, num_sync_tests);
	if (ret < 0) {
		pr_err("Failed to reallocate memory for num_samples=%d\n", new_value);
		mutex_unlock(&tms->mutex);
		return ret;
	}

	/* Update the parameter value */
	*(int *)kp->arg = new_value;
	mutex_unlock(&tms->mutex);

	pr_info("num_samples successfully changed to %d\n", new_value);
	return 0;
}

/* Callback for num_sync_tests parameter */
static int num_sync_tests_set(const char *val, const struct kernel_param *kp)
{
	struct armv8_timer_state *tms = &timer_state;
	int new_value, ret;

	/* Parse and validate new value */
	ret = kstrtoint(val, 10, &new_value);
	if (ret < 0) {
		pr_err("Invalid value for num_sync_tests: %s\n", val);
		return ret;
	}

	/* Clamp to valid range */
	if (new_value < 1) {
		pr_warn("num_sync_tests=%d too small, clamping to 1\n", new_value);
		new_value = 1;
	}
	if (new_value > MAX_SYNC_TESTS) {
		pr_warn("num_sync_tests=%d exceeds MAX_SYNC_TESTS=%d, clamping\n",
			new_value, MAX_SYNC_TESTS);
		new_value = MAX_SYNC_TESTS;
	}

	/* If memory hasn't been allocated yet (during module init), just set value */
	if (!tms->memory_allocated) {
		*(int *)kp->arg = new_value;
		return 0;
	}

	/* Acquire lock to prevent concurrent tests during reallocation */
	if (!mutex_trylock(&tms->mutex)) {
		pr_warn("Cannot change num_sync_tests: test in progress or memory being reallocated\n");
		return -EBUSY;
	}

	/* Reallocate memory with new size */
	ret = reallocate_memory(tms, num_samples, new_value);
	if (ret < 0) {
		pr_err("Failed to reallocate memory for num_sync_tests=%d\n", new_value);
		mutex_unlock(&tms->mutex);
		return ret;
	}

	/* Update the parameter value */
	*(int *)kp->arg = new_value;
	mutex_unlock(&tms->mutex);

	pr_info("num_sync_tests successfully changed to %d\n", new_value);
	return 0;
}

/*
 * Debugfs interface for detailed debugging
 */

/* Debugfs: raw_samples - Dump all raw timer samples from last test */
static int raw_samples_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	int cpu, i;

	/* Acquire lock to prevent concurrent memory reallocation */
	mutex_lock(&tms->mutex);

	/* Guard: Check if memory is allocated */
	if (!tms->timer_data) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "ERROR: Memory not allocated. Module may not be properly initialized.\n");
		return 0;
	}

	if (!tms->results || !tms->results->valid) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "========================================\n");
		seq_puts(m, "NO VALID TEST RESULTS\n");
		seq_puts(m, "========================================\n");
		seq_puts(m, "Reason: Configuration changed or no tests run yet\n\n");
		seq_puts(m, "Action required:\n");
		seq_puts(m, "  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n\n");
		seq_puts(m, "Note: Test results are invalidated when module\n");
		seq_puts(m, "parameters (num_samples, num_sync_tests) are changed.\n");
		seq_puts(m, "========================================\n");
		return 0;
	}

	seq_puts(m, "Raw Timer Samples from Last Monotonic Test\n");
	seq_puts(m, "===========================================\n");
	seq_printf(m, "Number of samples per CPU: %d\n", tms->results->num_samples);
	if (tms->results->num_samples != num_samples)
		seq_printf(m, "NOTE: Current num_samples=%d differs from test config\n", num_samples);
	seq_printf(m, "Timer frequency: %u Hz (%lu MHz)\n",
		   tms->timer_freq_hz, (unsigned long)(tms->timer_freq_hz / USEC_PER_SEC));
	if (!cpumask_empty(&tms->display_cpus))
		seq_printf(m, "Displaying CPUs: %*pbl\n\n", cpumask_pr_args(&tms->display_cpus));
	else
		seq_puts(m, "Displaying: all online CPUs\n\n");

	/* Use display_cpus if not empty, otherwise show all online CPUs */
	for_each_cpu(cpu, cpumask_empty(&tms->display_cpus) ? cpu_online_mask : &tms->display_cpus) {
		if (!tms->timer_data[cpu])
			continue;

		seq_printf(m, "CPU%d (Node%u):\n", cpu, tms->timer_data[cpu]->numa_node);
		seq_printf(m, "  Monotonic: %s\n", tms->timer_data[cpu]->monotonic ? "PASS" : "FAIL");
		seq_printf(m, "  Min delta: %lld ticks (~%lld ns)\n",
			   tms->timer_data[cpu]->min_delta,
			   ticks_to_ns(tms->timer_data[cpu]->min_delta));
		seq_printf(m, "  Max delta: %lld ticks (~%lld ns)\n",
			   tms->timer_data[cpu]->max_delta,
			   ticks_to_ns(tms->timer_data[cpu]->max_delta));
		seq_puts(m, "  Samples:\n");

		for (i = 0; i < tms->results->num_samples; i++) {
			seq_printf(m, "    [%4d] 0x%016llx", i, tms->timer_data[cpu]->samples[i]);
			if (i > 0) {
				s64 delta = (s64)(tms->timer_data[cpu]->samples[i] -
						  tms->timer_data[cpu]->samples[i-1]);
				seq_printf(m, "  (delta: %lld)", delta);
			}
			seq_puts(m, "\n");
		}
		seq_puts(m, "\n");
	}

	mutex_unlock(&tms->mutex);
	return 0;
}

static int raw_samples_open(struct inode *inode, struct file *file)
{
	return single_open(file, raw_samples_show, inode->i_private);
}

static const struct file_operations raw_samples_fops = {
	.owner = THIS_MODULE,
	.open = raw_samples_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Debugfs: results - Complete test results output */
static int full_results_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	int cpu, node, i, j, test, node1, node2;
	struct cpu_timer_data *data;
	struct sync_test_result *result;
	s64 delta, pairwise_skew, max_node_variance;

	/* Acquire lock to prevent concurrent memory reallocation */
	mutex_lock(&tms->mutex);

	/* Guard: Check if memory is allocated and tests have been run */
	if (!tms->timer_data || !tms->sample || !tms->results) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "ERROR: Memory not allocated. Module may not be properly initialized.\n");
		return 0;
	}

	if (!tms->results->valid) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "========================================\n");
		seq_puts(m, "NO VALID TEST RESULTS\n");
		seq_puts(m, "========================================\n");
		seq_puts(m, "Reason: Configuration changed or no tests run yet\n\n");
		seq_puts(m, "Action required:\n");
		seq_puts(m, "  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n\n");
		seq_puts(m, "Note: Test results are invalidated when module\n");
		seq_puts(m, "parameters (num_samples, num_sync_tests) are changed.\n");
		seq_puts(m, "========================================\n");
		return 0;
	}

	seq_puts(m, "========================================\n");
	seq_puts(m, "ARMv8 Timer Validation Results\n");
	seq_puts(m, "========================================\n");
	seq_printf(m, "Counter Type: %s\n",
		   use_virtual_counter ?
		   (use_ecv ? "Virtual (CNTVCT_EL0) with ECV" : "Virtual (CNTVCT_EL0)") :
		   (use_ecv ? "Physical (CNTPCT_EL0) with ECV" : "Physical (CNTPCT_EL0)"));
	seq_puts(m, "\n");

	/* ============================================ */
	/* SECTION 1: SYNC RESULTS (SKEW ANALYSIS)     */
	/* ============================================ */

	/* Sync results - MOVED TO TOP FOR FOCUS ON SKEW */
	if (tms->results->sync_results) {
		seq_puts(m, "========================================\n");
		seq_puts(m, "TEST 1: Synchronized cross-CPU validation\n");
		seq_puts(m, "========================================\n");
		seq_printf(m, "Synchronized %d CPUs across %d node(s)\n",
			   tms->results->num_cpus, tms->results->num_nodes);
		seq_printf(m, "Test CPUs: %*pbl\n",
			   cpumask_pr_args(&tms->target_cpus));
		seq_printf(m, "Thresholds: sync=%d ticks (~%llu.%03llu us), intra-node=%d ticks (~%llu.%03llu us), cross-node=%d ticks (~%llu.%03llu us)\n\n",
			   sync_threshold_ticks,
			   us_frac_int(ticks_to_us_frac(sync_threshold_ticks)),
			   us_frac_dec(ticks_to_us_frac(sync_threshold_ticks)),
			   intra_node_threshold,
			   us_frac_int(ticks_to_us_frac(intra_node_threshold)),
			   us_frac_dec(ticks_to_us_frac(intra_node_threshold)),
			   cross_node_threshold,
			   us_frac_int(ticks_to_us_frac(cross_node_threshold)),
			   us_frac_dec(ticks_to_us_frac(cross_node_threshold)));

		/* Print table header */
		seq_printf(m, "Sync Test Results Summary%s:\n",
			   exclude_last_cpu ? " (Last CPU excluded from analysis)" : "");
		seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");
		seq_puts(m, "| TestNum | Status | Skew(ticks)  |   Skew(us)     | MinCPU/NodeX | MaxCPU/NodeY | LastCPU |\n");
		seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");

		/* Print ALL tests */
		for (test = 0; test < tms->results->num_sync_tests; test++) {
			result = &tms->results->sync_results[test];

			if (!tms->timer_data[result->min_cpu] ||
			    !tms->timer_data[result->max_cpu]) {
				seq_printf(m, "| %4d | ERROR: NULL pointer in test data |\n",
					   result->test_num);
				continue;
			}

			seq_printf(m, "| %7d | %6s | %12lld | %10llu.%03llu |   %3d/%-2u     |   %3d/%-2u     |  %5d  |\n",
				   result->test_num,
				   result->overall_pass ? "PASS" : "FAIL",
				   result->max_skew,
				   us_frac_int(ticks_to_us_frac(result->max_skew)),
				   us_frac_dec(ticks_to_us_frac(result->max_skew)),
				   result->min_cpu,
				   tms->timer_data[result->min_cpu]->numa_node,
				   result->max_cpu,
				   tms->timer_data[result->max_cpu]->numa_node,
				   result->last_sense_cpu);
		}

		seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");
		seq_printf(m, "Summary: %d PASS, %d FAIL (out of %d tests)\n",
			   tms->results->sync_pass_count,
			   tms->results->sync_fail_count,
			   tms->results->num_sync_tests);
		seq_puts(m, "Note: LastCPU arrived last and set sense=1\n\n");

		/* Show within-node skew for all tests if multiple nodes - one table per node */
		if (tms->results->num_nodes > 1) {
			for (node = 0; node < MAX_NUMNODES; node++) {
				/* Skip nodes with 0 or 1 CPU (skew requires at least 2 CPUs) */
				if (tms->results->sync_results[0].node_count[node] <= 1)
					continue;

				seq_printf(m, "Within node skew (All Tests) - Node %d%s:\n",
					   node, exclude_last_cpu ? " (Last CPU excluded)" : "");
				seq_puts(m, "+---------+----------+--------------+--------------+--------+\n");
				seq_puts(m, "| TestNum | NumCPUs  | Skew(ticks)  |   Skew(us)   | Status |\n");
				seq_puts(m, "+---------+----------+--------------+--------------+--------+\n");

				for (test = 0; test < tms->results->num_sync_tests; test++) {
					result = &tms->results->sync_results[test];

					if (result->node_count[node] > 0) {
						seq_printf(m, "| %7d | %8d | %12lld | %12lld | %6s |\n",
							   test,
							   result->node_count[node],
							   result->node_variance[node],
							   ticks_to_us(result->node_variance[node]),
							   result->node_variance[node] <= intra_node_threshold ?
						   "PASS" : "FAIL");
					}
				}
				seq_puts(m, "+---------+----------+--------------+--------------+--------+\n\n");
			}
		}

		/* Show pairwise node skew for ALL tests if 3+ nodes */
		if (tms->results->num_nodes > 2) {
			seq_printf(m, "Cross-Node Skew (All Tests)%s:\n",
				   exclude_last_cpu ? " (Last CPU excluded)" : "");
			seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n");
			seq_puts(m, "| TestNum | NodeX | NodeY | Skew(ticks)  |   Skew(us)     | Status |\n");
			seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n");

			for (test = 0; test < tms->results->num_sync_tests; test++) {
				result = &tms->results->sync_results[test];

				for (node1 = 0; node1 < MAX_NUMNODES; node1++) {
					if (result->node_count[node1] == 0)
						continue;
					for (node2 = node1 + 1; node2 < MAX_NUMNODES; node2++) {
						if (result->node_count[node2] == 0)
							continue;

						pairwise_skew = result->pairwise_skew[node1][node2];

						seq_printf(m, "| %7d | %5d | %5d | %12lld | %10llu.%03llu | %6s |\n",
							   test, node1, node2,
							   pairwise_skew,
							   us_frac_int(ticks_to_us_frac(pairwise_skew)),
							   us_frac_dec(ticks_to_us_frac(pairwise_skew)),
							   pairwise_skew <= cross_node_threshold ?
					   "PASS" : "FAIL");
					}
				}
			}
			seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n\n");
		}

		/* Per-node summary statistics */
		seq_puts(m, "Per-Node Statistics:\n");
		seq_puts(m, "+---------+----------+-------------+-----------+\n");
		seq_puts(m, "| Node    | NumCPUs  | Intra-Var   |  Status   |\n");
		seq_puts(m, "+---------+----------+-------------+-----------+\n");
		for (node = 0; node < MAX_NUMNODES; node++) {
			/* Skip nodes with 0 or 1 CPU (intra-node variance requires at least 2 CPUs) */
			if (tms->results->node_cpu_count[node] <= 1)
				continue;

			max_node_variance = 0;

			/* Calculate maximum variance for this node across all tests */
			for (test = 0; test < tms->results->num_sync_tests; test++) {
				result = &tms->results->sync_results[test];
				if (result->node_variance[node] > max_node_variance)
					max_node_variance = result->node_variance[node];
			}

			seq_printf(m, "| %7d | %8d | %5lld ticks | %9s |\n",
				   node,
				   tms->results->node_cpu_count[node],
				   max_node_variance,
				   (max_node_variance <= intra_node_threshold) ? "PASS" : "FAIL");
		}
		seq_puts(m, "+---------+----------+-------------+-----------+\n");
		seq_puts(m, "========================================\n");
		seq_puts(m, "Synchronization Test Performance:\n");
		seq_printf(m, "  Total duration: %llu ms (%llu.%03llu seconds)\n",
			   tms->results->sync_test_duration_ns / NSEC_PER_MSEC,
			   tms->results->sync_test_duration_ns / NSEC_PER_SEC,
			   (tms->results->sync_test_duration_ns % NSEC_PER_SEC) / NSEC_PER_MSEC);
		seq_printf(m, "  Per-test timing: min=%llu us, max=%llu us, avg=%llu us\n",
			   tms->results->sync_test_min_ns / NSEC_PER_USEC,
			   tms->results->sync_test_max_ns / NSEC_PER_USEC,
			   tms->results->sync_test_duration_ns /
		   (tms->results->num_sync_tests * NSEC_PER_USEC));
		seq_printf(m, "  Tests per second: %llu\n",
			   (u64)tms->results->num_sync_tests * NSEC_PER_SEC /
		   tms->results->sync_test_duration_ns);
		seq_printf(m, "  Overhead per CPU: ~%llu ns\n",
			   tms->results->sync_test_duration_ns /
		   (tms->results->num_sync_tests *
		    tms->results->num_cpus));
		seq_puts(m, "========================================\n\n");
	}

	/* ============================================ */
	/* SECTION 2: MONOTONIC & ZERO VALUE TESTS     */
	/* ============================================ */

	seq_puts(m, "========================================\n");
	seq_puts(m, "TEST 2: Sequential sampling for monotonic validation\n");
	seq_puts(m, "========================================\n");
	seq_printf(m, "INFO: Monotonic test completed in %llu ms (%d samples x %d CPUs)\n\n",
		   tms->results->monotonic_test_duration_ns / NSEC_PER_MSEC, tms->results->num_samples, tms->results->num_cpus);

	seq_printf(m, "  Total nodes detected: %d\n", tms->results->num_nodes);
	for (node = 0; node < MAX_NUMNODES; node++) {
		if (tms->results->node_cpu_count[node] > 0) {
			seq_printf(m, "  Node %d: %d CPUs\n", node, tms->results->node_cpu_count[node]);
		}
	}
	seq_puts(m, "========================================\n\n");

	if (tms->results->zero_count == 0) {
		seq_puts(m, "PASS: No zero timer values detected\n");
	} else {
		seq_printf(m, "ERROR: Found %d zero values!\n", tms->results->zero_count);
	}
	seq_puts(m, "========================================\n\n");

	seq_puts(m, "========================================\n");
	seq_puts(m, "TEST 3: Monotonic behavior validation\n");
	seq_puts(m, "========================================\n");

	/* Print per-CPU statistics table */
	seq_puts(m, "Per-CPU Monotonic Test Results:\n");
	seq_puts(m, "+------+------+--------------+--------------+--------------+--------+\n");
	seq_puts(m, "| CPU  | Node | Min(ticks)   | Avg(ticks)   | Max(ticks)   | Status |\n");
	seq_puts(m, "+------+------+--------------+--------------+--------------+--------+\n");

	for_each_online_cpu(cpu) {
		data = tms->timer_data[cpu];
		if (!data)
			continue;

		seq_printf(m, "| %4u | %4u | %12lld | %12lld | %12lld | %6s |\n",
			   data->cpu,
			   data->numa_node,
			   data->min_delta,
			   data->avg_delta,
			   data->max_delta,
			   data->monotonic ? "PASS" : "FAIL");
	}

	seq_puts(m, "+------+------+--------------+--------------+--------------+--------+\n");
	seq_printf(m, "Summary: %d PASS, %d FAIL (out of %d CPUs)\n\n",
		   tms->results->monotonic_pass_count,
		   tms->results->monotonic_fail_count,
		   tms->results->monotonic_pass_count + tms->results->monotonic_fail_count);

	/* Report detailed failure information */
	for_each_online_cpu(cpu) {
		data = tms->timer_data[cpu];
		if (!data)
			continue;

		/* Report backward jumps (critical) */
		if (data->backward_idx >= 0) {
			i = data->backward_idx;
			delta = data->backward_delta;

			seq_printf(m, "CRITICAL: CPU%u Node%u - Timer went BACKWARD by %lld ticks at sample[%d]!\n",
				   data->cpu, data->numa_node, -delta, i);
			seq_printf(m, "  sample[%d]=0x%llx -> sample[%d]=0x%llx (BACKWARD JUMP)\n",
				   i-1, data->samples[i-1], i, data->samples[i]);
			seq_puts(m, "  This is a severe hardware/firmware bug!\n");
			seq_printf(m, "  Dumping samples around failure point (sample %d +/- 5):\n", i);

			/* Dump samples around the failure point */
			for (j = max(0, i - 5); j <= min(tms->results->num_samples - 1, i + 5); j++) {
				if (j == i) {
					seq_printf(m, "    sample[%d]=0x%llx  <-- BACKWARD JUMP\n", j, data->samples[j]);
				} else if (j == i - 1) {
					seq_printf(m, "    sample[%d]=0x%llx  (previous)\n", j, data->samples[j]);
				} else {
					seq_printf(m, "    sample[%d]=0x%llx\n", j, data->samples[j]);
				}
			}
		}

		/* Report zero deltas (warnings) */
		if (data->zero_delta_idx >= 0) {
			i = data->zero_delta_idx;

			seq_printf(m, "WARN: CPU%u Node%u - Timer returned same value at sample[%d] (delta=0)\n",
				   data->cpu, data->numa_node, i);
			seq_printf(m, "  sample[%d]=sample[%d]=0x%llx (read within same timer cycle)\n",
				   i-1, i, data->samples[i]);
		}
	}

	/* Final summary */
	if (tms->results->monotonic_fail_count == 0) {
		seq_printf(m, "MONOTONIC: PASS - All %d CPUs monotonic\n",
			   tms->results->monotonic_pass_count);
	} else {
		seq_printf(m, "MONOTONIC: FAIL - %d/%d CPUs failed\n",
			   tms->results->monotonic_fail_count,
			   tms->results->monotonic_pass_count + tms->results->monotonic_fail_count);
	}
	seq_puts(m, "\n");

	/* Final summary */
	seq_puts(m, "========================================\n");
	seq_puts(m, "VALIDATION SUMMARY\n");
	seq_puts(m, "========================================\n");
	seq_puts(m, "Test configuration:\n");
	seq_printf(m, "  - Samples per CPU: %d\n", tms->results->num_samples);
	seq_printf(m, "  - Sync tests: %d\n", tms->results->num_sync_tests);
	seq_puts(m, "  - Thresholds:\n");
	seq_printf(m, "      Global sync: %d ticks (~%lld us)\n",
		   sync_threshold_ticks, ticks_to_us(sync_threshold_ticks));
	seq_printf(m, "      Intra-node: %d ticks (~%lld us)\n",
		   intra_node_threshold, ticks_to_us(intra_node_threshold));
	seq_printf(m, "      Cross-node: %d ticks (~%lld us)\n",
		   cross_node_threshold, ticks_to_us(cross_node_threshold));
	seq_printf(m, "  - Number of CPUs: %d\n", tms->results->num_cpus);
	seq_puts(m, "\n");
	seq_puts(m, "Test results:\n");
	seq_printf(m, "  Zero values: %d found\n", tms->results->zero_count);
	if (tms->results->monotonic_fail_count == 0) {
		seq_printf(m, "  Monotonic Test: PASS (%d CPUs)\n", tms->results->monotonic_pass_count);
	} else {
		seq_printf(m, "  Monotonic Test: FAIL (%d failures)\n", tms->results->monotonic_fail_count);
	}
	seq_printf(m, "  Synchronization tests: %d passed, %d failed (out of %d)\n",
		   tms->results->sync_pass_count,
		   tms->results->sync_fail_count,
		   tms->results->num_sync_tests);

	if (tms->results->overall_pass) {
		seq_puts(m, "\n*** OVERALL: PASS ***\n");
	} else {
		seq_puts(m, "\n*** OVERALL: FAIL ***\n");
	}
	seq_puts(m, "========================================\n");

	mutex_unlock(&tms->mutex);
	return 0;
}

static int full_results_open(struct inode *inode, struct file *file)
{
	return single_open(file, full_results_show, inode->i_private);
}

static const struct file_operations full_results_fops = {
	.owner = THIS_MODULE,
	.open = full_results_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Debugfs: sync_results - Full synchronized test results table */
static int sync_results_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	int test, node, node1, node2;
	struct sync_test_result *result;
	s64 pairwise_skew;

	/* Acquire lock to prevent concurrent memory reallocation */
	mutex_lock(&tms->mutex);

	/* Guard: Check if memory is allocated and tests have been run */
	if (!tms->timer_data || !tms->sample || !tms->sync_point || !tms->results) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "ERROR: Memory not allocated. Module may not be properly initialized.\n");
		return 0;
	}

	if (!tms->results->valid) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "========================================\n");
		seq_puts(m, "NO VALID TEST RESULTS\n");
		seq_puts(m, "========================================\n");
		seq_puts(m, "Reason: Configuration changed or no tests run yet\n\n");
		seq_puts(m, "Action required:\n");
		seq_puts(m, "  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n\n");
		seq_puts(m, "Note: Test results are invalidated when module\n");
		seq_puts(m, "parameters (num_samples, num_sync_tests) are changed.\n");
		seq_puts(m, "========================================\n");
		return 0;
	}

	seq_puts(m, "========================================\n");
	seq_puts(m, "TEST 1: Synchronized cross-CPU validation\n");
	seq_puts(m, "========================================\n");
	seq_printf(m, "Counter Type: %s\n",
		   use_virtual_counter ?
		   (use_ecv ? "Virtual (CNTVCT_EL0) with ECV" : "Virtual (CNTVCT_EL0)") :
		   (use_ecv ? "Physical (CNTPCT_EL0) with ECV" : "Physical (CNTPCT_EL0)"));
		seq_printf(m, "Synchronized %d CPUs across %d node(s)\n",
			   tms->results->num_cpus, tms->results->num_nodes);
		seq_printf(m, "Test CPUs: %*pbl\n",
			   cpumask_pr_args(&tms->target_cpus));
		seq_printf(m, "Thresholds: sync=%d ticks (~%llu.%03llu us), intra-node=%d ticks (~%llu.%03llu us), cross-node=%d ticks (~%llu.%03llu us)\n\n",
			   sync_threshold_ticks,
			   us_frac_int(ticks_to_us_frac(sync_threshold_ticks)),
			   us_frac_dec(ticks_to_us_frac(sync_threshold_ticks)),
			   intra_node_threshold,
			   us_frac_int(ticks_to_us_frac(intra_node_threshold)),
			   us_frac_dec(ticks_to_us_frac(intra_node_threshold)),
			   cross_node_threshold,
			   us_frac_int(ticks_to_us_frac(cross_node_threshold)),
			   us_frac_dec(ticks_to_us_frac(cross_node_threshold)));

		/* Print table header */
		seq_printf(m, "Sync Test Results Summary%s:\n",
			   exclude_last_cpu ? " (Last CPU excluded from analysis)" : "");
	seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");
	seq_puts(m, "| TestNum | Status | Skew(ticks)  |   Skew(us)     | MinCPU/NodeX | MaxCPU/NodeY | LastCPU |\n");
	seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");

	/* Print ALL tests - no size limit in debugfs */
	for (test = 0; test < tms->results->num_sync_tests; test++) {
		result = &tms->results->sync_results[test];

		/* Safety: Check for NULL pointers before dereferencing */
		if (!tms->timer_data[result->min_cpu] || !tms->timer_data[result->max_cpu]) {
			seq_printf(m, "| %7d | ERROR: NULL pointer in test data |\n", result->test_num);
			continue;
		}

		seq_printf(m, "| %7d | %6s | %12lld | %10llu.%03llu |   %3d/%-2u     |   %3d/%-2u     |  %5d  |\n",
			   result->test_num,
			   result->overall_pass ? "PASS" : "FAIL",
			   result->max_skew,
			   us_frac_int(ticks_to_us_frac(result->max_skew)),
			   us_frac_dec(ticks_to_us_frac(result->max_skew)),
			   result->min_cpu,
			   tms->timer_data[result->min_cpu]->numa_node,
			   result->max_cpu,
			   tms->timer_data[result->max_cpu]->numa_node,
			   result->last_sense_cpu);
	}

	seq_puts(m, "+---------+--------+--------------+----------------+--------------+--------------+---------+\n");
	seq_printf(m, "Summary: %d PASS, %d FAIL (out of %d tests)\n",
		   tms->results->sync_pass_count, tms->results->sync_fail_count, num_sync_tests);
	seq_puts(m, "Note: LastCPU arrived last and set sense=1\n\n");

	/* Show within-node skew for all tests if multiple nodes - one table per node */
	if (tms->results->num_nodes > 1) {
		for (node = 0; node < MAX_NUMNODES; node++) {
			/* Skip nodes with 0 or 1 CPU (skew requires at least 2 CPUs) */
			if (tms->results->sync_results[0].node_count[node] <= 1)
				continue;

			seq_printf(m, "Within node skew (All Tests) - Node %d%s:\n",
				   node, exclude_last_cpu ? " (Last CPU excluded)" : "");
			seq_puts(m, "+---------+----------+--------------+----------------+--------+\n");
			seq_puts(m, "| TestNum | NumCPUs  | Skew(ticks)  |   Skew(us)     | Status |\n");
			seq_puts(m, "+---------+----------+--------------+----------------+--------+\n");

			for (test = 0; test < tms->results->num_sync_tests; test++) {
				result = &tms->results->sync_results[test];

				if (result->node_count[node] > 0) {
					seq_printf(m, "| %7d | %8d | %12lld | %10llu.%03llu | %6s |\n",
						   test,
						   result->node_count[node],
						   result->node_variance[node],
						   us_frac_int(ticks_to_us_frac(result->node_variance[node])),
						   us_frac_dec(ticks_to_us_frac(result->node_variance[node])),
						   result->node_variance[node] <= intra_node_threshold ?
						   "PASS" : "FAIL");
				}
			}
			seq_puts(m, "+---------+----------+--------------+----------------+--------+\n\n");
		}
	}

	/* Show pairwise node skew for ALL tests if 3+ nodes */
	if (tms->results->num_nodes > 2) {
		seq_printf(m, "Cross-Node Skew (All Tests)%s:\n",
			   exclude_last_cpu ? " (Last CPU excluded)" : "");
	seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n");
	seq_puts(m, "| TestNum | NodeX | NodeY | Skew(ticks)  |   Skew(us)     | Status |\n");
	seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n");

	for (test = 0; test < tms->results->num_sync_tests; test++) {
		result = &tms->results->sync_results[test];

		for (node1 = 0; node1 < MAX_NUMNODES; node1++) {
			if (result->node_count[node1] == 0)
				continue;
			for (node2 = node1 + 1; node2 < MAX_NUMNODES; node2++) {
				if (result->node_count[node2] == 0)
					continue;

				pairwise_skew = result->pairwise_skew[node1][node2];

				seq_printf(m, "| %7d | %5d | %5d | %12lld | %10llu.%03llu | %6s |\n",
					   test, node1, node2, pairwise_skew,
					   us_frac_int(ticks_to_us_frac(pairwise_skew)),
					   us_frac_dec(ticks_to_us_frac(pairwise_skew)),
					   pairwise_skew <= cross_node_threshold ?
					   "PASS" : "FAIL");
			}
		}
	}
	seq_puts(m, "+---------+-------+-------+--------------+----------------+--------+\n\n");
	}

	/* Show per-node statistics if multiple nodes */
	if (tms->results->num_nodes > 1) {
		seq_puts(m, "Per-Node Statistics:\n");
		seq_puts(m, "+------+----------+-------------+-----------+\n");
		seq_puts(m, "| Node | NumCPUs  |  Intra-Var  |  Status   |\n");
		seq_puts(m, "+------+----------+-------------+-----------+\n");

		/* Show first test's node info */
		if (num_sync_tests > 0) {
			result = &tms->results->sync_results[0];

			for (node = 0; node < MAX_NUMNODES; node++) {
				/* Skip nodes with 0 or 1 CPU (intra-node variance requires at least 2 CPUs) */
				if (result->node_count[node] <= 1)
					continue;

				seq_printf(m, "| %4d | %8d | %5lld ticks | %9s |\n",
					   node,
					   result->node_count[node],
					   result->node_variance[node],
					   result->node_variance[node] <= intra_node_threshold ? "PASS" : "FAIL");
			}
		}
		seq_puts(m, "+------+----------+-------------+-----------+\n\n");
	}

	/* Performance statistics */
	seq_puts(m, "========================================\n");
	seq_puts(m, "Synchronization Test Performance:\n");
	seq_printf(m, "  Total duration: %llu ms (%llu.%03llu seconds)\n",
		   tms->results->sync_test_duration_ns / NSEC_PER_MSEC,
		   tms->results->sync_test_duration_ns / NSEC_PER_SEC,
		   (tms->results->sync_test_duration_ns / NSEC_PER_MSEC) % MSEC_PER_SEC);
	seq_printf(m, "  Per-test timing: min=%llu us, max=%llu us, avg=%llu us\n",
		   tms->results->sync_test_min_ns / NSEC_PER_USEC,
		   tms->results->sync_test_max_ns / NSEC_PER_USEC,
		   tms->results->sync_test_duration_ns /
		   (num_sync_tests * NSEC_PER_USEC));
	seq_printf(m, "  Tests per second: %llu\n",
		   (u64)tms->results->num_sync_tests * NSEC_PER_SEC /
		   tms->results->sync_test_duration_ns);
	seq_printf(m, "  Overhead per CPU: ~%llu ns\n",
		   tms->results->sync_test_duration_ns /
		   (tms->results->num_sync_tests *
		    tms->results->num_cpus));
	seq_puts(m, "========================================\n");

	mutex_unlock(&tms->mutex);
	return 0;
}

static int sync_results_open(struct inode *inode, struct file *file)
{
	return single_open(file, sync_results_show, inode->i_private);
}

static const struct file_operations sync_results_fops = {
	.owner = THIS_MODULE,
	.open = sync_results_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Debugfs: target_cpus - Set which CPUs participate in time_sync tests */
static int target_cpus_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;

	seq_printf(m, "Test CPUs: %*pbl\n", cpumask_pr_args(&tms->target_cpus));
	seq_printf(m, "Online CPUs: %*pbl\n", cpumask_pr_args(cpu_online_mask));
	seq_puts(m, "\nUsage:\n");
	seq_puts(m, "  Set specific CPUs for testing: echo 0,5,10-15 > target_cpus\n");
	seq_puts(m, "  Reset to all online:           echo > target_cpus\n");
	seq_puts(m, "\nNote: These CPUs will participate in synchronization (time_sync) tests.\n");
	seq_puts(m, "      Changing this will invalidate previous test results.\n");
	return 0;
}

static ssize_t target_cpus_write(struct file *file, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct armv8_timer_state *tms = file->f_inode->i_private;
	char buf[256];
	size_t len;
	int ret;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	/* Remove trailing newline if present */
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	/* Acquire mutex to prevent concurrent tests */
	if (!mutex_trylock(&tms->mutex)) {
		pr_warn("Cannot change target_cpus: test in progress\n");
		return -EBUSY;
	}

	/* Empty string = reset to all online CPUs */
	if (buf[0] == '\0' || buf[0] == '\n') {
		cpumask_copy(&tms->target_cpus, cpu_online_mask);

		/* Reallocate sync_point on NUMA node of first target CPU */
		if (tms->sync_point) {
			int first_cpu = cpumask_first(&tms->target_cpus);
			int node = cpu_to_node(first_cpu);
			struct sync_point *new_sync_point;

			new_sync_point = kzalloc_node(sizeof(struct sync_point), GFP_KERNEL, node);
			if (!new_sync_point) {
				pr_err("Failed to reallocate sync_point on node %d\n", node);
				mutex_unlock(&tms->mutex);
				return -ENOMEM;
			}
			kfree(tms->sync_point);
			tms->sync_point = new_sync_point;
		}

		/* Invalidate results since test configuration changed */
		if (tms->results)
			tms->results->valid = false;
		mutex_unlock(&tms->mutex);
		return count;
	}

	/* Parse CPU list */
	ret = cpulist_parse(buf, &tms->target_cpus);
	if (ret) {
		pr_err("Invalid CPU list format: %s\n", buf);
		mutex_unlock(&tms->mutex);
		return ret;
	}

	/* Validate CPUs are online */
	if (!cpumask_subset(&tms->target_cpus, cpu_online_mask)) {
		pr_warn("Some CPUs in list are not online, intersecting with online CPUs\n");
		cpumask_and(&tms->target_cpus, &tms->target_cpus, cpu_online_mask);
	}

	/* Ensure at least one CPU is selected */
	if (cpumask_empty(&tms->target_cpus)) {
		pr_err("Cannot set empty CPU list, keeping previous configuration\n");
		mutex_unlock(&tms->mutex);
		return -EINVAL;
	}

	/* Reallocate sync_point on NUMA node of first target CPU */
	if (tms->sync_point) {
		int first_cpu = cpumask_first(&tms->target_cpus);
		int node = cpu_to_node(first_cpu);
		struct sync_point *new_sync_point;

		new_sync_point = kzalloc_node(sizeof(struct sync_point), GFP_KERNEL, node);
		if (!new_sync_point) {
			pr_err("Failed to reallocate sync_point on node %d\n", node);
			mutex_unlock(&tms->mutex);
			return -ENOMEM;
		}
		kfree(tms->sync_point);
		tms->sync_point = new_sync_point;
	}

	/* Invalidate results since test configuration changed */
	if (tms->results)
		tms->results->valid = false;

	mutex_unlock(&tms->mutex);
	return count;
}

static int target_cpus_open(struct inode *inode, struct file *file)
{
	return single_open(file, target_cpus_show, inode->i_private);
}

static const struct file_operations target_cpus_fops = {
	.owner = THIS_MODULE,
	.open = target_cpus_open,
	.read = seq_read,
	.write = target_cpus_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Debugfs: display_cpus - Set which CPUs to display in raw_samples */
static int display_cpus_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;

	if (cpumask_empty(&tms->display_cpus)) {
		seq_puts(m, "Displaying: all online CPUs (default)\n");
		seq_printf(m, "Online CPUs: %*pbl\n", cpumask_pr_args(cpu_online_mask));
	} else {
		seq_printf(m, "Display CPUs: %*pbl\n", cpumask_pr_args(&tms->display_cpus));
	}
	seq_puts(m, "\nUsage:\n");
	seq_puts(m, "  Set specific CPUs: echo 0,5,10-15 > display_cpus\n");
	seq_puts(m, "  Reset to all:      echo > display_cpus\n");
	seq_puts(m, "\nNote: This only controls which CPUs are displayed in raw_samples.\n");
	seq_puts(m, "      Use target_cpus to control which CPUs participate in tests.\n");
	return 0;
}

static ssize_t display_cpus_write(struct file *file, const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct armv8_timer_state *tms = file->f_inode->i_private;
	char buf[256];
	size_t len;
	int ret;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	/* Remove trailing newline if present */
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	/* Empty string = reset to all CPUs */
	if (buf[0] == '\0' || buf[0] == '\n') {
		cpumask_clear(&tms->display_cpus);
		cpumask_copy(&tms->display_cpus, cpu_online_mask);
		pr_info("Display CPUs reset to all online CPUs\n");
		return count;
	}

	/* Parse CPU list */
	ret = cpulist_parse(buf, &tms->display_cpus);
	if (ret) {
		pr_err("Invalid CPU list format: %s\n", buf);
		return ret;
	}

	/* Validate CPUs are possible */
	if (!cpumask_subset(&tms->display_cpus, cpu_possible_mask)) {
		pr_err("Some CPUs in list are not possible\n");
		cpumask_and(&tms->display_cpus, &tms->display_cpus, cpu_possible_mask);
	}

	pr_info("Display CPUs updated to: %*pbl\n", cpumask_pr_args(&tms->display_cpus));
	return count;
}

static int display_cpus_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_cpus_show, inode->i_private);
}

static const struct file_operations display_cpus_fops = {
	.owner = THIS_MODULE,
	.open = display_cpus_open,
	.read = seq_read,
	.write = display_cpus_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/* Debugfs: sync_overhead - Barrier synchronization overhead/performance metrics */
static int sync_overhead_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	u64 avg_latency_ns = 0;

	seq_puts(m, "Synchronization Overhead Statistics\n");
	seq_puts(m, "====================================\n\n");

	if (tms->count == 0) {
		seq_puts(m, "No overhead statistics available. Run a sync test first.\n");
		return 0;
	}

	avg_latency_ns = tms->total_latency_ns / tms->count;

	seq_printf(m, "Total barriers executed: %llu\n", tms->count);
	seq_printf(m, "Average latency: %llu ns (~%llu us)\n",
		   avg_latency_ns, avg_latency_ns / NSEC_PER_USEC);
	seq_printf(m, "Minimum latency: %llu ns (~%llu us)\n",
		   tms->min_latency_ns, tms->min_latency_ns / NSEC_PER_USEC);
	seq_printf(m, "Maximum latency: %llu ns (~%llu us)\n",
		   tms->max_latency_ns, tms->max_latency_ns / NSEC_PER_USEC);
	seq_printf(m, "Latency range: %llu ns (~%llu us)\n",
		   tms->max_latency_ns - tms->min_latency_ns,
		   (tms->max_latency_ns - tms->min_latency_ns) / NSEC_PER_USEC);
	seq_puts(m, "\nConfiguration:\n");
	seq_printf(m, "  Number of CPUs: %d\n", num_online_cpus());
	seq_printf(m, "  Sync tests run: %d\n", num_sync_tests);
	seq_puts(m, "  Barrier type: Sense-reversing with cache-line optimization\n");

	return 0;
}

static int sync_overhead_open(struct inode *inode, struct file *file)
{
	return single_open(file, sync_overhead_show, inode->i_private);
}

static const struct file_operations sync_overhead_fops = {
	.owner = THIS_MODULE,
	.open = sync_overhead_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* NOTE: The following interfaces have been moved from sysfs to debugfs:
 * - trigger (control), status (read), results (read)
 * - num_cpus (read), memory_info (read)
 */

/* Debugfs: raw_samples - Show raw timer samples (will be defined below) */
/* Debugfs: per_cpu_details - Detailed per-CPU statistics */
static int per_cpu_details_show(struct seq_file *m, void *v)
{
	struct armv8_timer_state *tms = m->private;
	int cpu;
	int node_cpu_count[MAX_NUMNODES] = {0};
	size_t per_cpu_size, total_timer_data, total_sample_data, total_allocated;

	/* Acquire lock to prevent concurrent memory reallocation */
	mutex_lock(&tms->mutex);

	/* Guard: Check if memory is allocated */
	if (!tms->timer_data || !tms->sample || !tms->results) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "ERROR: Memory not allocated. Module may not be properly initialized.\n");
		return 0;
	}

	if (!tms->results->valid) {
		mutex_unlock(&tms->mutex);
		seq_puts(m, "========================================\n");
		seq_puts(m, "NO VALID TEST RESULTS\n");
		seq_puts(m, "========================================\n");
		seq_puts(m, "Reason: Configuration changed or no tests run yet\n\n");
		seq_puts(m, "Action required:\n");
		seq_puts(m, "  echo 1 > /sys/kernel/debug/armv8_timer/trigger\n\n");
		seq_puts(m, "Note: Test results are invalidated when module\n");
		seq_puts(m, "parameters (num_samples, num_sync_tests) are changed.\n");
		seq_puts(m, "========================================\n");
		return 0;
	}

	seq_puts(m, "Per-CPU Detailed Statistics\n");
	seq_puts(m, "============================\n\n");

	seq_puts(m, "System Configuration:\n");
	seq_printf(m, "  Possible CPUs: %d\n", num_possible_cpus());
	seq_printf(m, "  Online CPUs: %d\n", num_online_cpus());
	seq_printf(m, "  Test CPUs: %d (cpumask: %*pbl)\n",
		   cpumask_weight(&tms->target_cpus), cpumask_pr_args(&tms->target_cpus));
	seq_printf(m, "  Timer frequency: %u Hz (%lu MHz)\n",
		   tms->timer_freq_hz, (unsigned long)(tms->timer_freq_hz / USEC_PER_SEC));
	seq_printf(m, "  Samples per CPU: %d (max: %d)\n", tms->results->num_samples, MAX_SAMPLES);
	seq_printf(m, "  Sync tests: %d (max: %d)\n", tms->results->num_sync_tests, MAX_SYNC_TESTS);
	if (tms->results->num_samples != num_samples || tms->results->num_sync_tests != num_sync_tests) {
		seq_printf(m, "  NOTE: Current module params differ (samples=%d, sync_tests=%d)\n",
			   num_samples, num_sync_tests);
	}

	/* Memory usage report */
	per_cpu_size = CPU_TIMER_DATA_SIZE(num_samples);
	total_timer_data = per_cpu_size * tms->num_cpus;
	total_sample_data = sizeof(struct per_cpu_sync_samples) * tms->num_cpus;
	total_allocated = total_timer_data + total_sample_data + sizeof(struct sync_point);

	seq_puts(m, "\nMemory Usage:\n");
	seq_printf(m, "  Per-CPU timer_data: %zu bytes x %d = %zu KB\n",
		   per_cpu_size, tms->num_cpus, total_timer_data / 1024);
	seq_printf(m, "  Per-CPU sample: %zu bytes x %d = %zu KB\n",
		   sizeof(struct per_cpu_sync_samples), tms->num_cpus, total_sample_data / 1024);
	seq_printf(m, "  Total allocated: %zu KB (%zu MB)\n",
		   total_allocated / 1024, total_allocated / (1024 * 1024));
	seq_puts(m, "\n");

	/* Count CPUs per node */
	for_each_online_cpu(cpu) {
		if (tms->timer_data[cpu] && tms->timer_data[cpu]->numa_node < MAX_NUMNODES)
			node_cpu_count[tms->timer_data[cpu]->numa_node]++;
	}

	seq_puts(m, "NUMA Node Distribution:\n");
	for (cpu = 0; cpu < MAX_NUMNODES; cpu++) {
		if (node_cpu_count[cpu] > 0) {
			seq_printf(m, "  Node %d: %d CPUs\n",
				   cpu, node_cpu_count[cpu]);
		}
	}
	seq_puts(m, "\n");

	seq_puts(m, "Per-CPU Details:\n");
	seq_puts(m, "----------------\n");
	for_each_online_cpu(cpu) {
		if (!tms->timer_data[cpu])
			continue;

		seq_printf(m, "CPU%d:\n", cpu);
		seq_printf(m, "  NUMA Node: %u\n", tms->timer_data[cpu]->numa_node);
		seq_printf(m, "  NUMA node: %d\n", cpu_to_node(cpu));
		seq_printf(m, "  Monotonic test: %s\n",
			   tms->timer_data[cpu]->monotonic ? "PASS" : "FAIL");
		seq_printf(m, "  Min delta: %lld ticks (~%lld ns)\n",
			   tms->timer_data[cpu]->min_delta,
			   ticks_to_ns(tms->timer_data[cpu]->min_delta));
		seq_printf(m, "  Max delta: %lld ticks (~%lld ns)\n",
			   tms->timer_data[cpu]->max_delta,
			   ticks_to_ns(tms->timer_data[cpu]->max_delta));
		seq_printf(m, "  Delta range: %lld ticks (~%lld ns)\n",
			   tms->timer_data[cpu]->max_delta - tms->timer_data[cpu]->min_delta,
			   ticks_to_ns(tms->timer_data[cpu]->max_delta - tms->timer_data[cpu]->min_delta));
		seq_puts(m, "\n");
	}

	mutex_unlock(&tms->mutex);
	return 0;
}

static int per_cpu_details_open(struct inode *inode, struct file *file)
{
	return single_open(file, per_cpu_details_show, inode->i_private);
}

static const struct file_operations per_cpu_details_fops = {
	.owner = THIS_MODULE,
	.open = per_cpu_details_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/*
 * CPU hotplug callbacks
 * Handle CPUs coming online/offline to maintain data structure integrity
 */

static int armv8_timer_cpu_online(unsigned int cpu)
{
	struct armv8_timer_state *tms = &timer_state;

	/*
	 * CPU is coming online - add it to test cpumask
	 * NUMA node ID will be detected during test execution on the CPU itself
	 *
	 * Note: Acquire mutex to prevent racing with ongoing tests
	 */
	mutex_lock(&tms->mutex);

	if (tms->memory_allocated && tms->timer_data && tms->timer_data[cpu]) {
		tms->timer_data[cpu]->cpu = cpu;
		tms->timer_data[cpu]->numa_node = 0xFF;  /* Will be set during test */

		/* Add CPU to test cpumask so it's included in next test */
		cpumask_set_cpu(cpu, &tms->target_cpus);

		pr_debug("CPU%d came online, added to test cpumask\n", cpu);
	}

	mutex_unlock(&tms->mutex);
	return 0;
}

static int armv8_timer_cpu_offline(unsigned int cpu)
{
	struct armv8_timer_state *tms = &timer_state;

	/*
	 * CPU is going offline - remove it from test cpumask
	 *
	 * Note: Acquire mutex to prevent racing with ongoing tests
	 * This ensures a CPU doesn't go offline while a test is running
	 */
	mutex_lock(&tms->mutex);

	/* Remove CPU from test cpumask to avoid testing offline CPUs */
	cpumask_clear_cpu(cpu, &tms->target_cpus);

	pr_debug("CPU%d went offline, removed from test cpumask\n", cpu);

	mutex_unlock(&tms->mutex);
	return 0;
}

/* Module initialization */
static int __init armv8_timer_init(void)
{
	struct armv8_timer_state *tms = &timer_state;
	int ret;

	/* Initialize state structure */
	memset(&timer_state, 0, sizeof(timer_state));
	mutex_init(&tms->mutex);
	tms->min_latency_ns = U64_MAX;
	strscpy(tms->status, "Not run yet", sizeof(tms->status));

	/* Auto-detect ECV and LSE support */
	if (cpus_have_final_cap(ARM64_HAS_ECV)) {
		if (use_ecv < 0) {
			use_ecv = 1;
		}
		pr_info("ECV (Enhanced Counter Virtualization) supported\n");
	} else {
		if (use_ecv > 0) {
			pr_warn("ECV requested but not supported by hardware, forcing use_ecv=0\n");
		}
		use_ecv = 0;
	}

	if (cpus_have_final_cap(ARM64_HAS_LSE_ATOMICS)) {
		pr_info("LSE atomics supported\n");
	}

	/*
	 * Counter type selection
	 * - Virtual counter (CNTVCT_EL0) used in guest/VM
	 * - Physical counter (CNTPCT_EL0) for host/bare-metal
	 */
	pr_info("Using %s counter%s\n",
		use_virtual_counter ? "CNTVCT_EL0" : "CNTPCT_EL0",
		use_ecv ? " with ECV" : "");

	/* Allocate test results structure */
	tms->results = kzalloc(sizeof(struct test_session_results), GFP_KERNEL);
	if (!tms->results) {
		pr_err("Failed to allocate test results structure\n");
		return -ENOMEM;
	}

	/* Cache timer frequency for efficient conversions */
	tms->timer_freq_hz = read_cntfrq();
	if (tms->timer_freq_hz == 0) {
		pr_warn("Timer frequency is 0, defaulting to 1GHz\n");
		tms->timer_freq_hz = NSEC_PER_SEC;  /* 1GHz default */
	} else if (tms->timer_freq_hz < USEC_PER_SEC || tms->timer_freq_hz > 10 * NSEC_PER_SEC) {
		pr_warn("Suspicious timer frequency: %u Hz (expected: 1MHz-10GHz), proceeding anyway\n",
			tms->timer_freq_hz);
	}

	/* Use num_possible_cpus() for memory allocation, but track online count for tests */
	tms->num_cpus = num_possible_cpus();

	/* Validate and clamp parameters */
	if (num_samples < 1) {
		pr_warn("num_samples=%d too small, clamping to 1\n", num_samples);
		num_samples = 1;
	}
	if (num_samples > MAX_SAMPLES) {
		pr_warn("num_samples=%d exceeds MAX_SAMPLES=%d, clamping\n",
			num_samples, MAX_SAMPLES);
		num_samples = MAX_SAMPLES;
	}
	if (num_sync_tests < 1) {
		pr_warn("num_sync_tests=%d too small, clamping to 1\n", num_sync_tests);
		num_sync_tests = 1;
	}
	if (num_sync_tests > MAX_SYNC_TESTS) {
		pr_warn("num_sync_tests=%d exceeds MAX_SYNC_TESTS=%d, clamping\n",
			num_sync_tests, MAX_SYNC_TESTS);
		num_sync_tests = MAX_SYNC_TESTS;
	}

	/* Initialize cpumasks for test CPU management and display filtering */
	if (num_online_cpus() > 2) {
		/* Default to CPUs 0,1 for systems with more than 2 CPUs */
		cpumask_clear(&tms->target_cpus);
		cpumask_set_cpu(0, &tms->target_cpus);
		cpumask_set_cpu(1, &tms->target_cpus);
	} else {
		/* Use all CPUs for systems with 2 or fewer CPUs */
		cpumask_copy(&tms->target_cpus, cpu_online_mask);
	}
	cpumask_copy(&tms->display_cpus, cpu_online_mask);

	/* Allocate memory using the new dynamic allocation function */
	ret = allocate_memory(tms, num_samples, num_sync_tests);
	if (ret < 0) {
		pr_err("ERROR: Failed to allocate memory\n");
		goto cleanup_test_results;
	}

	pr_info("ARMv8 Timer Validator loaded\n");

	/* Create debugfs directory and files - ALL interfaces now in debugfs */
	tms->debugfs_dir = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!tms->debugfs_dir) {
		pr_warn("Failed to create debugfs directory\n");
		ret = -ENOMEM;
		goto cleanup_memory;
	}

	/* Control interfaces */
	debugfs_create_file("trigger", 0644, tms->debugfs_dir, tms, &trigger_fops);
	debugfs_create_file("status", 0444, tms->debugfs_dir, tms, &status_fops);

	/* Results interfaces */
	debugfs_create_file("summary_results", 0444, tms->debugfs_dir, tms, &summary_results_fops);
	debugfs_create_file("results", 0444, tms->debugfs_dir, tms, &full_results_fops);
	debugfs_create_file("sync_results", 0444, tms->debugfs_dir, tms, &sync_results_fops);

	/* System information */
	debugfs_create_file("num_cpus", 0444, tms->debugfs_dir, tms, &num_cpus_fops);
	debugfs_create_file("memory_info", 0444, tms->debugfs_dir, tms, &memory_info_fops);

	/* Detailed debugging */
	debugfs_create_file("per_cpu_details", 0444, tms->debugfs_dir, tms,
			    &per_cpu_details_fops);
	debugfs_create_file("raw_samples", 0444, tms->debugfs_dir, tms, &raw_samples_fops);
	debugfs_create_file("sync_overhead", 0444, tms->debugfs_dir, tms,
			    &sync_overhead_fops);

	/* CPU selection controls */
	debugfs_create_file("target_cpus", 0644, tms->debugfs_dir, tms, &target_cpus_fops);
	debugfs_create_file("display_cpus", 0644, tms->debugfs_dir, tms, &display_cpus_fops);

	/* Register CPU hotplug state callbacks */
	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"armv8_timer:online",
					armv8_timer_cpu_online,
					armv8_timer_cpu_offline);
	if (ret < 0) {
		pr_err("Failed to register CPU hotplug state: %d\n", ret);
		goto cleanup_debugfs;
	}
	tms->hp_state = ret;

	/* Run tests automatically if requested */
	if (auto_run) {
		(void)run_all_tests(tms);  /* Ignore return value during init */
	} else {
		snprintf(tms->status, sizeof(tms->status), "Not run yet");
	}

	return 0;

cleanup_debugfs:
	debugfs_remove_recursive(tms->debugfs_dir);

cleanup_memory:
	free_all_memory(tms);

cleanup_test_results:
	kfree(tms->results);
	tms->results = NULL;
	return ret;
}

/* Module cleanup */
static void __exit armv8_timer_exit(void)
{
	struct armv8_timer_state *tms = &timer_state;

	/* Unregister CPU hotplug state */
	cpuhp_remove_state_nocalls(tms->hp_state);

	/* Remove debugfs entries */
	debugfs_remove_recursive(tms->debugfs_dir);

	/* Free test results structure */
	kfree(tms->results);
	tms->results = NULL;

	/* Free all allocated memory */
	free_all_memory(tms);

	pr_info("Module unloaded\n");
}

module_init(armv8_timer_init);
module_exit(armv8_timer_exit);
