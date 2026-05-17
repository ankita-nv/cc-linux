// SPDX-License-Identifier: GPL-2.0
/*
 * PMU bridge exposing resctrl monitor counters to perf.
 *
 * resctrl already counts cache occupancy and memory bandwidth using
 * hardware monitors backing each control/monitor group, and exposes the
 * values through files in the resctrl filesystem. This driver wraps the
 * same counters as a perf PMU so they can be sampled alongside other perf
 * events.
 *
 * The PMU is system-wide; per-task events are rejected because resctrl
 * has already attributed counters to a CLOSID/RMID combination by the
 * time the read happens. Event configuration is encoded in perf_event_attr.config:
 *
 *   bits  0..7  : eventid (enum resctrl_event_id)
 *   bits  8..15 : domainid (resctrl domain id from /sys/fs/resctrl/info)
 *   bits 16..31 : closid
 *   bits 32..47 : rmid
 *   bits 48..63 : monid (pre-assigned MBM counter index for ABMC; 0 for
 *                        events that resolve a hardware monitor lazily)
 *
 * This driver never touches the hardware directly - it dispatches to
 * resctrl_arch_rmid_read() for cache-occupancy and to
 * resctrl_arch_cntr_read() for the ABMC-assigned MBM counters.
 */

#include <linux/arm_mpam.h>
#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/resctrl.h>
#include <linux/smp.h>

#define DRIVER_NAME    "resctrl_pmu"

struct resctrl_pmu {
       struct pmu      pmu;
       struct device   *dev;
};

#define to_resctrl_pmu(p) container_of(p, struct resctrl_pmu, pmu)

#define RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(_name, _config, _start, _end) \
       static inline u64 get_##_name(struct perf_event *event)         \
       {                                                               \
               return FIELD_GET(GENMASK_ULL(_end, _start),             \
                                event->attr._config);                  \
       }

RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(eventid,  config,  0,  7);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(domainid, config,  8, 15);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(closid,   config, 16, 31);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(rmid,     config, 32, 47);
RESCTRL_PMU_EVENT_ATTR_EXTRACTOR(monid,    config, 48, 63);

static struct rdt_resource *resctrl_event_get_resource(enum resctrl_event_id evt)
{
       switch (evt) {
       case QOS_L3_OCCUP_EVENT_ID:
       case QOS_L3_MBM_LOCAL_EVENT_ID:
               return resctrl_arch_get_resource(RDT_RESOURCE_L3);
       case QOS_L3_MBM_TOTAL_EVENT_ID:
               return resctrl_arch_get_resource(RDT_RESOURCE_MBA);
       default:
               return NULL;
       }
}

/*
 * Dispatch a single counter read. Cache occupancy goes through the
 * legacy ctx-based path; MBM events come from pre-assigned ABMC counters
 * (cntr_id = monid).
 */
static int resctrl_pmu_read_counter(struct perf_event *event, u64 *val)
{
       enum resctrl_event_id evt = get_eventid(event);
       u32 closid = get_closid(event);
       u32 rmid = get_rmid(event);
       u32 domainid = get_domainid(event);
       u32 monid = get_monid(event);
       struct rdt_domain_hdr *hdr;
       struct rdt_resource *r;

       r = resctrl_event_get_resource(evt);
       if (!r)
               return -EINVAL;

       hdr = resctrl_arch_find_domain(&r->mon_domains, domainid);
       if (!hdr || hdr->type != RESCTRL_MON_DOMAIN)
               return -EINVAL;

       if (evt == QOS_L3_OCCUP_EVENT_ID) {
               u32 mon_idx = monid;

               return resctrl_arch_rmid_read(r, hdr, closid, rmid, evt,
                                             NULL, val, &mon_idx);
       }

       return resctrl_arch_cntr_read(r,
                                     container_of(hdr,
                                                  struct rdt_l3_mon_domain,
                                                  hdr),
                                     closid, rmid, monid, evt, val);
}

static void resctrl_pmu_event_update(struct perf_event *event)
{
       struct hw_perf_event *hwc = &event->hw;
       enum resctrl_event_id evt = get_eventid(event);
       u64 now, prev, delta;
       int err;

       do {
               now = 0;
               prev = local64_read(&hwc->prev_count);
               err = resctrl_pmu_read_counter(event, &now);
               if (err)
                       return;

               /* CSU is an instantaneous occupancy, accumulate against prev. */
               if (evt == QOS_L3_OCCUP_EVENT_ID)
                       now += prev;
       } while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

       if (prev) {
               delta = now - prev;
               local64_add(delta, &event->count);
       }
}

static int resctrl_pmu_event_init(struct perf_event *event)
{
       struct resctrl_pmu *rp = to_resctrl_pmu(event->pmu);
       enum resctrl_event_id evt;
       struct rdt_domain_hdr *hdr;
       struct rdt_resource *r;
       struct perf_event *sibling;
       u32 domainid;

       if (event->attr.type != event->pmu->type)
               return -ENOENT;

       if (is_sampling_event(event) ||
           (event->attach_state & PERF_ATTACH_TASK))
               return -EOPNOTSUPP;

       if (event->cpu < 0) {
               dev_dbg(rp->dev, "per-task mode not supported\n");
               return -EOPNOTSUPP;
       }

       evt = get_eventid(event);
       if (!resctrl_is_mon_event_enabled(evt))
               return -EINVAL;

       r = resctrl_event_get_resource(evt);
       if (!r || !r->mon_capable)
               return -EINVAL;

       /*
        * Reject the user-supplied monid up-front when it is outside the
        * range the class advertises. Cache occupancy resolves the monitor
        * lazily, so monid is treated as a hint for that event.
        */
       if (get_monid(event) >= resctrl_arch_mon_count(r, evt))
               return -EINVAL;

       domainid = get_domainid(event);
       hdr = resctrl_arch_find_domain(&r->mon_domains, domainid);
       if (!hdr || hdr->type != RESCTRL_MON_DOMAIN)
               return -EINVAL;

       /* Pin to a CPU that can read the counter (avoids cross-MSC IPI). */
       event->cpu = cpumask_empty(&hdr->cpu_mask) ?
                       raw_smp_processor_id() :
                       cpumask_any(&hdr->cpu_mask);

       if (!is_software_event(event->group_leader) &&
           event->group_leader->pmu != event->pmu)
               return -EINVAL;

       for_each_sibling_event(sibling, event->group_leader) {
               if (is_software_event(sibling))
                       continue;
               if (sibling->pmu != event->pmu)
                       return -EINVAL;
       }

       local64_set(&event->hw.prev_count, 0);
       local64_set(&event->count, 0);

       return 0;
}

static void resctrl_pmu_event_start(struct perf_event *event, int flags)
{
       struct hw_perf_event *hwc = &event->hw;

       hwc->state = 0;
       resctrl_pmu_event_update(event);
}

static void resctrl_pmu_event_stop(struct perf_event *event, int flags)
{
       if (flags & PERF_EF_UPDATE)
               resctrl_pmu_event_update(event);
       event->hw.state |= PERF_HES_STOPPED;
}

static int resctrl_pmu_event_add(struct perf_event *event, int flags)
{
       event->hw.state = PERF_HES_STOPPED;
       if (flags & PERF_EF_START)
               resctrl_pmu_event_start(event, flags);
       perf_event_update_userpage(event);

       return 0;
}

static void resctrl_pmu_event_del(struct perf_event *event, int flags)
{
       resctrl_pmu_event_stop(event, flags | PERF_EF_UPDATE);
       perf_event_update_userpage(event);
}

static int resctrl_pmu_event_idx(struct perf_event *event)
{
       u32 closid = get_closid(event);
       u32 rmid = get_rmid(event);

       return resctrl_arch_rmid_idx_encode(closid, rmid);
}

static void resctrl_pmu_do_nothing(struct pmu *pmu)
{
}

static ssize_t resctrl_pmu_event_show(struct device *dev,
                                     struct device_attribute *attr,
                                     char *page)
{
       struct perf_pmu_events_attr *pmu_attr =
               container_of(attr, struct perf_pmu_events_attr, attr);

       return sysfs_emit(page, "event=0x%llx\n", pmu_attr->id);
}

static struct attribute *resctrl_pmu_events[] = {
       PMU_EVENT_ATTR_ID(mbm_total_bytes, resctrl_pmu_event_show,
                         QOS_L3_MBM_TOTAL_EVENT_ID),
       PMU_EVENT_ATTR_ID(mbm_local_bytes, resctrl_pmu_event_show,
                         QOS_L3_MBM_LOCAL_EVENT_ID),
       PMU_EVENT_ATTR_ID(llc_occupancy,   resctrl_pmu_event_show,
                         QOS_L3_OCCUP_EVENT_ID),
       NULL
};

static umode_t resctrl_pmu_event_is_visible(struct kobject *kobj,
                                           struct attribute *attr, int unused)
{
       struct perf_pmu_events_attr *pmu_attr =
               container_of(attr, struct perf_pmu_events_attr, attr.attr);

       if (resctrl_is_mon_event_enabled(pmu_attr->id))
               return attr->mode;

       return 0;
}

static const struct attribute_group resctrl_pmu_events_group = {
       .name           = "events",
       .attrs          = resctrl_pmu_events,
       .is_visible     = resctrl_pmu_event_is_visible,
};

PMU_FORMAT_ATTR(eventid,  "config:0-7");
PMU_FORMAT_ATTR(domainid, "config:8-15");
PMU_FORMAT_ATTR(closid,   "config:16-31");
PMU_FORMAT_ATTR(rmid,     "config:32-47");
PMU_FORMAT_ATTR(monid,    "config:48-63");

static struct attribute *resctrl_pmu_formats[] = {
       &format_attr_eventid.attr,
       &format_attr_domainid.attr,
       &format_attr_closid.attr,
       &format_attr_rmid.attr,
       &format_attr_monid.attr,
       NULL
};

static const struct attribute_group resctrl_pmu_format_group = {
       .name   = "format",
       .attrs  = resctrl_pmu_formats,
};

static ssize_t resctrl_pmu_cpumask_show(struct device *dev,
                                       struct device_attribute *attr,
                                       char *buf)
{
       /*
        * resctrl counts system-wide; report a single CPU so perf only
        * tries to open the event once per domain.
        */
       return sysfs_emit(buf, "%u\n", raw_smp_processor_id());
}

static struct device_attribute resctrl_pmu_cpumask_attr =
               __ATTR(cpumask, 0444, resctrl_pmu_cpumask_show, NULL);

static struct attribute *resctrl_pmu_cpumask_attrs[] = {
       &resctrl_pmu_cpumask_attr.attr,
       NULL
};

static const struct attribute_group resctrl_pmu_cpumask_group = {
       .attrs = resctrl_pmu_cpumask_attrs,
};

static const struct attribute_group *resctrl_pmu_attr_grps[] = {
       &resctrl_pmu_events_group,
       &resctrl_pmu_format_group,
       &resctrl_pmu_cpumask_group,
       NULL
};

static int resctrl_pmu_probe(struct platform_device *pdev)
{
       struct device *dev = &pdev->dev;
       struct resctrl_pmu *rp;
       int err;

       rp = devm_kzalloc(dev, sizeof(*rp), GFP_KERNEL);
       if (!rp)
               return -ENOMEM;

       rp->dev = dev;
       platform_set_drvdata(pdev, rp);

       rp->pmu = (struct pmu) {
               .module         = THIS_MODULE,
               .task_ctx_nr    = perf_invalid_context,
               .pmu_enable     = resctrl_pmu_do_nothing,
               .pmu_disable    = resctrl_pmu_do_nothing,
               .event_init     = resctrl_pmu_event_init,
               .event_idx      = resctrl_pmu_event_idx,
               .add            = resctrl_pmu_event_add,
               .del            = resctrl_pmu_event_del,
               .start          = resctrl_pmu_event_start,
               .stop           = resctrl_pmu_event_stop,
               .read           = resctrl_pmu_event_update,
               .attr_groups    = resctrl_pmu_attr_grps,
               .capabilities   = PERF_PMU_CAP_NO_EXCLUDE,
       };

       err = perf_pmu_register(&rp->pmu, DRIVER_NAME, -1);
       if (err) {
               dev_err(dev, "error %d registering PMU\n", err);
               return err;
       }

       return 0;
}

static void resctrl_pmu_remove(struct platform_device *pdev)
{
       struct resctrl_pmu *rp = platform_get_drvdata(pdev);

       perf_pmu_unregister(&rp->pmu);
}

static struct platform_driver resctrl_pmu_driver = {
       .driver = {
               .name = DRIVER_NAME,
       },
       .probe  = resctrl_pmu_probe,
       .remove = resctrl_pmu_remove,
};
module_platform_driver(resctrl_pmu_driver);

MODULE_DESCRIPTION("PMU bridge exposing resctrl monitor counters to perf");
MODULE_LICENSE("GPL");
