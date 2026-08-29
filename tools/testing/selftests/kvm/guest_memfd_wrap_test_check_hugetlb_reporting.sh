#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Wrapper that runs test, checking that HugeTLB-related statistics have not
# changed before and after test.
#
# Example:
#   ./guest_memfd_wrap_test_check_hugetlb_reporting.sh ./guest_memfd_test
#
# Example of combining this with ./guest_memfd_provide_hugetlb_cgroup_mount.sh:
#   ./guest_memfd_provide_hugetlb_cgroup_mount.sh \
#     ./guest_memfd_wrap_test_check_hugetlb_reporting.sh \
#     ./guest_memfd_hugetlb_reporting_test
#
# Copyright (C) 2025, Google LLC.

declare -A baseline

hugetlb_sizes=(
  "2048kB"
  "1048576kB"
)

statistics=(
  "free_hugepages"
  "nr_hugepages"
  "nr_overcommit_hugepages"
  "resv_hugepages"
  "surplus_hugepages"
)

cgroup_hugetlb_sizes=(
  "2MB"
  "1GB"
)

cgroup_statistics=(
  "limit_in_bytes"
  "max_usage_in_bytes"
  "usage_in_bytes"
)

establish_statistics_baseline() {
  for size in "${hugetlb_sizes[@]}"; do

    for statistic in "${statistics[@]}"; do

      local path="/sys/kernel/mm/hugepages/hugepages-${size}/${statistic}"
      baseline["$path"]=$(cat "$path")

    done

  done

  if [ -n "$HUGETLB_CGROUP_PATH" ]; then

    for size in "${cgroup_hugetlb_sizes[@]}"; do

      for statistic in "${cgroup_statistics[@]}"; do

        local rsvd_path="${HUGETLB_CGROUP_PATH}/hugetlb.${size}.rsvd.${statistic}"
        local path="${HUGETLB_CGROUP_PATH}/hugetlb.${size}.${statistic}"

        baseline["$rsvd_path"]=$(cat "$rsvd_path")
        baseline["$path"]=$(cat "$path")

      done

    done

  fi
}

assert_path_at_baseline() {
  local path="$1"
  local current
  local expected

  current=$(cat "$path")
  expected=${baseline["$path"]}
  if [ "$current" != "$expected"  ]; then
    echo "$path was $current instead of $expected"
    return 1
  fi
}

assert_statistics_at_baseline() {
  local path
  local status=0

  for path in "${!baseline[@]}"; do
    assert_path_at_baseline "$path" || status=1
  done

  return "$status"
}


establish_statistics_baseline

"$@"
test_status=$?

assert_statistics_at_baseline
statistics_status=$?

if [ "$test_status" -ne 0 ]; then
  exit "$test_status"
fi

exit "$statistics_status"
