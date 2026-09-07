/* Diagnostic-only compiler-trace runtime. Release/stable builds do not link this file. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__clang__)
#define RMG_NOINST __attribute__((no_sanitize("coverage"), no_instrument_function, noinline))
#else
#define RMG_NOINST __attribute__((noinline))
#endif

static volatile int enabled_state = -1;
static volatile uint32_t next_guard = 1;

static RMG_NOINST int enabled(void) {
    int v = enabled_state;
    if (v >= 0) return v;
    const char *e = getenv("RMG_FORENSIC_TRACE");
    v = (e && *e && strcmp(e, "0") != 0) ? 1 : 0;
    enabled_state = v;
    return v;
}

static RMG_NOINST void emit_cmp(const char *kind, unsigned bits,
                                uint64_t a, uint64_t b) {
    if (!enabled()) return;
    flockfile(stdout);
    fprintf(stdout, "[FT-CMP] kind=%s bits=%u a=0x%016llx b=0x%016llx pid=%d\n",
            kind, bits, (unsigned long long)a, (unsigned long long)b, (int)getpid());
    funlockfile(stdout);
    fflush(stdout);
}

RMG_NOINST void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *p = start; p < stop; ++p) *p = next_guard++;
}

RMG_NOINST void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!guard || !*guard || !enabled()) return;
    void *pc = __builtin_return_address(0);
    fprintf(stdout, "[FT-PC] guard=%u pc=%p pid=%d\n", *guard, pc, (int)getpid());
    fflush(stdout);
}

RMG_NOINST void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { emit_cmp("cmp1", 8, a, b); }
RMG_NOINST void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { emit_cmp("cmp2", 16, a, b); }
RMG_NOINST void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { emit_cmp("cmp4", 32, a, b); }
RMG_NOINST void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { emit_cmp("cmp8", 64, a, b); }
RMG_NOINST void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { emit_cmp("const_cmp1", 8, a, b); }
RMG_NOINST void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { emit_cmp("const_cmp2", 16, a, b); }
RMG_NOINST void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { emit_cmp("const_cmp4", 32, a, b); }
RMG_NOINST void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { emit_cmp("const_cmp8", 64, a, b); }

RMG_NOINST void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    if (!enabled() || !cases) return;
    uint64_t count = cases[0], bits = cases[1];
    flockfile(stdout);
    fprintf(stdout, "[FT-SWITCH] val=0x%016llx bits=%llu cases=%llu",
            (unsigned long long)val, (unsigned long long)bits,
            (unsigned long long)count);
    for (uint64_t i = 0; i < count; ++i)
        fprintf(stdout, " c[%llu]=0x%016llx", (unsigned long long)i,
                (unsigned long long)cases[2 + i]);
    fprintf(stdout, " pid=%d\n", (int)getpid());
    funlockfile(stdout);
    fflush(stdout);
}

RMG_NOINST void __sanitizer_cov_trace_div4(uint32_t v) {
    if (!enabled()) return;
    fprintf(stdout, "[FT-DIV] bits=32 value=0x%08x pid=%d\n", v, (int)getpid());
    fflush(stdout);
}
RMG_NOINST void __sanitizer_cov_trace_div8(uint64_t v) {
    if (!enabled()) return;
    fprintf(stdout, "[FT-DIV] bits=64 value=0x%016llx pid=%d\n",
            (unsigned long long)v, (int)getpid());
    fflush(stdout);
}
RMG_NOINST void __sanitizer_cov_trace_gep(uintptr_t idx) {
    if (!enabled()) return;
    fprintf(stdout, "[FT-GEP] index=0x%016lx pid=%d\n", (unsigned long)idx, (int)getpid());
    fflush(stdout);
}
RMG_NOINST void __sanitizer_cov_trace_pc_indirect(void *callee) {
    if (!enabled()) return;
    void *pc = __builtin_return_address(0);
    fprintf(stdout, "[FT-INDIRECT] pc=%p callee=%p pid=%d\n", pc, callee, (int)getpid());
    fflush(stdout);
}
RMG_NOINST void __cyg_profile_func_enter(void *fn, void *call_site) {
    if (!enabled()) return;
    fprintf(stdout, "[FT-FUNC+] fn=%p callsite=%p pid=%d\n", fn, call_site, (int)getpid());
}
RMG_NOINST void __cyg_profile_func_exit(void *fn, void *call_site) {
    if (!enabled()) return;
    fprintf(stdout, "[FT-FUNC-] fn=%p callsite=%p pid=%d\n", fn, call_site, (int)getpid());
}
