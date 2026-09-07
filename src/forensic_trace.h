#ifndef RMG_FORENSIC_TRACE_H
#define RMG_FORENSIC_TRACE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "kernelsnitch/utils.h"

static inline int rmg_ft_enabled(void) {
    const char *v = getenv("RMG_FORENSIC_TRACE");
    return v && *v && strcmp(v, "0") != 0;
}

#define RMG_FT_DECISION_U64(check_, actual_, result_, reason_) do { \
    if (rmg_ft_enabled()) pr_info("[FT-DECISION] check=%s actual=0x%016llx result=%s reason=%s\n", \
        (check_), (unsigned long long)(actual_), (result_) ? "PASS" : "REJECT", (reason_)); \
} while (0)

#define RMG_FT_DECISION_RANGE(check_, actual_, low_, high_, result_, reason_) do { \
    if (rmg_ft_enabled()) pr_info("[FT-RANGE] check=%s actual=0x%016llx low=0x%016llx high=0x%016llx result=%s reason=%s\n", \
        (check_), (unsigned long long)(actual_), (unsigned long long)(low_), (unsigned long long)(high_), \
        (result_) ? "PASS" : "REJECT", (reason_)); \
} while (0)

#define RMG_FT_EVENT(name_, fmt_, ...) do { \
    if (rmg_ft_enabled()) pr_info("[FT-EVENT] name=%s " fmt_ "\n", (name_), ##__VA_ARGS__); \
} while (0)

#endif
