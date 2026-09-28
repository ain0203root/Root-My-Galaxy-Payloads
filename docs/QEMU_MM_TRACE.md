# QEMU MM Trace oracle

This is the experimental S24 FE path where the payload gets the `mm_struct` address from the guest kernel trace stream instead of using KernelSnitch for the S721 MM search.

## Build

The S721B target on this branch selects `MM_SEARCH_MODE=2` from its target profile:

```sh
make TARGET=r12s-S721BXXSCDZF3 \
  ANDROID_NDK_HOME=/path/to/android-ndk
```

In mode 2, the classic `mm_struct` search in both `prepare_kernel_page()` and the pipe-page preparation path skips the KernelSnitch collision/bruteforce stage and uses the QEMU trace oracle.

At runtime the payload expects an inherited descriptor named by `QEMU_MM_TRACE_FD=<fd number>`. The payload switches that descriptor to non-blocking mode itself.

## QEMU guest-side trace setup

The Samsung QEMU environment boots the Samsung kernel image inside the Buildroot/DEFEX guest. Inside that guest, enable the `kmem_cache_alloc` tracepoint and clear the buffer before starting the payload:

```sh
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

echo 0 > /sys/kernel/tracing/tracing_on
echo > /sys/kernel/tracing/trace
echo 0 > /sys/kernel/tracing/events/enable
echo 1 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable
echo 1 > /sys/kernel/tracing/tracing_on

exec 3< /sys/kernel/tracing/trace_pipe
QEMU_MM_TRACE_FD=3 LD_PRELOAD=/root/cve-2026-43499-app.so /bin/sh
```

The exact payload path depends on where the artifact was copied into the guest.

FD 3 must be inherited by the LD_PRELOAD process.

## What the payload matches

The parser looks for a trace record containing:

- `kmem_cache_alloc:`
- `ptr=<address>`
- `call_site=copy_mm+...` or `call_site=mm_alloc+...`
- the payload process PID as the trace `common_pid`

Immediately before the dedicated clone, the payload drains older trace data. It then creates one controlled child, opens `/proc/<pid>/mem` for that child, and reads the next matching allocation record as the oracle address.

The returned memfd is kept open through the same later reclaim window where the old path kept `memfd_leak` open. This preserves the existing lifetime relationship instead of merely treating the address as a diagnostic value.

## What changed in S721

Mode 2 changes the MM search source only:

```text
old:
  child clone
    -> KernelSnitch collision finding
    -> KernelSnitch bruteforce
    -> ks->mm_struct

new:
  child clone
    -> guest kmem_cache_alloc trace
    -> qemu_mm_oracle_leak()
    -> oracle mm_struct
```

The later S721 page-base checks, object-index checks, payload construction, reclaim sequence, P0 logic, FOPS/slide logic and pipe-stage logic remain in place.

KernelSnitch code is still present in the repository because other target profiles use it. In this branch it is not used by the S721B mode-2 MM search path.

## Important limitation

The repository contains the payload-side trace consumer. The Samsung QEMU tree checked for this work does not contain a custom `mm_struct` trace implementation; the oracle currently relies on the guest kernel's tracefs stream while that kernel is running under QEMU.

The end-to-end combination of the S721 kernel, tracefs event format and `trace_pipe` FD inheritance still needs to be verified in the actual QEMU guest. In particular, the parser currently expects `common_pid` to identify the payload-side parent that issued the clone.

A successful oracle capture is logged as:

```text
qemu mm oracle captured mm=... memfd=... pid=...
```

A failed capture is logged as:

```text
qemu mm oracle leak failed
```


CI publication note: the QEMU oracle artifact is published separately from the stable S721B payload.
