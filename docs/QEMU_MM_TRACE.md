# QEMU MM Trace validation

This is a diagnostic path for the classic S24 FE KernelSnitch mm_struct search. It does not replace the existing reclaim route and it is not enabled by default in the target profile.

## Build

```sh
make TARGET=r12s-S721BXXSCDZF3 QEMU_MM_TRACE_VALIDATE=1 \
  ANDROID_NDK_HOME=/path/to/android-ndk
```

At runtime the payload expects an inherited descriptor named by `QEMU_MM_TRACE_FD=<fd number>`.

The payload switches the inherited descriptor to non-blocking mode itself.

## QEMU guest-side trace setup

The Samsung QEMU environment boots the Samsung kernel image inside the Buildroot/DEFEX guest. Inside that guest, enable the kmem_cache_alloc tracepoint and clear the buffer before starting the payload:

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

The important part is that FD 3 is inherited by the LD_PRELOAD process.

## What the payload matches

The parser accepts a trace record when it contains:

- `kmem_cache_alloc:`
- `ptr=<address>`
- `call_site=copy_mm+...` or `call_site=mm_alloc+...`
- the payload process PID

The validation path drains the trace stream immediately before `clone_leak_child()`, captures the resulting oracle address, and compares it with the existing KernelSnitch result for the same child.

A successful comparison logs:

```text
qemu mm validate captured mm=...
qemu mm validate ks=... actual=... exact=1 page=1
```

`exact=1` means the addresses match. `page=1` means the addresses are in the same order-3 page.

A mismatch is logged as:

```text
qemu mm validate mismatch ks=... actual=...
```

and the attempt is discarded.

## Scope

The repository contains the payload-side consumer. It does not patch the QEMU executable itself to invent a new trace format. The diagnostic setup above uses the guest kernel's tracefs stream while the kernel is running under QEMU.

`QEMU_MM_TRACE_ORACLE` remains a separate path and is not enabled by this guide.