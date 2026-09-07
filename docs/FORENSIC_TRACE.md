# Forensic execution trace

This diagnostic path is intentionally separate from the production `all`, `release`, and `stable` artifacts.

## What it records

The forensic build combines source-level debug information with compiler-generated runtime callbacks. During one execution it can record:

- control-flow guard hits (`FT-PC`);
- integer comparisons and both observed operands (`FT-CMP`);
- switch dispatch values and cases (`FT-SWITCH`);
- division and pointer-index observations (`FT-DIV`, `FT-GEP`);
- indirect calls (`FT-INDIRECT`);
- function entry/exit (`FT-FUNC+`, `FT-FUNC-`);
- existing payload log messages, including current source file/line in `DEBUG` mode.

The resulting execution log is therefore much more useful than `logcat` or a plain syscall trace for answering *which decision path actually executed* and *which values were compared*.

## Build

```sh
make TARGET=<exact-profile> ANDROID_NDK_HOME=<ndk> forensic
```

Result:

```text
build/<exact-profile>/cve-2026-43499-app.forensic.so
```

Enable the callbacks at runtime:

```sh
RMG_FORENSIC_TRACE=1
```

## Symbolization

Builds include DWARF debug information. Resolve recorded PCs against the forensic ELF using the Android/LLVM `addr2line` toolchain. The recorded `pc`, PID and guard number are deliberately kept in the raw trace so later symbolization can be repeated without rerunning the device.

## Interpretation

`FT-CMP` is the important forensic layer: it captures comparison operands, while the normal payload logs explain the surrounding operation. Together they let a post-run analysis correlate source locations with actual values and PASS/REJECT observations.

The forensic artifact is not treated as a verified production payload. Release artifact hashes and the normal payload feed remain unchanged.
