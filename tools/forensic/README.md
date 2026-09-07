# Payload forensic diagnostics

The `forensic-trace` branch adds a diagnostic-only native build. Production `all`, `release`, and `stable` targets remain separate.

The forensic artifact records compiler-observed control flow and data-flow signals (`FT-PC`, `FT-CMP`, `FT-SWITCH`, `FT-DIV`, `FT-GEP`, `FT-INDIRECT`, `FT-FUNC+/-`) and is built with debug information so raw PCs can be symbolized after the run. The normal verbose payload messages remain present, giving source-level context around these observations.

Use `RMG_FORENSIC_TRACE=1` to enable the callbacks at runtime.
