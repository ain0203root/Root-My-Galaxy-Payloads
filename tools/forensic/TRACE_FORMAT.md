# Trace format

Human-readable events carry wall-clock and monotonic timestamps plus PID/TID. JSONL contains the same event stream for machine processing.

Native events:
- `FT-PC`: executed instrumented control-flow location.
- `FT-CMP`: observed comparison operands.
- `FT-SWITCH`: switch value and cases.
- `FT-DIV`: division input.
- `FT-GEP`: pointer/index calculation input.
- `FT-INDIRECT`: indirect-call target.
- `FT-FUNC+` / `FT-FUNC-`: function entry/exit.
- `FT-DECISION`: explicit semantic decision marker.

Correlate native PCs with the exact forensic ELF, then join those records with the normal verbose payload messages. This preserves observed values and surrounding context without claiming to reconstruct hidden kernel state or every CPU instruction.