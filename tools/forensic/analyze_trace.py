#!/usr/bin/env python3
import collections
import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: analyze_trace.py <trace.log>")

path = Path(sys.argv[1])
counts = collections.Counter()
comparisons = []
decisions = []
for line in path.read_text(errors="replace").splitlines():
    if "[FT-CMP]" in line:
        m = re.search(r"kind=(\S+)\s+bits=(\d+)\s+a=(0x[0-9a-fA-F]+)\s+b=(0x[0-9a-fA-F]+).*pid=(\d+)", line)
        if m:
            comparisons.append(m.groups())
            counts["comparisons"] += 1
    elif "[FT-PC]" in line:
        counts["pc_hits"] += 1
    elif "[FT-FUNC+]" in line:
        counts["function_entries"] += 1
    elif "[FT-FUNC-]" in line:
        counts["function_exits"] += 1
    elif "[FT-INDIRECT]" in line:
        counts["indirect_calls"] += 1
    elif "[FT-SWITCH]" in line:
        counts["switches"] += 1
    elif "[FT-GEP]" in line:
        counts["gep"] += 1
    elif "[FT-DIV]" in line:
        counts["divisions"] += 1
    elif "[FT-DECISION]" in line or "[FT-RANGE]" in line:
        decisions.append(line)

print("=== RMG FORENSIC SUMMARY ===")
for key in sorted(counts):
    print(f"{key}: {counts[key]}")
print(f"semantic_decisions: {len(decisions)}")
print()
print("=== DECISIONS ===")
for line in decisions[:500]:
    print(line)
print()
print("=== FIRST COMPARISONS ===")
for row in comparisons[:100]:
    print("kind=%s bits=%s a=%s b=%s pid=%s" % row)
