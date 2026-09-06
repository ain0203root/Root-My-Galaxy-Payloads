#!/usr/bin/env bash
set -euo pipefail
log_file=${1:-rmg-forensic.log}
RMG_FORENSIC_TRACE=1 exec "$@" >"$log_file" 2>&1
