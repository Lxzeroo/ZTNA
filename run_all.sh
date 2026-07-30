#!/usr/bin/env bash
# PyZTNA -- launch every service in the background (Linux/macOS dev use).
# Windows users should use run_all.ps1 instead.
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

mkdir -p logs certs
python3 -m idp.idp_server        > /tmp/pyztna_idp.log 2>&1 &      echo $! > /tmp/pyztna_idp.pid
python3 -m resources.docs_app    > /tmp/pyztna_docs.log 2>&1 &     echo $! > /tmp/pyztna_docs.pid
python3 -m resources.finance_app > /tmp/pyztna_finance.log 2>&1 &  echo $! > /tmp/pyztna_finance.pid
sleep 1
python3 -m gateway.gateway_server > /tmp/pyztna_gateway.log 2>&1 & echo $! > /tmp/pyztna_gateway.pid

echo "Started. PIDs written to /tmp/pyztna_*.pid. Logs in /tmp/pyztna_*.log."
echo "Stop with: kill \$(cat /tmp/pyztna_*.pid)"
