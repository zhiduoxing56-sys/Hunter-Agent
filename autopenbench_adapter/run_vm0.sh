#!/usr/bin/env bash
# Minimal real AutoPenBench baseline: in-vitro/web_security/vm0.
set -euo pipefail

project_root=/home/tenggn/projects
agent_root="$project_root/PentestGPT/pentestgpt_agent"
export PYTHONPATH="$project_root/Hunter-Agent:$agent_root/src${PYTHONPATH:+:$PYTHONPATH}"
echo 'AUTOPENBENCH_ADAPTER_REVISION=kali-keyring-rootless-json-and-nonzero-v4'

exec "$agent_root/.venv/bin/python" \
  "$project_root/Hunter-Agent/autopenbench_adapter/run_baseline.py" \
  --level in-vitro --category web_security --vm 0
