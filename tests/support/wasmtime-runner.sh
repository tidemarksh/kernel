#!/usr/bin/env bash
set -euo pipefail

args=(--dir=/ --env "TIDEMARK_KERNEL_ROOT=$PWD")

for forwarded in \
  WASMTIME_BACKTRACE_DETAILS
do
  if [[ -n "${!forwarded-}" ]]; then
    args+=(--env "${forwarded}=${!forwarded}")
  fi
done

exec wasmtime "${args[@]}" "$@"
