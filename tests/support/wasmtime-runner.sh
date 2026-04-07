#!/usr/bin/env bash
set -euo pipefail

exec wasmtime --dir=/ --env TIDEMARK_KERNEL_ROOT="$PWD" "$@"
