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

module=${1:-}

run_isolated_test_binary() {
  local wasm=$1
  local -a tests=()
  local line name

  while IFS= read -r line; do
    [[ $line == *": test" ]] || continue
    name=${line%%: test}
    tests+=("$name")
  done < <(wasmtime "${args[@]}" "$wasm" --list)

  local total=${#tests[@]}
  local passed=0
  local failed=0

  echo "running $total tests in isolated wasmtime instances"
  for name in "${tests[@]}"; do
    printf 'test %s ... ' "$name"
    if wasmtime "${args[@]}" "$wasm" "$name" --exact >/tmp/tidemark-wasmtime-test.out 2>&1; then
      echo "ok"
      passed=$((passed + 1))
    else
      echo "FAILED"
      cat /tmp/tidemark-wasmtime-test.out
      failed=$((failed + 1))
    fi
  done

  rm -f /tmp/tidemark-wasmtime-test.out
  if [[ $failed -eq 0 ]]; then
    echo
    echo "test result: ok. $passed passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
    return 0
  fi

  echo
  echo "test result: FAILED. $passed passed; $failed failed; 0 ignored; 0 measured; 0 filtered out"
  return 101
}

if [[ $# -eq 1 ]]; then
  case "$(basename "$module")" in
    ltp-*|riscv_tests-*)
      run_isolated_test_binary "$module"
      exit $?
      ;;
  esac
fi

exec wasmtime "${args[@]}" "$@"
