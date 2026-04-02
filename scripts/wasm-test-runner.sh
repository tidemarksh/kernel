#!/usr/bin/env bash
set -u

wasm="$1"
shift || true

wasmtime=(wasmtime --dir=/)

run_direct() {
  exec "${wasmtime[@]}" "$wasm" "$@"
}

args=("$@")

for arg in "${args[@]}"; do
  case "$arg" in
    --list|--help|-h|--version)
      run_direct "${args[@]}"
      ;;
  esac
done

list_args=()
per_case_args=()

i=0
while (( i < ${#args[@]} )); do
  arg="${args[i]}"
  case "$arg" in
    --exact)
      ;;
    --ignored|--include-ignored|--nocapture|--quiet|-q|--show-output)
      list_args+=("$arg")
      per_case_args+=("$arg")
      ;;
    --color|--format|--skip)
      if (( i + 1 >= ${#args[@]} )); then
        run_direct "${args[@]}"
      fi
      value="${args[i+1]}"
      list_args+=("$arg" "$value")
      per_case_args+=("$arg" "$value")
      ((i+=2))
      continue
      ;;
    -*)
      list_args+=("$arg")
      ;;
    *)
      list_args+=("$arg")
      ;;
  esac
  ((i+=1))
done

if ! list_output="$("${wasmtime[@]}" "$wasm" "${list_args[@]}" --list 2>/dev/null)"; then
  run_direct "${args[@]}"
fi

mapfile -t tests < <(printf '%s\n' "$list_output" | sed -n 's/^\(.*\): test$/\1/p')
if (( ${#tests[@]} == 0 )); then
  run_direct "${args[@]}"
fi

status=0
for test_name in "${tests[@]}"; do
  if ! "${wasmtime[@]}" "$wasm" "${per_case_args[@]}" "$test_name" --exact; then
    status=1
  fi
done

exit "$status"
