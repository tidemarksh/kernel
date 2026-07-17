(module
  (import "kernel" "thread_step" (func $thread_step (param i32 i32) (result i32)))
  (import "kernel" "debug_thread_step_status"
    (func $observed_status (result i32)))
  (import "kernel" "debug_thread_step_budget"
    (func $observed_budget (result i32)))
  (import "kernel" "debug_thread_step_remaining"
    (func $observed_remaining (result i32)))

  (func (export "run") (result i32 i32 i32 i32)
    i32.const 0
    i32.const 1
    call $thread_step
    call $observed_status
    call $observed_budget
    call $observed_remaining))
