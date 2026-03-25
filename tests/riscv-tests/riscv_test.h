// Minimal riscv_test.h for tidemark userland emulator.
// PASS: ecall exit(0). FAIL: ecall exit(testnum >> 1).
// pass/fail labels are defined by TEST_PASSFAIL in test_macros.h.

#ifndef _RISCV_TEST_H
#define _RISCV_TEST_H

#define TESTNUM gp

#define RVTEST_RV64U   \
  .text;               \
  .global _start;

#define RVTEST_RV64UF  \
  .text;               \
  .global _start;

#define RVTEST_CODE_BEGIN \
_start:

#define RVTEST_CODE_END

#define RVTEST_PASS \
  li a7, 93;        \
  li a0, 0;         \
  ecall;

#define RVTEST_FAIL \
  li a7, 93;        \
  srl a0, TESTNUM, 1; \
  ecall;

#define RVTEST_DATA_BEGIN .data;
#define RVTEST_DATA_END

#endif
