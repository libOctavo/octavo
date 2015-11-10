#include "common"

ENTRY(OCTAVO_cpuid)
  pushq %rbp
  movq %rsp, %rbp
  pushq %rbx
  movl $1, %eax
  cpuid
  movl %edx, %eax
  shlq $32, %rax
  addq %rcx, %rax
  popq %rbx
  popq %rbp
  retq
END(OCTAVO_cpuid)

ENTRY(OCTAVO_cpuid_ex)
  pushq %rbp
  movq %rsp, %rbp
  pushq %rbx
  movl $7, %eax
  xorl %ecx, %ecx
  cpuid
  movl %ebx, %eax
  shlq $32, %rax
  addq %rcx, %rax
  popq %rbx
  popq %rbp
  retq
END(OCTAVO_cpuid_ex)
