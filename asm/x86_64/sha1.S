/*
 * SHA-1 hash in x86-64 assembly
 *
 * Copyright (c) 2014 Project Nayuki
 * http://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly
 *
 * (MIT License)
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

#include "common"

/* fn OCTAVO_sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) */
ENTRY(OCTAVO_sha1_compress)
  /*
   * Storage usage:
   *   Bytes  Location  Description
   *       4  edi       (Last 64 rounds) temporary for calculation per round
   *       8  rdi       (First 16 rounds) base address of block array argument (read-only)
   *      64  [rsp+0]   Circular buffer of most recent 16 key schedule items, 4 bytes each
   */
#define AA %eax // SHA-1 variable A
#define BB %ebx // SHA-1 variable B
#define CC %ecx // SHA-1 variable C
#define DD %edx // SHA-1 variable D
#define EE %ebp // SHA-1 variable E

#define TMP %esi // Temporary for round calculations

#define STATE %r8 // State block

#define STACK %rsp

  #define ROUND0a(a, b, c, d, e, i)  \
    movl    (i*4)(%rdi), TMP;  \
    bswapl  TMP;               \
    movl    TMP, (i*4)(%rsp);  \
    addl    TMP, e;           \
    movl    c, TMP;           \
    xorl    d, TMP;           \
    andl    b, TMP;           \
    xorl    d, TMP;           \
    ROUNDTAIL(a, b, e, i, 0x5A827999)

  #define SCHEDULE(i, e)  \
    movl  (((i- 3)&0xF)*4)(STACK), TMP;  \
    xorl  (((i- 8)&0xF)*4)(STACK), TMP;  \
    xorl  (((i-14)&0xF)*4)(STACK), TMP;  \
    xorl  (((i-16)&0xF)*4)(STACK), TMP;  \
    roll  $1, TMP;                      \
    addl  TMP, e;                      \
    movl  TMP, ((i&0xF)*4)(STACK);

  #define ROUND0b(a, b, c, d, e, i)  \
    SCHEDULE(i, e)   \
    movl  c, TMP;  \
    xorl  d, TMP;  \
    andl  b, TMP;  \
    xorl  d, TMP;  \
    ROUNDTAIL(a, b, e, i, 0x5A827999)

  #define ROUND1(a, b, c, d, e, i)  \
    SCHEDULE(i, e)   \
    movl  b, TMP;  \
    xorl  c, TMP;  \
    xorl  d, TMP;  \
    ROUNDTAIL(a, b, e, i, 0x6ED9EBA1)

  #define ROUND2(a, b, c, d, e, i)  \
    SCHEDULE(i, e)     \
    movl  c, TMP;    \
    movl  c, %edi;    \
    orl   d, TMP;    \
    andl  b, TMP;    \
    andl  d, %edi;    \
    orl   %edi, TMP;  \
    ROUNDTAIL(a, b, e, i, -0x70E44324)

  #define ROUND3(a, b, c, d, e, i)  \
    SCHEDULE(i, e)   \
    movl  b, TMP;  \
    xorl  c, TMP;  \
    xorl  d, TMP;  \
    ROUNDTAIL(a, b, e, i, -0x359D3E2A)

  #define ROUNDTAIL(a, b, e, i, k)  \
    roll  $30, b;         \
    leal  k(e,TMP), e;  \
    movl  a, TMP;        \
    roll  $5, TMP;        \
    addl  TMP, e;

  /* Save registers, allocate scratch space */
  pushq    %rbx
  pushq    %rbp
  subq    $64, STACK

  /* Load arguments */
  movq    %rdi, STATE
  movl     0(%rdi), AA
  movl     4(%rdi), BB
  movl     8(%rdi), CC
  movl    12(%rdi), DD
  movl    16(%rdi), EE
  movq    %rsi, %rdi

  /* 80 rounds of hashing */
  ROUND0a(AA, BB, CC, DD, EE,  0)
  ROUND0a(EE, AA, BB, CC, DD,  1)
  ROUND0a(DD, EE, AA, BB, CC,  2)
  ROUND0a(CC, DD, EE, AA, BB,  3)
  ROUND0a(BB, CC, DD, EE, AA,  4)
  ROUND0a(AA, BB, CC, DD, EE,  5)
  ROUND0a(EE, AA, BB, CC, DD,  6)
  ROUND0a(DD, EE, AA, BB, CC,  7)
  ROUND0a(CC, DD, EE, AA, BB,  8)
  ROUND0a(BB, CC, DD, EE, AA,  9)
  ROUND0a(AA, BB, CC, DD, EE, 10)
  ROUND0a(EE, AA, BB, CC, DD, 11)
  ROUND0a(DD, EE, AA, BB, CC, 12)
  ROUND0a(CC, DD, EE, AA, BB, 13)
  ROUND0a(BB, CC, DD, EE, AA, 14)
  ROUND0a(AA, BB, CC, DD, EE, 15)
  ROUND0b(EE, AA, BB, CC, DD, 16)
  ROUND0b(DD, EE, AA, BB, CC, 17)
  ROUND0b(CC, DD, EE, AA, BB, 18)
  ROUND0b(BB, CC, DD, EE, AA, 19)
  ROUND1(AA, BB, CC, DD, EE, 20)
  ROUND1(EE, AA, BB, CC, DD, 21)
  ROUND1(DD, EE, AA, BB, CC, 22)
  ROUND1(CC, DD, EE, AA, BB, 23)
  ROUND1(BB, CC, DD, EE, AA, 24)
  ROUND1(AA, BB, CC, DD, EE, 25)
  ROUND1(EE, AA, BB, CC, DD, 26)
  ROUND1(DD, EE, AA, BB, CC, 27)
  ROUND1(CC, DD, EE, AA, BB, 28)
  ROUND1(BB, CC, DD, EE, AA, 29)
  ROUND1(AA, BB, CC, DD, EE, 30)
  ROUND1(EE, AA, BB, CC, DD, 31)
  ROUND1(DD, EE, AA, BB, CC, 32)
  ROUND1(CC, DD, EE, AA, BB, 33)
  ROUND1(BB, CC, DD, EE, AA, 34)
  ROUND1(AA, BB, CC, DD, EE, 35)
  ROUND1(EE, AA, BB, CC, DD, 36)
  ROUND1(DD, EE, AA, BB, CC, 37)
  ROUND1(CC, DD, EE, AA, BB, 38)
  ROUND1(BB, CC, DD, EE, AA, 39)
  ROUND2(AA, BB, CC, DD, EE, 40)
  ROUND2(EE, AA, BB, CC, DD, 41)
  ROUND2(DD, EE, AA, BB, CC, 42)
  ROUND2(CC, DD, EE, AA, BB, 43)
  ROUND2(BB, CC, DD, EE, AA, 44)
  ROUND2(AA, BB, CC, DD, EE, 45)
  ROUND2(EE, AA, BB, CC, DD, 46)
  ROUND2(DD, EE, AA, BB, CC, 47)
  ROUND2(CC, DD, EE, AA, BB, 48)
  ROUND2(BB, CC, DD, EE, AA, 49)
  ROUND2(AA, BB, CC, DD, EE, 50)
  ROUND2(EE, AA, BB, CC, DD, 51)
  ROUND2(DD, EE, AA, BB, CC, 52)
  ROUND2(CC, DD, EE, AA, BB, 53)
  ROUND2(BB, CC, DD, EE, AA, 54)
  ROUND2(AA, BB, CC, DD, EE, 55)
  ROUND2(EE, AA, BB, CC, DD, 56)
  ROUND2(DD, EE, AA, BB, CC, 57)
  ROUND2(CC, DD, EE, AA, BB, 58)
  ROUND2(BB, CC, DD, EE, AA, 59)
  ROUND3(AA, BB, CC, DD, EE, 60)
  ROUND3(EE, AA, BB, CC, DD, 61)
  ROUND3(DD, EE, AA, BB, CC, 62)
  ROUND3(CC, DD, EE, AA, BB, 63)
  ROUND3(BB, CC, DD, EE, AA, 64)
  ROUND3(AA, BB, CC, DD, EE, 65)
  ROUND3(EE, AA, BB, CC, DD, 66)
  ROUND3(DD, EE, AA, BB, CC, 67)
  ROUND3(CC, DD, EE, AA, BB, 68)
  ROUND3(BB, CC, DD, EE, AA, 69)
  ROUND3(AA, BB, CC, DD, EE, 70)
  ROUND3(EE, AA, BB, CC, DD, 71)
  ROUND3(DD, EE, AA, BB, CC, 72)
  ROUND3(CC, DD, EE, AA, BB, 73)
  ROUND3(BB, CC, DD, EE, AA, 74)
  ROUND3(AA, BB, CC, DD, EE, 75)
  ROUND3(EE, AA, BB, CC, DD, 76)
  ROUND3(DD, EE, AA, BB, CC, 77)
  ROUND3(CC, DD, EE, AA, BB, 78)
  ROUND3(BB, CC, DD, EE, AA, 79)

  /* Save updated state */
  addl    AA,  0(STATE)
  addl    BB,  4(STATE)
  addl    CC,  8(STATE)
  addl    DD, 12(STATE)
  addl    EE, 16(STATE)

  /* Restore registers */
  addq    $64, %rsp
  popq    %rbp
  popq    %rbx
  retq
END(OCTAVO_sha1_compress)
