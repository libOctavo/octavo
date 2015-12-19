/*
 * MD5 hash in x86-64 assembly
 *
 * Copyright (c) 2014 Project Nayuki
 * http://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly
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

/* fn md5_compress(state: &mut [u32; 4], block: &[u8; 16]) */
ENTRY(OCTAVO_md5_compress)
  /*
   * Storage usage:
   *   Bytes  Location  Description
   *       4  esi       Temporary for calculation per round
   *       4  edi       Temporary for calculation per round
   *       8  rbp       Base address of block array argument (read-only)
   *       8  r8        Base address of state array argument (read-only)
   *      16  xmm0      Caller's value of rbx (only lower 64 bits are used)
   *      16  xmm1      Caller's value of rbp (only lower 64 bits are used)
   */

  #define AA %eax
  #define BB %ebx
  #define CC %ecx
  #define DD %edx

  #define ROUND0(a, b, c, d, k, s, t)  \
    movl  c, %esi;         \
    addl  (k*4)(%rbp), a;  \
    xorl  d, %esi;         \
    andl  b, %esi;         \
    xorl  d, %esi;         \
    leal  t(%esi,a), a;    \
    roll  $s, a;           \
    addl  b, a;

  #define ROUND1(a, b, c, d, k, s, t)  \
    movl  d, %esi;         \
    movl  d, %edi;         \
    addl  (k*4)(%rbp), a;  \
    notl  %esi;            \
    andl  b, %edi;         \
    andl  c, %esi;         \
    orl   %edi, %esi;      \
    leal  t(%esi,a), a;   \
    roll  $s, a;           \
    addl  b, a;

  #define ROUND2(a, b, c, d, k, s, t)  \
    movl  c, %esi;         \
    addl  (k*4)(%rbp), a;  \
    xorl  d, %esi;         \
    xorl  b, %esi;         \
    leal  t(%esi,a), a;   \
    roll  $s, a;           \
    addl  b, a;

  #define ROUND3(a, b, c, d, k, s, t)  \
    movl  d, %esi;        \
    not   %esi;           \
    addl  (k*4)(%rbp), a; \
    orl   b, %esi;        \
    xorl  c, %esi;        \
    leal  t(%esi,a), a;   \
    roll  $s, a;          \
    addl  b, a;

  /* Save registers */
  pushq  %rbx
  pushq  %rbp

  /* Load arguments */
  movq  %rsi, %rbp
  movl   0(%rdi), AA  /* a */
  movl   4(%rdi), BB  /* b */
  movl   8(%rdi), CC  /* c */
  movl  12(%rdi), DD  /* d */
  movq  %rdi, %r8

  /* 64 rounds of hashing */
  ROUND0(AA, BB, CC, DD,  0,  7, -0x28955B88)
  ROUND0(DD, AA, BB, CC,  1, 12, -0x173848AA)
  ROUND0(CC, DD, AA, BB,  2, 17,  0x242070DB)
  ROUND0(BB, CC, DD, AA,  3, 22, -0x3E423112)
  ROUND0(AA, BB, CC, DD,  4,  7, -0x0A83F051)
  ROUND0(DD, AA, BB, CC,  5, 12,  0x4787C62A)
  ROUND0(CC, DD, AA, BB,  6, 17, -0x57CFB9ED)
  ROUND0(BB, CC, DD, AA,  7, 22, -0x02B96AFF)
  ROUND0(AA, BB, CC, DD,  8,  7,  0x698098D8)
  ROUND0(DD, AA, BB, CC,  9, 12, -0x74BB0851)
  ROUND0(CC, DD, AA, BB, 10, 17, -0x0000A44F)
  ROUND0(BB, CC, DD, AA, 11, 22, -0x76A32842)
  ROUND0(AA, BB, CC, DD, 12,  7,  0x6B901122)
  ROUND0(DD, AA, BB, CC, 13, 12, -0x02678E6D)
  ROUND0(CC, DD, AA, BB, 14, 17, -0x5986BC72)
  ROUND0(BB, CC, DD, AA, 15, 22,  0x49B40821)
  ROUND1(AA, BB, CC, DD,  1,  5, -0x09E1DA9E)
  ROUND1(DD, AA, BB, CC,  6,  9, -0x3FBF4CC0)
  ROUND1(CC, DD, AA, BB, 11, 14,  0x265E5A51)
  ROUND1(BB, CC, DD, AA,  0, 20, -0x16493856)
  ROUND1(AA, BB, CC, DD,  5,  5, -0x29D0EFA3)
  ROUND1(DD, AA, BB, CC, 10,  9,  0x02441453)
  ROUND1(CC, DD, AA, BB, 15, 14, -0x275E197F)
  ROUND1(BB, CC, DD, AA,  4, 20, -0x182C0438)
  ROUND1(AA, BB, CC, DD,  9,  5,  0x21E1CDE6)
  ROUND1(DD, AA, BB, CC, 14,  9, -0x3CC8F82A)
  ROUND1(CC, DD, AA, BB,  3, 14, -0x0B2AF279)
  ROUND1(BB, CC, DD, AA,  8, 20,  0x455A14ED)
  ROUND1(AA, BB, CC, DD, 13,  5, -0x561C16FB)
  ROUND1(DD, AA, BB, CC,  2,  9, -0x03105C08)
  ROUND1(CC, DD, AA, BB,  7, 14,  0x676F02D9)
  ROUND1(BB, CC, DD, AA, 12, 20, -0x72D5B376)
  ROUND2(AA, BB, CC, DD,  5,  4, -0x0005C6BE)
  ROUND2(DD, AA, BB, CC,  8, 11, -0x788E097F)
  ROUND2(CC, DD, AA, BB, 11, 16,  0x6D9D6122)
  ROUND2(BB, CC, DD, AA, 14, 23, -0x021AC7F4)
  ROUND2(AA, BB, CC, DD,  1,  4, -0x5B4115BC)
  ROUND2(DD, AA, BB, CC,  4, 11,  0x4BDECFA9)
  ROUND2(CC, DD, AA, BB,  7, 16, -0x0944B4A0)
  ROUND2(BB, CC, DD, AA, 10, 23, -0x41404390)
  ROUND2(AA, BB, CC, DD, 13,  4,  0x289B7EC6)
  ROUND2(DD, AA, BB, CC,  0, 11, -0x155ED806)
  ROUND2(CC, DD, AA, BB,  3, 16, -0x2B10CF7B)
  ROUND2(BB, CC, DD, AA,  6, 23,  0x04881D05)
  ROUND2(AA, BB, CC, DD,  9,  4, -0x262B2FC7)
  ROUND2(DD, AA, BB, CC, 12, 11, -0x1924661B)
  ROUND2(CC, DD, AA, BB, 15, 16,  0x1FA27CF8)
  ROUND2(BB, CC, DD, AA,  2, 23, -0x3B53A99B)
  ROUND3(AA, BB, CC, DD,  0,  6, -0x0BD6DDBC)
  ROUND3(DD, AA, BB, CC,  7, 10,  0x432AFF97)
  ROUND3(CC, DD, AA, BB, 14, 15, -0x546BDC59)
  ROUND3(BB, CC, DD, AA,  5, 21, -0x036C5FC7)
  ROUND3(AA, BB, CC, DD, 12,  6,  0x655B59C3)
  ROUND3(DD, AA, BB, CC,  3, 10, -0x70F3336E)
  ROUND3(CC, DD, AA, BB, 10, 15, -0x00100B83)
  ROUND3(BB, CC, DD, AA,  1, 21, -0x7A7BA22F)
  ROUND3(AA, BB, CC, DD,  8,  6,  0x6FA87E4F)
  ROUND3(DD, AA, BB, CC, 15, 10, -0x01D31920)
  ROUND3(CC, DD, AA, BB,  6, 15, -0x5CFEBCEC)
  ROUND3(BB, CC, DD, AA, 13, 21,  0x4E0811A1)
  ROUND3(AA, BB, CC, DD,  4,  6, -0x08AC817E)
  ROUND3(DD, AA, BB, CC, 11, 10, -0x42C50DCB)
  ROUND3(CC, DD, AA, BB,  2, 15,  0x2AD7D2BB)
  ROUND3(BB, CC, DD, AA,  9, 21, -0x14792C6F)

  /* Save updated state */
  addl  AA,  0(%r8)
  addl  BB,  4(%r8)
  addl  CC,  8(%r8)
  addl  DD, 12(%r8)

  /* Restore registers */
  popq %rbp
  popq %rbx
  retq
