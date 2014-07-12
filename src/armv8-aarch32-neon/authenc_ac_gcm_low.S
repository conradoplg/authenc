.arm
.align 4
.globl ac_gcm_convert_low
.globl _ac_gcm_convert_low
.globl ac_gcm_ghash_low
.globl _ac_gcm_ghash_low
.globl ac_gcm_mul_low
.globl _ac_gcm_mul_low

#define VMULLP64(d, n, m) .word (0b11110010101000000000111000000000 \
 | (m & 0xF) | ((m & 0x10) << 1) \
 | ((n & 0xF) << 16) | ((n & 0x10) << 3) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

.macro vmull_p64 d, n, m
    .word (0b11110010101000000000111000000000 \
    | (\m & 0xF) | ((\m & 0x10) << 1) \
    | ((\n & 0xF) << 16) | ((\n & 0x10) << 3) \
    | ((\d & 0x7) << 13) | ((\d & 0x8) << 19) )
.endm

/**
 * Binary 128x128-bit polynomial multiplication.
 * TODO: update
 * Clobbers d21-23.
 *
 * @param[in] q2		First operand.
 * @param[in] q3		Second operand.
 * @param[in] d20       Precomputed d6 + d7
 * @param[out] q1:q0	The result q2 * q3.
 */
.macro mul128_p64 r0q, r0qn, r0l, r0h, r1q, r1qn, r1l, r1h, al, aln, ah, ahn, bl, bln, bh, bhn, dd, ddn, t0d, t0dn, t1q, t1qn, t1l, t1h
    vmull_p64 \r0qn, \aln, \bln
    vmull_p64 \r1qn, \ahn, \bhn
	//veor \dd, \bl, \bh
	veor \t0d, \al, \ah
    vmull_p64 \t1qn, \ddn, \t0dn
	veor \t1q, \r0q
	veor \t1q, \r1q
	veor \r0h, \t1l
	veor \r1l, \t1h
.endm

/**
 * GCM reduction (modulo z^128 + z^7 + z^2 + z + 1).
 *
 * Clobbers q2-q3, q8-q9, d30.
 *
 * @param[in] q1:q0		The number polynomial to be reduced.
 * @param[out] q0		The reduced value.
 */
.macro rdc
	vmov.i8 d30, #135
	//[d3:d2|d1:d0]
	//[d3:d2] * r(z)
	//[d5:d4] = d2 * r(z)
	//[d7:d6] = d3 * r(z)
	//q2 = [d5:d4] = [  a7|  a6|  a5|  a4|  a3|  a2|  a1|  a0]
	vmull.p8 q2, d2, d30
	//q3 = [d7:d6] = [  b7|  b6|  b5|  b4|  b3|  b2|  b1|  b0]
	vmull.p8 q3, d3, d30
	//d4 = [a7|a6|a5|a4|a3|a2|a1|a0]
	//d5 = [A7|A6|A5|A4|A3|A2|A1|A0]
	vuzp.8 d4, d5
	//d6 = [b7|b6|b5|b4|b3|b2|b1|b0]
	//d7 = [B7|B6|B5|B4|B3|B2|B1|B0]
	vuzp.8 d6, d7

	//d4 = [a7|a6|a5|a4|a3|a2|a1|a0]
	//d5 = [b7|b6|b5|b4|b3|b2|b1|b0]
	//d6 = [A7|A6|A5|A4|A3|A2|A1|A0]
	//d7 = [B7|B6|B5|B4|B3|B2|B1|B0]
	vswp d5, d6

	//C ^= b:a
	veor q0, q2

	//d16 = [A6|A5|A4|A3|A2|A1|A0|  ]
	//d17 = [B6|B5|B4|B3|B2|B1|B0|A7]
	//d18 = [                     B7]
	vshl.i64 q8, q3, #8
	vsri.64 d17, d6, #(64-8)
	vshr.U64 d18, d7, #(64-8)

	//C ^= B:A
	veor q0, q8

	//Reduce d18 (B7)
	vmull.p8 q2, d18, d30
	veor d0, d4
.endm

/**
 * Reflected GCM reduction.
 * TODO: update
 * Clobbers q0, q1, q8, q9.
 *
 * @param[in] q1:q0		The number polynomial to be reduced.
 * @param[out] q2		The reduced value.
 */
.macro rrdc rq, a0q, a0l, a0h, a1q, a1l, a1h, t0q, t0l, t0h, t1q, t1l, t1h
	// Reflected reduction. Input: \a1q:\a0q.
	//\t0l = \a0l << 57
	//\t0h = \a0h << 57
	vshl.i64 \t0q, \a0q, #57
	//\t1l = \a0l << 62
	//\t1h = \a0h << 62
	vshl.i64 \t1q, \a0q, #62
	//\t1l = (\a0l << 62) ^ (\a0l << 57)
	//\t1h = (\a0h << 62) ^ (\a0h << 57)
	veor \t1q, \t1q, \t0q
	//\t0l = (\a0l << 63)
	//\t0h = (\a0h << 63)
	vshl.i64 \t0q, \a0q, #63
	//\t1l = (\a0l << 62) ^ (\a0l << 57) ^ (\a0l << 63)
	//\t1h = (\a0h << 62) ^ (\a0h << 57) ^ (\a0h << 63)
	veor \t1q, \t1q, \t0q
	//\a0h = \a0h ^ (\a0l << 62) ^ (\a0l << 57) ^ (\a0l << 63)
	veor \a0h, \a0h, \t1l
	//\a1l = \a1l ^ (\a0h << 62) ^ (\a0h << 57) ^ (\a0h << 63)
	veor \a1l, \a1l, \t1h

	//\t1l = \a0l >> 1
	//\t1h = \a0h >> 1
	vshr.u64 \t1q, \a0q, #1
	//\a1l' = \a1l ^ \a0l
	//\a1h' = \a1h ^ \a0h
	veor \a1q, \a1q, \a0q
	//\a0l' = \a0l ^ (\a0l >> 1)
	//\a0h' = \a0h ^ (\a0h >> 1)
	veor \a0q, \a0q, \t1q
	//\t1l = (\a0l >> 7)
	//\t1h = (\a0h >> 7)
	vshr.u64 \t1q, \t1q, #6
	//\a0l' = (\a0l >> 1) ^ (\a0l >> 2)
	//\a0h' = (\a0h >> 1) ^ (\a0h >> 2)
	vshr.u64 \a0q, \a0q, #1
	//\a0l' = \a1l ^ \a0l ^ (\a0l >> 1) ^ (\a0l >> 2)
	//\a0h' = \a1h ^ \a0h ^ (\a0h >> 1) ^ (\a0h >> 2)
	veor \a0q, \a0q, \a1q
	//\a0l' = \a1l ^ \a0l ^ (\a0l >> 1) ^ (\a0l >> 2) ^ (\a0l >> 7)
	//\a0h' = \a1h ^ \a0h ^ (\a0h >> 1) ^ (\a0h >> 2) ^ (\a0h >> 7)
	veor \rq, \a0q, \t1q
.endm


ac_gcm_convert_low:
_ac_gcm_convert_low:
	vld1.32 {q0}, [r1]
	vrev64.8 q0, q0
	vswp d0, d1
	vst1.32 {q0}, [r0]
	bx lr

ac_gcm_ghash_low:
_ac_gcm_ghash_low:
    teq r3, #0
    bxeq lr

	// Load old Y
	vldm r0, {q14}
	// Load H, H2, H3, H4
    vldm r1, {q0-q3}
    veor d16, d0, d1
	veor d17, d2, d3
    veor d18, d4, d5
    veor d19, d6, d7

	cmp r3, #63
	bls leftover

	ghash_block:
	// Load input
	vld1.64 {q12}, [r2]!
	// Convert to GCM format
	vrev64.8 q12, q12
	vswp d24, d25
	// q8 = in0 ^ Y0
	veor q14, q12
	// q10-q11 = (in0 ^ Y0) * H^4
    //mul128_p64 r0q, r0qn, r0l, r0h,  r1q, r1qn, r1l, r1h,  al, aln, ah, ahn,  bl, bln, bh, bhn,  dd, ddn,  t0d, t0dn,  t1q, t1qn
	mul128_p64 q10, 10, d20, d21,  q11, 11, d22, d23,  d28, 28, d29, 29,  d6, 6, d7, 7,  d19, 19, d30, 30, q15, 15, d30, d31

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in1 * H^3
    //mul128_p64 r0q, r0qn, r0l, r0h,  r1q, r1qn, r1l, r1h,  al, aln, ah, ahn,  bl, bln, bh, bhn,  dd, ddn,  t0d, t0dn,  t1q, t1qn
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d4, 4, d5, 5,  d18, 18,  d30, 30, q15, 15, d30, d31
    veor q10, q12
    veor q11, q13

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in2 * H^2
    //mul128_p64 r0q, r0qn, r0l, r0h,  r1q, r1qn, r1l, r1h,  al, aln, ah, ahn,  bl, bln, bh, bhn,  dd, ddn,  t0d, t0dn,  t1q, t1qn
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d2, 2, d3, 3,  d17, 17,  d30, 30, q15, 15, d30, d31
    veor q10, q12
    veor q11, q13

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in1 * H
    //mul128_p64 r0q, r0qn, r0l, r0h,  r1q, r1qn, r1l, r1h,  al, aln, ah, ahn,  bl, bln, bh, bhn,  dd, ddn,  t0d, t0dn,  t1q, t1qn
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d0, 0, d1, 1,  d16, 16,  d30, 30, q15, 15, d30, d31
    veor q10, q12
    veor q11, q13

    //rrdc rq, a0q, a0l, a0h, a1q, a1l, a1h, t0q, t0l, t0h, t1q, t1l, t1h
	rrdc q14, q10, d20, d21, q11, d22, d23, q12, d24, d25, q13, d26, d27

	sub r3, #64
    cmp r3, #63
    bhi ghash_block

    leftover:
    cmp r3, #0
    beq finish
    // Load input
	vld1.64 {q12}, [r2]!
	// Convert to GCM format
	vrev64.8 q12, q12
	vswp d24, d25
	// Y' = in ^ Y
	veor q14, q12
	// Y' = (in ^ Y) * H
    mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d0, 0, d1, 1,  d16, 16,  d30, 30, q15, 15, d30, d31
    rrdc q14, q12, d24, d25, q13, d26, d27, q10, d20, d21, q11, d22, d23
    sub r3, #16
    b leftover

    finish:
	vstm r0, {q14}

	bx lr

ac_gcm_mul_low:
_ac_gcm_mul_low:
	// Load B
	vldm r2, {q3}
	veor d20, d6, d7

	// Load A
	vld1.64 {q2}, [r1]!
	// C = A * B
    mul128_p64 q0, 0, d0, d1,  q1, 1, d2, d3,  d4, 4, d5, 5,  d6, 6, d7, 7,  d20, 20,  d21, 21,  q9, 9, d18, d19
    rrdc q2, q0, d0, d1, q1, d2, d3, q12, d24, d25, q13, d26, d27

	vstm r0, {q2}

	bx lr
