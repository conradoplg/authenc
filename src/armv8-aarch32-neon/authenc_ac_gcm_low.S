.arm
.align 4
.globl ac_gcm_convert_low
.globl _ac_gcm_convert_low
.globl ac_gcm_ghash_low
.globl _ac_gcm_ghash_low
.globl ac_gcm_mul_low
.globl _ac_gcm_mul_low

.macro vmull_p64 d, n, m
    .word (0b11110010101000000000111000000000 \
    | (\m & 0xF) | ((\m & 0x10) << 1) \
    | ((\n & 0xF) << 16) | ((\n & 0x10) << 3) \
    | ((\d & 0x7) << 13) | ((\d & 0x8) << 19) )
.endm

/**
 * Binary 128x128-bit polynomial multiplication.
 *
 * @param[out] r0q, r0qn, r0l, r0h   Lower part of result (q register, number of q, lower d, higher d)
 * @param[out] r1q, r1qn, r1l, r1h   Higher part of result (q register, number of q, lower d, higher d)
 * @param[in] al, aln, ah, ahn  First operand (lower d, number of lower d, higher d, number of higher d). Preserved.
 * @param[in] bl, bln, bh, bhn  Second operand (lower d, number of lower d, higher d, number of higher d). Preserved.
 * @param[in] t1q, t1qn, t1l, t1ln, t1h, t1hn Temp register (q reg, # of q, lower d, # of lower d, higher d, # of higher d). Clobbered.
 */
.macro mul128_p64 r0q, r0qn, r0l, r0h, r1q, r1qn, r1l, r1h, al, aln, ah, ahn, bl, bln, bh, bhn, t1q, t1qn, t1l, t1ln, t1h, t1hn
    vmull_p64 \r0qn, \aln, \bln
    vmull_p64 \r1qn, \ahn, \bhn
	veor \t1h, \bl, \bh
	veor \t1l, \al, \ah
    vmull_p64 \t1qn, \t1hn, \t1ln
	veor \t1q, \r0q
	veor \t1q, \r1q
	veor \r0h, \t1l
	veor \r1l, \t1h
.endm

/**
 * Reflected GCM reduction.
 *
 * @param[out] rq		The reduced value.
 * @param[in] a0q, a0l, a0h Lower part of operand (q reg, lower d, higher d). Clobbered.
 * @param[in] a1q, a1l, a1h Higher part of operand (q reg, lower d, higher d). Clobbered.
 * @param[in] t0q, t0l, t0h Temp reg (q reg, lower d, higher d). Clobbered.
 * @param[in] t1q, t1l, t1h Temp reg (q reg, lower d, higher d). Clobbered.
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
    vpush {q4-q7}

	// Load old Y
	vldm r0, {q14}
	// Load H^1--H^8
    vldm r1, {q0-q7}

	cmp r3, #127
	bls leftover

	ghash_block:
	// Load input
	vld1.64 {q12}, [r2]!
	// Convert to GCM format
	vrev64.8 q12, q12
	vswp d24, d25
	// q8 = in0 ^ Y0
	veor q14, q12
	// q10-q11 = (in0 ^ Y0) * H^8
	mul128_p64 q10, 10, d20, d21,  q11, 11, d22, d23,  d28, 28, d29, 29,  d14, 14, d15, 15,  q15, 15, d30, 30, d31, 31

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in1 * H^7
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d12, 12, d13, 13,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in2 * H^6
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d10, 10, d11, 11,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in3 * H^5
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d8, 8, d9, 9,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    
    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in4 * H^4
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d6, 6, d7, 7,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    
    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in5 * H^3
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d4, 4, d5, 5,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    
    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in6 * H^2
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d2, 2, d3, 3,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

    
    // Load input
	vld1.64 {q14}, [r2]!
	// Convert to GCM format
	vrev64.8 q14, q14
	vswp d28, d29
	// q12-q13 = in7 * H
	mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d0, 0, d1, 1,  q15, 15, d30, 30, d31, 31
    veor q10, q12
    veor q11, q13

	rrdc q14, q10, d20, d21, q11, d22, d23, q12, d24, d25, q13, d26, d27

	sub r3, #128
    cmp r3, #127
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
    mul128_p64 q12, 12, d24, d25,  q13, 13, d26, d27,  d28, 28, d29, 29,  d0, 0, d1, 1,  q15, 15, d30, 30, d31, 31
    rrdc q14, q12, d24, d25, q13, d26, d27, q10, d20, d21, q11, d22, d23
    sub r3, #16
    b leftover

    finish:
	vstm r0, {q14}

    vpop {q4-q7}
	bx lr

ac_gcm_mul_low:
_ac_gcm_mul_low:
	// Load B
	vldm r2, {q3}
	veor d20, d6, d7

	// Load A
	vld1.64 {q2}, [r1]!
	// C = A * B
    mul128_p64 q0, 0, d0, d1,  q1, 1, d2, d3,  d4, 4, d5, 5,  d6, 6, d7, 7,  q15, 15, d30, 30, d31, 31
    rrdc q2, q0, d0, d1, q1, d2, d3, q12, d24, d25, q13, d26, d27

	vstm r0, {q2}

	bx lr
