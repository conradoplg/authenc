.align 4
.globl ac_gcm_convert_low
.globl _ac_gcm_convert_low
.globl ac_gcm_ghash_low
.globl _ac_gcm_ghash_low
.globl ac_gcm_mul_low
.globl _ac_gcm_mul_low

/**
 * Binary 128x128-bit polynomial multiplication.
 *
 * @param[out] r0q Lower part of result.
 * @param[out] r1q Higher part of result.
 * @param[in] aq First operand. Preserved.
 * @param[in] bq Second operand. Preserved.
 * @param[in] t0q Temp register. Clobbered.
 * @param[in] t1q Temp register. Clobbered.
 * @param[in] zq Zeroed register. Preserved.
 */
.macro mul128_p64 r0q, r1q, aq, bq, t0q, t1q, zq
    //r0 = a0 * b0
    pmull \r0q\().1q, \aq\().1d, \bq\().1d
    //r1 = a1 * b1
    pmull2 \r1q\().1q, \aq\().2d, \bq\().2d
    //Reverse low and high parts
    ext.16b \t0q, \bq, \bq, #8
    //t1 = a0 * b1
    pmull \t1q\().1q, \aq\().1d, \t0q\().1d
    //t0 = a1 * b0
    pmull2 \t0q\().1q, \aq\().2d, \t0q\().2d
    //t0 (a0 * b1) + (a1 * b0)
    eor.16b \t0q, \t0q, \t1q
    //xor into place
    ext.16b \t1q, \zq, \t0q, #8
    eor.16b \r0q, \r0q, \t1q
    ext.16b \t1q, \t0q, \zq, #8
    eor.16b \r1q, \r1q, \t1q
.endm

/**
 * Reflected GCM reduction using VMULL.
 *
 * @param[out] rq:		The reduced value.
 * @param[in] a0q, a0l, a0ln, a0h, a0hn: Lower part of operand (q reg, lower d, lower d #, higher d, higher d #). Clobbered.
 * @param[in] a1q, a1l, a1h: Higher part of operand (q reg, lower d, higher d). Clobbered.
 * @param[in] t0q, t0qn, t0l, t0h: Temp reg (q reg, q reg #, lower d, higher d). Clobbered.
 * @param[in] t1q, t1l, t1h: Temp reg (q reg, lower d, higher d). Clobbered.
 * @param[in] pdn: precomputed value # (0xc200000000000000)
 */
.macro rrdc_p64 rq, a0q, a0l, a0ln, a0h, a0hn, a1q, a1l, a1h, t0q, t0qn, t0l, t0h, t1q, t1l, t1h, pq, zq
    pmull \t0q\().1q, \a0q\().1d, \pq\().1d
    ext \t1q\().16b, \zq\().16b, \t0q\().16b, #8
    eor.16b \a0q, \a0q, \t1q
    ext \t1q\().16b, \t0q\().16b, \zq\().16b, #8
    eor.16b \a1q, \a1q, \t1q
    pmull2 \t0q\().1q, \a0q\().2d, \pq\().2d
    eor.16b \a1q, \a1q, \t0q
    eor.16b \rq, \a0q, \a1q
.endm

ac_gcm_convert_low:
_ac_gcm_convert_low:
    ld1.16b {v0}, [x1]
	rev64.16b v0, v0
	ext.16b v0, v0, v0, #8
	st1.16b {v0}, [x0]
	ret

ac_gcm_ghash_low:
_ac_gcm_ghash_low:
    cbz x3, exit

	// Load old Y
	ld1.16b {v14}, [x0]
	// Load H^1--H^8
    ld1.16b {v0,v1,v2,v3}, [x1], #(16*4)
    ld1.16b {v4,v5,v6,v7}, [x1]
    movi.16b v8, #0xc2
    shl.2d v8, v8, #(64-8)
    movi.16b v9, #0

#if 0
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

	rrdc_p64 q14, q10, d20, 20, d21, 21, q11, d22, d23, q12, 12, d24, d25, q13, d26, d27, 16

	sub r3, #128
    cmp r3, #127
    bhi ghash_block
#endif

    leftover:
    cbz x3, finish
    // Load input
	ld1.16b {v12}, [x2], #16
	// Convert to GCM format
	rev64.16b v12, v12
	ext.16b v12, v12, v12, #8
	// Y' = in ^ Y
	eor.16b v14, v14, v12
	// Y' = (in ^ Y) * H
    mul128_p64 v12, v13, v14, v0, v15, v10, v9
    rrdc_p64 v14, v12, d24, 24, d25, 25, v13, d26, d27, v10, 10, d20, d21, v11, d22, d23, v8, v9
    sub x3, x3, #16
    b leftover

    finish:
	st1.16b {v14}, [x0]

    exit:
	ret

ac_gcm_mul_low:
_ac_gcm_mul_low:
	// Load B
	ld1.16b {v3}, [x2]
    movi.16b v8, #0xc2
    shl.2d v8, v8, #(64-8)

	// Load A
	ld1.16b {v2}, [x1], #16
	// C = A * B
    mul128_p64 v0, v1, v2, v3, v15, v10, v9
    rrdc_p64 v2, v0, d0, 0, d1, 1, v1, d2, d3, v12, 12, d24, d25, v13, d26, d27, v8, v9

	st1.16b {v2}, [x0]

	ret
