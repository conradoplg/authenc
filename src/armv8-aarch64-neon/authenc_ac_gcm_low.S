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
.macro mul128_p64 r0, r1, a, b, t0, t1, z
    //r0 = a0 * b0
    pmull \r0\().1q, \a\().1d, \b\().1d
    //r1 = a1 * b1
    pmull2 \r1\().1q, \a\().2d, \b\().2d
    //Reverse low and high parts
    ext.16b \t0, \b, \b, #8
    //t1 = a0 * b1
    pmull \t1\().1q, \a\().1d, \t0\().1d
    //t0 = a1 * b0
    pmull2 \t0\().1q, \a\().2d, \t0\().2d
    //t0 (a0 * b1) + (a1 * b0)
    eor.16b \t0, \t0, \t1
    //xor into place
    ext.16b \t1, \z, \t0, #8
    eor.16b \r0, \r0, \t1
    ext.16b \t1, \t0, \z, #8
    eor.16b \r1, \r1, \t1
.endm

/**
 * GCM reduction using VMULL.
 *
 * @param[out] rq The reduced value.
 * @param[in] a0q Lower part of operand. Clobbered.
 * @param[in] a1q Higher part of operand. Clobbered.
 * @param[in] t0q Temp register. Clobbered.
 * @param[in] t1q Temp register. Clobbered.
 * @param[in] pq Precomputed value (0x00000000000000870000000000000087). Preserved.
 */
.macro rdc_p64 rq, a0q, a1q, t0q, t1q, pq, zq
    pmull2 \t0q\().1q, \a1q\().2d, \pq\().2d
    ext \t1q\().16b, \t0q\().16b, \zq\().16b, #8
    eor.16b \a1q, \a1q, \t1q
    ext \t1q\().16b, \zq\().16b, \t0q\().16b, #8
    eor.16b \a0q, \a0q, \t1q
    pmull \t0q\().1q, \a1q\().1d, \pq\().1d
    eor.16b \rq, \a0q, \t0q
.endm

ac_gcm_convert_low:
_ac_gcm_convert_low:
    ld1.16b {v0}, [x1]
    rbit.16b v0, v0
	st1.16b {v0}, [x0]
	ret

ac_gcm_ghash_low:
_ac_gcm_ghash_low:
    cbz x3, exit

	// Load old Y
	ld1.16b {v14}, [x0]
	// Load H^1--H^8
    ld1.16b {v0,v1,v2,v3}, [x1], #64
    ld1.16b {v4,v5,v6,v7}, [x1]
    movi.16b v8, #0x87
    ushr.2d v8, v8, #(64-8)
    movi.16b v9, #0

	cmp x3, #127
	b.ls leftover

	ghash_block:
	// Load input
	ld1.16b {v12}, [x2], #16
	// Convert to GCM format
	rbit.16b v12, v12
	// v14 = in0 ^ Y0
	eor.16b v14, v14, v12
	// q10-q11 = (in0 ^ Y0) * H^8
    mul128_p64 v10, v11, v14, v7, v15, v16, v9

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in1 * H^7
    mul128_p64 v12, v13, v14, v6, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in2 * H^6
    mul128_p64 v12, v13, v14, v5, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in3 * H^5
    mul128_p64 v12, v13, v14, v4, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in4 * H^4
    mul128_p64 v12, v13, v14, v3, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in5 * H^3
    mul128_p64 v12, v13, v14, v2, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in6 * H^2
    mul128_p64 v12, v13, v14, v1, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    // Load input
	ld1.16b {v14}, [x2], #16
	// Convert to GCM format
	rbit.16b v14, v14
	// q12-q13 = in7 * H
    mul128_p64 v12, v13, v14, v0, v15, v16, v9
    eor.16b v10, v10, v12
    eor.16b v11, v11, v13

    rdc_p64 v14, v10, v11, v12, v13, v8, v9

	sub x3, x3, #128
    cmp x3, #127
    b.hi ghash_block

    leftover:
    cbz x3, finish
    // Load input
	ld1.16b {v12}, [x2], #16
	// Convert to GCM format
    rbit.16b v12, v12
	// Y' = in ^ Y
	eor.16b v14, v14, v12
	// Y' = (in ^ Y) * H
    mul128_p64 v12, v13, v14, v0, v15, v10, v9
    rdc_p64 v14, v12, v13, v10, v11, v8, v9
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
    movi.16b v8, #0x87
    ushr.2d v8, v8, #(64-8)
    movi.16b v9, #0

	// Load A
	ld1.16b {v2}, [x1]
	// C = A * B
    mul128_p64 v0, v1, v2, v3, v15, v10, v9
    rdc_p64 v2, v0, v1, v12, v13, v8, v9

	st1.16b {v2}, [x0]

	ret
