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
 * @param[out] r The reduced value.
 * @param[in] a0 Lower part of operand. Clobbered.
 * @param[in] a1 Higher part of operand. Clobbered.
 * @param[in] t0 Temp register. Clobbered.
 * @param[in] t1 Temp register. Clobbered.
 * @param[in] p Precomputed value (0x00000000000000870000000000000087). Preserved.
 */
.macro rdc_p64 r, a0, a1, t0, t1, p, z
	// Reduce higher part
	// t0 = a1h * 0x87
    pmull2 \t0\().1q, \a1\().2d, \p\().2d
    // xor into place
    ext \t1\().16b, \t0\().16b, \z\().16b, #8
    eor.16b \a1, \a1, \t1
    ext \t1\().16b, \z\().16b, \t0\().16b, #8
    eor.16b \a0, \a0, \t1
    // Reduce lower part
    // t0 = a1l * 0x87
    pmull \t0\().1q, \a1\().1d, \p\().1d
    // xor into place
    eor.16b \r, \a0, \t0
.endm

.macro ghash_block_iter h
    // Load input
	ld1.16b {v24}, [x2], #16
	// Convert to GCM format
	rbit.16b v24, v24
	// Y' = in[n] * H^(8-n)
    mul128_p64 v22, v23, v24, \h, v25, v16, v19
    // Accumulate unreduced result
    eor.16b v20, v20, v22
    eor.16b v21, v21, v23
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
	ld1.16b {v24}, [x0]
	// Load H^1--H^8
    ld1.16b {v0,v1,v2,v3}, [x1], #64
    ld1.16b {v4,v5,v6,v7}, [x1]
    // Constant used in reduction
    movi.16b v18, #0x87
    ushr.2d v18, v18, #(64-8)
    // Zero register used in reduction
    movi.16b v19, #0

	cmp x3, #127
	b.ls leftover

	// Hash 8 blocks
	ghash_block:
		// Load input
		ld1.16b {v22}, [x2], #16
		// Convert to GCM format
		rbit.16b v22, v22
		// Y' = in0 ^ Y0
		eor.16b v24, v24, v22
		// Y' = (in0 ^ Y0) * H^8
	    mul128_p64 v20, v21, v24, v7, v25, v16, v19

		ghash_block_iter v6
		ghash_block_iter v5
		ghash_block_iter v4
		ghash_block_iter v3
		ghash_block_iter v2
		ghash_block_iter v1
		ghash_block_iter v0

	    rdc_p64 v24, v20, v21, v22, v23, v18, v19

		sub x3, x3, #128
	    cmp x3, #127
	    b.hi ghash_block

	// Hash remaining blocks
    leftover:
	    cbz x3, finish

	    // Load input
		ld1.16b {v22}, [x2], #16
		// Convert to GCM format
	    rbit.16b v22, v22
		// Y' = in ^ Y
		eor.16b v24, v24, v22
		// Y' = (in ^ Y) * H
	    mul128_p64 v22, v23, v24, v0, v25, v20, v19
	    rdc_p64 v24, v22, v23, v20, v21, v18, v19

	    sub x3, x3, #16
	    b leftover

    finish:
	st1.16b {v24}, [x0]

    exit:
	ret

ac_gcm_mul_low:
_ac_gcm_mul_low:
	// Load B
	ld1.16b {v3}, [x2]
	// Constant used in reduction
    movi.16b v18, #0x87
    ushr.2d v18, v18, #(64-8)
    // Zero register used in reduction
    movi.16b v19, #0

	// Load A
	ld1.16b {v2}, [x1]
	// C = A * B
    mul128_p64 v0, v1, v2, v3, v25, v20, v19
    rdc_p64 v2, v0, v1, v22, v23, v18, v19

	st1.16b {v2}, [x0]

	ret
