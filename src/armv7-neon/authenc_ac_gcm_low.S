.arm
.align 4
.globl ac_gcm_convert_low
.globl _ac_gcm_convert_low
.globl ac_gcm_ghash_low
.globl _ac_gcm_ghash_low

/**
 * Binary 64x64-bit polynomial multiplication.
 *
 * Clobbers t0q, t1q, t2q, t3q.
 *
 * @param[in] ad		First operand.
 * @param[in] bd		Second operand.
 * @param[in] k16		The constant #0x000000000000FFFF
 * @param[in] k32		The constant #0x00000000FFFFFFFF
 * @param[in] k48		The constant #0x0000FFFFFFFFFFFF
 * @param[out] rq		The result ad * bd
 */
.macro mul64_p8 rq rl rh ad bd k16 k32 k48 t0q t0l t0h t1q t1l t1h t2q t2l t2h t3q t3l t3h
	@A1
	vext.8  \t0l, \ad, \ad, $1
	@F = A1*B
	vmull.p8 \t0q, \t0l, \bd
	@B1
	vext.8  \rl, \bd, \bd, $1
	@E = A*B1 (7)
	vmull.p8 \rq, \ad, \rl
		@A2
		vext.8  \t1l, \ad, \ad, $2
		@H = A2*B
		vmull.p8 \t1q, \t1l, \bd
		@B2
		vext.8  \t3l, \bd, \bd, $2
		@G = A*B2
		vmull.p8 \t3q, \ad, \t3l
			@A3
			vext.8  \t2l, \ad, \ad, $3
			@J = A3*B
			vmull.p8 \t2q, \t2l, \bd
	@L = E + F
	veor	\t0q, \t0q, \rq
			@B3
			vext.8  \rl, \bd, \bd, $3
			@I = A*B3
			vmull.p8 \rq, \ad, \rl
		@M = G + H
		veor	\t1q, \t1q, \t3q
				@B4
				vext.8  \t3l, \bd, \bd, $4
				@K = A*B4
				vmull.p8 \t3q, \ad, \t3l
	@t0 = (L) (P0 + P1) << 8
	veor	\t0l, \t0l, \t0h
	vand	\t0h, \t0h, \k48
		@t1 = (M) (P2 + P3) << 16
		veor	\t1l, \t1l, \t1h
		vand	\t1h, \t1h, \k32
			@N = I + J
			veor	\t2q, \t2q, \rq
	veor	\t0l, \t0l, \t0h
		veor	\t1l, \t1l, \t1h
			@t2 = (N) (P4 + P5) << 24
			veor	\t2l, \t2l, \t2h
			vand	\t2h, \t2h, \k16
				@t3 = (K) (P6 + P7) << 32
				veor	\t3l, \t3l, \t3h
				vmov.i64 \t3h, $0
	vext.8  \t0q, \t0q, \t0q, $15
			veor	\t2l, \t2l, \t2h
		vext.8  \t1q, \t1q, \t1q, $14
				vmull.p8 \rq, \ad, \bd
			vext.8  \t2q, \t2q, \t2q, $13
				vext.8  \t3q, \t3q, \t3q, $12
	veor	\t0q, \t0q, \t1q
	veor	\t2q, \t2q, \t3q
	veor	\rq, \rq, \t0q
	veor	\rq, \rq, \t2q

.endm

/**
 * Binary 128x128-bit polynomial multiplication.
 *
 * Clobbers d16-d18, d21-d31
 *
 * @param[in] q2		First operand.
 * @param[in] q3		Second operand.
 * @param[in] d16		The constant #0x000000000000FFFF
 * @param[in] d17		The constant #0x00000000FFFFFFFF
 * @param[in] d18		The constant #0x0000FFFFFFFFFFFF
 * @param[out] q1:q0	The result q2 * q3.
 */
.macro mul128_p8
	mul64_p8 q0, d0, d1, d4, d6, d16, d17, d18, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	mul64_p8 q1, d2, d3, d5, d7, d16, d17, d18, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	//veor d20, d6, d7
	veor d21, d4, d5
	mul64_p8 q11, d22, d23, d20, d21, d16, d17, d18, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	veor q11, q0
	veor q11, q1
	veor d1, d22
	veor d2, d23
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
 *
 * Clobbers q0, q1, q14, q15.
 *
 * @param[in] q1:q0		The number polynomial to be reduced.
 * @param[out] q2		The reduced value.
 */
.macro rrdc
	// Reflected reduction. Input: q1:q0.
	//d28 = d0 << 57
	//d29 = d1 << 57
	vshl.i64 q14, q0, #57
	//d30 = d0 << 62
	//d31 = d1 << 62
	vshl.i64 q15, q0, #62
	//d30 = (d0 << 62) ^ (d0 << 57)
	//d31 = (d1 << 62) ^ (d1 << 57)
	veor q15, q15, q14
	//d28 = (d0 << 63)
	//d29 = (d1 << 63)
	vshl.i64 q14, q0, #63
	//d30 = (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
	//d31 = (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor q15, q15, q14
	//d1 = d1 ^ (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
	veor d1, d1, d30
	//d2 = d2 ^ (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor d2, d2, d31

	//d30 = d0 >> 1
	//d31 = d1 >> 1
	vshr.u64 q15, q0, #1
	//d2' = d2 ^ d0
	//d3' = d3 ^ d1
	veor q1, q1, q0
	//d0' = d0 ^ (d0 >> 1)
	//d1' = d1 ^ (d1 >> 1)
	veor q0, q0, q15
	//d30 = (d0 >> 7)
	//d31 = (d1 >> 7)
	vshr.u64 q15, q15, #6
	//d0' = (d0 >> 1) ^ (d0 >> 2)
	//d1' = (d1 >> 1) ^ (d1 >> 2)
	vshr.u64 q0, q0, #1
	//d0' = d2 ^ d0 ^ (d0 >> 1) ^ (d0 >> 2)
	//d1' = d3 ^ d1 ^ (d1 >> 1) ^ (d1 >> 2)
	veor q0, q0, q1
	//d0' = d2 ^ d0 ^ (d0 >> 1) ^ (d0 >> 2) ^ (d0 >> 7)
	//d1' = d3 ^ d1 ^ (d1 >> 1) ^ (d1 >> 2) ^ (d1 >> 7)
	veor q2, q0, q15
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
	vldm r0, {q2}
	vmov.i64 d18, #0x0000FFFFFFFFFFFF
	// Load H
	vldm r1, {q3}
	vmov.i64 d17, #0x00000000FFFFFFFF
	vmov.i64 d16, #0x000000000000FFFF
	veor d20, d6, d7

	ghash_block:
	// Load input
	vld1.64 {q0}, [r2]!
	// Convert to GCM format
	vrev64.8 q0, q0
	vswp d0, d1
	// Y' = in ^ Y
	veor q2, q0
	// Y' = (in ^ Y) * H
	mul128_p8
	rrdc

	subs r3, #16
	bne ghash_block

	vstm r0, {q2}

	bx lr
