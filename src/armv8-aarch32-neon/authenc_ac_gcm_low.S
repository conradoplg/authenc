.arm
.align 4
.globl ac_gcm_convert_low
.globl _ac_gcm_convert_low
.globl ac_gcm_ghash_low
.globl _ac_gcm_ghash_low

#define VMULLP64(d, n, m) .word (0b11110010101000000000111000000000 \
 | (m & 0xF) | ((m & 0x10) << 1) \
 | ((n & 0xF) << 16) | ((n & 0x10) << 3) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

/**
 * Binary 128x128-bit polynomial multiplication.
 *
 * Clobbers d16-d18, d20-d31
 *
 * @param[in] q2		First operand.
 * @param[in] q3		Second operand.
 * @param[in] d16		The constant #0x000000000000FFFF
 * @param[in] d17		The constant #0x00000000FFFFFFFF
 * @param[in] d18		The constant #0x0000FFFFFFFFFFFF
 * @param[out] q1:q0	The result q2 * q3.
 */
.macro mul128_p8
    VMULLP64(0, 4, 6)
    VMULLP64(1, 5, 7)
	//veor d20, d6, d7
	veor d21, d4, d5
    VMULLP64(11, 20, 21)
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
 * Clobbers q0, q1, q8, q9.
 *
 * @param[in] q1:q0		The number polynomial to be reduced.
 * @param[out] q2		The reduced value.
 */
.macro rrdc
	// Reflected reduction. Input: q1:q0.
	//d16 = d0 << 57
	//d17 = d1 << 57
	vshl.i64 q8, q0, #57
	//d18 = d0 << 62
	//d19 = d1 << 62
	vshl.i64 q9, q0, #62
	//d18 = (d0 << 62) ^ (d0 << 57)
	//d19 = (d1 << 62) ^ (d1 << 57)
	veor q9, q9, q8
	//d16 = (d0 << 63)
	//d17 = (d1 << 63)
	vshl.i64 q8, q0, #63
	//d18 = (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
	//d19 = (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor q9, q9, q8
	//d1 = d1 ^ (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
	veor d1, d1, d18
	//d2 = d2 ^ (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor d2, d2, d19

	//d18 = d0 >> 1
	//d19 = d1 >> 1
	vshr.u64 q9, q0, #1
	//d2' = d2 ^ d0
	//d3' = d3 ^ d1
	veor q1, q1, q0
	//d0' = d0 ^ (d0 >> 1)
	//d1' = d1 ^ (d1 >> 1)
	veor q0, q0, q9
	//d18 = (d0 >> 7)
	//d19 = (d1 >> 7)
	vshr.u64 q9, q9, #6
	//d0' = (d0 >> 1) ^ (d0 >> 2)
	//d1' = (d1 >> 1) ^ (d1 >> 2)
	vshr.u64 q0, q0, #1
	//d0' = d2 ^ d0 ^ (d0 >> 1) ^ (d0 >> 2)
	//d1' = d3 ^ d1 ^ (d1 >> 1) ^ (d1 >> 2)
	veor q0, q0, q1
	//d0' = d2 ^ d0 ^ (d0 >> 1) ^ (d0 >> 2) ^ (d0 >> 7)
	//d1' = d3 ^ d1 ^ (d1 >> 1) ^ (d1 >> 2) ^ (d1 >> 7)
	veor q2, q0, q9
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
	// Load H
	vldm r1, {q3}
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
