.arm
.align
.globl ac_gcm_mul_low
.globl ac_gcm_convert_low

#define AC_GCM_REFLC

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

#ifndef AC_GCM_REFLC

ac_gcm_mul_low:
	vld1.32 {d4,d5}, [r1]
	vld1.32 {d6,d7}, [r2]

	vmov.i64 d14, #0x0000FFFFFFFFFFFF
	vmov.i64 d13, #0x00000000FFFFFFFF
	vmov.i64 d12, #0x000000000000FFFF

	mul64_p8 q0, d0, d1, d4, d6, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	mul64_p8 q1, d2, d3, d5, d7, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	veor d6, d7
	veor d7, d4, d5
	mul64_p8 q2, d4, d5, d6, d7, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	veor q2, q0
	veor q2, q1
	veor d1, d4
	veor d2, d5

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

	vst1.32 {d0,d1}, [r0]

	bx lr

ac_gcm_convert_low:
	ldm r1, {r1, r2, r3, ip}
	rbit r1, r1
	rbit r2, r2
	rbit r3, r3
	rbit ip, ip
	rev r1, r1
	rev r2, r2
	rev r3, r3
	rev ip, ip
	stm r0, {r1, r2, r3, ip}
	bx lr

#else

ac_gcm_mul_low:
	vld1.32 {d4,d5}, [r1]
	vld1.32 {d6,d7}, [r2]

	vmov.i64 d14, #0x0000FFFFFFFFFFFF
	vmov.i64 d13, #0x00000000FFFFFFFF
	vmov.i64 d12, #0x000000000000FFFF

	mul64_p8 q0, d0, d1, d4, d6, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	mul64_p8 q1, d2, d3, d5, d7, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	veor d6, d7
	veor d7, d4, d5
	mul64_p8 q2, d4, d5, d6, d7, d12, d13, d14, q12, d24, d25, q13, d26, d27, q14, d28, d29, q15, d30, d31
	veor q2, q0
	veor q2, q1
	veor d1, d4
	veor d2, d5

	//d4 = d0 << 57
	//d5 = d1 << 57
	vshl.i64	q2,q0,#57		@ 1st phase
	//d6 = d0 << 62
	//d7 = d1 << 62
	vshl.i64	q3,q0,#62
	//d6 = (d0 << 62) ^ (d0 << 57)
	//d7 = (d1 << 62) ^ (d1 << 57)
	veor		q3,q3,q2		@
	//d4 = (d0 << 63)
	//d5 = (d1 << 63)
	vshl.i64	q2,q0,#63
	//d6 = (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
	//d7 = (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor		q3, q3, q2		@
	//d1 = d1 ^ (d0 << 62) ^ (d0 << 57) ^ (d0 << 63)
 	veor		d1,d1,d6	@
 	//d2 = d2 ^ (d1 << 62) ^ (d1 << 57) ^ (d1 << 63)
	veor		d2,d2,d7

	vshr.u64	q3,q0,#1		@ 2nd phase
	veor		q1,q1,q0
	veor		q0,q0,q3		@
	vshr.u64	q3,q3,#6
	vshr.u64	q0,q0,#1		@
	veor		q0,q0,q1		@
	veor		q0,q0,q3		@

	vst1.32 {d0,d1}, [r0]

	bx lr

ac_gcm_convert_low:
	vld1.32 {q0}, [r1]
	vrev64.8 q0, q0
	vswp d0, d1
	vst1.32 {q0}, [r0]
	bx lr

#endif
