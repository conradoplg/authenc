.arm
.align
.globl ac_gcm_mul_low
.globl ac_gcm_convert_low

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

ac_gcm_mul_low:
	vld1.32 {d4,d5}, [r1:64]
	vld1.32 {d6,d7}, [r2:64]

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
	vmull.p8 q2, d2, d30
	vmull.p8 q3, d3, d30
	vuzp.8 d4, d5
	vuzp.8 d6, d7

	vswp d5, d6

	veor q0, q2
	vshl.i64 q8, q3, #8
	vsri.64 d17, d6, #(64-8)
	vshr.U64 d18, d7, #(64-8)
	veor q0, q8

	vmull.p8 q2, d18, d30
	veor d0, d4

	vst1.32 {d0,d1}, [r0:64]

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
