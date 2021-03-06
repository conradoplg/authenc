.arm
.align 4
.globl sc_aesctr_enc_low
.globl _sc_aesctr_enc_low

//Clang assembler does not allow aese/aesmc on armv7, even though it is supported.
//For this reason these macros are defined to insert the opcodes.

#define AESE(d, m) .word (0b11110011101100000000001100000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

#define AESMC(d, m) .word (0b11110011101100000000001110000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

/**
 * Computes AES-CTR encryption.
 * @param[out] r0 Pointer to output.
 * @param[in] r1 Pointer to input.
 * @param[in] r2 Length of input/output.
 * @param[in] r3 Pointer to 16-byte nonce (16 bytes).
 * @param[in] [sp] Pointer to expanded key (11 * 16 bytes).
 */
sc_aesctr_enc_low:
_sc_aesctr_enc_low:
    teq r2, #0
	bxeq lr
	//r12 = ekey
    ldr r12, [sp]
    push {r10,r11}
    vpush {q4-q7}

    //load expanded key
    vldm r12!, {q8-q15}
    vldm r12, {q1-q3}

    //q5 = counter
    //q6 = counter + 1
    //r12 = right-most 32 bits of counter
    //r3 = right-most 32 bits of counter + 1
    vld1.64 {q5}, [r3]
    vmov.32 r12, d11[1]
    rev r12, r12
    vmov q6, q5
    vmov.32 r3, d13[1]
    rev r3, r3
    add r3, #1
    rev r11, r3
    vmov.32 d13[1], r11

    cmp r2, #31
    bls leftover

	full_block:
	    vmov q0, q5
	        vmov q7, q6
	    AESE(0, 8)
	        AESE(7, 8)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 9)
	        AESE(7, 9)
	    add r12, #2
	        add r3, #2
	    AESMC(0, 0)
	        AESMC(7, 7)
	    rev r10, r12
	        rev r11, r3
	    AESE(0, 10)
	        AESE(7, 10)
	    vmov.32 d11[1], r10
	        vmov.32 d13[1], r11
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 11)
	        AESE(7, 11)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 12)
	        AESE(7, 12)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 13)
	        AESE(7, 13)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 14)
	        AESE(7, 14)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 15)
	        AESE(7, 15)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 1)
	        AESE(7, 1)
	    AESMC(0, 0)
	        AESMC(7, 7)
	    AESE(0, 2)
	        AESE(7, 2)
	    veor q0, q3
	        veor q7, q3
	    //load input
	    vld1.64 {q4}, [r1]!
	    //encrypt
	    veor q4, q0
	        vld1.64 {q0}, [r1]!
	        veor q0, q7
	    //store
	    vst1.64 {q4}, [r0]!
	        vst1.64 {q0}, [r0]!
	    subs r2, #32
		bne full_block
	    cmp r2, #0
	    beq finish

    leftover:
    vmov q0, q5
    AESE(0, 8)
    AESMC(0, 0)
    AESE(0, 9)
    add r12, #2
    AESMC(0, 0)
    rev r10, r12
    AESE(0, 10)
    vmov.32 d11[1], r10
    AESMC(0, 0)
    AESE(0, 11)
    AESMC(0, 0)
    AESE(0, 12)
    AESMC(0, 0)
    AESE(0, 13)
    AESMC(0, 0)
    AESE(0, 14)
    AESMC(0, 0)
    AESE(0, 15)
    AESMC(0, 0)
    AESE(0, 1)
    AESMC(0, 0)
    AESE(0, 2)
    veor q0, q3
    //load input
    vld1.64 {q4}, [r1]!
    //encrypt
    veor q4, q0
    //store
    vst1.64 {q4}, [r0]!

    finish:
    vpop {q4-q7}
    pop {r10,r11}
    bx lr
