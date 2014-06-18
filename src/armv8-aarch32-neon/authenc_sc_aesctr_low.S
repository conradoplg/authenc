.arm
.align 4
.globl sc_aesctr_enc_low
.globl _sc_aesctr_enc_low
.globl _asmtest
.globl asmtest

asmtest:
_asmtest:
    .rept 100
    veor q0, q1
    veor q2, q0
    .endr
    bx lr

#define AESE(d, m) .word (0b11110011101100000000001100000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

#define AESMC(d, m) .word (0b11110011101100000000001110000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )



//extern void sc_aesctr_enc_low(unsigned char *output, const unsigned char *input,
//                              size_t input_len, const unsigned char *nonce, const unsigned char *ekey);

sc_aesctr_enc_low:
_sc_aesctr_enc_low:
    //r0 = output
    //r1 = input
    //r2 = input_len
    //r3 = nonce
    //r12 = ekey
    teq r2, #0
	bxeq lr
    ldr r12, [sp]
    vpush {q4-q7}
#if 1
    //load expanded key
    vldm r12!, {q8-q15}
    vldm r12, {q1-q3}

    //q5 = counter
    //q6 = counter + 1
    vld1.64 {q5}, [r3]
#endif
#if 1
    vmov q6, q5
    vmov.32 r12, d13[1]
    rev r12, r12
    add r12, #1
    rev r12, r12
    vmov.32 d13[1], r12
#endif
#if 1
full_block:
    vmov q0, q5
        vmov q7, q6
    AESE(0, 8)
        AESE(7, 8)
    vmov.32 r12, d11[1]
        vmov.32 r3, d13[1]
    AESMC(0, 0)
        AESMC(7, 7)
    rev r12, r12
        rev r3, r3
    AESE(0, 9)
        AESE(7, 9)
    add r12, #2
        add r3, #2
    AESMC(0, 0)
        AESMC(7, 7)
    rev r12, r12
        rev r3, r3
    AESE(0, 10)
        AESE(7, 10)
    vmov.32 d11[1], r12
        vmov.32 d13[1], r3
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
#endif
    vpop {q4-q7}
    bx lr
