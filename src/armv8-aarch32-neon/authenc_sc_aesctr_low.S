.arm
.align 4
.globl sc_aesctr_enc_low
.globl _sc_aesctr_enc_low

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
    vpush {q4-q5}

    //q5 = counter
    vld1.64 {q5}, [r3]

    //load expanded key
    vldm r12!, {q8-q15}
    vldm r12, {q1-q3}

full_block:
    vmov q0, q5
    AESE(0, 8)
    vmov.32 r12, d11[1]
    AESMC(0, 0)
    rev r12, r12
    AESE(0, 9)
    add r12, #1
    AESMC(0, 0)
    rev r12, r12
    AESE(0, 10)
    vmov.32 d11[1], r12
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

    subs r2, #16
	bne full_block

    vpop {q4-q5}
    bx lr
