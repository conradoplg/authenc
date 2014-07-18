//.arm
.align 4
.globl sc_aesctr_enc_low
.globl _sc_aesctr_enc_low
.globl _asmtest
.globl asmtest

asmtest:
_asmtest:
    ldr q0, [x0], #16
    ld1.16b {v0, v1}, [x0], #32
    eor.16b v0, v2, v2
    //eor v0.16b, v1.16b, v2.16b
    .rept 100
    eor v0.16b, v0.16b, v1.16b
    eor v2.16b, v2.16b, v0.16b
    .endr
    ret

#define AESE(d, m) .word (0b11110011101100000000001100000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

#define AESMC(d, m) .word (0b11110011101100000000001110000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )



//extern void sc_aesctr_enc_low(unsigned char *output, const unsigned char *input,
//                              size_t input_len, const unsigned char *nonce, const unsigned char *ekey);
#if 1
sc_aesctr_enc_low:
_sc_aesctr_enc_low:
    //r0 = output
    //r1 = input
    //r2 = input_len
    //r3 = nonce
    //r4 = ekey
    cbz x2, finish
#if 1
    //load expanded key
    ld1.16b {v8, v9, v10, v11}, [x4], #64
    ld1.16b {v12, v13, v14, v15}, [x4], #64
    ld1.16b {v1, v2, v3}, [x4], #48

    //q5 = counter
    //q6 = counter + 1
    ld1.16b {v5}, [x3], #16
#endif
#if 1
    mov.16b v6, v5
    mov w12, v6.S[3]
    rev w12, w12
    add w12, w12, #1
    rev w12, w12
    mov v6.S[3], w12
#endif
#if 1
full_block:
    mov.16b v0, v5
        mov.16b v7, v6
    aese.16b v0, v8
        aese.16b v7, v8
    mov w12, v5.S[3]
        mov w3, v6.S[3]
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    rev w12, w12
        rev w3, w3
    aese.16b v0, v9
        aese.16b v7, v9
    add w12, w12, #2
        add w3, w3, #2
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    rev w12, w12
        rev w3, w3
    aese.16b v0, v10
        aese.16b v7, v10
    mov v5.S[3], w12
        mov v6.S[3], w3
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v11
        aese.16b v7, v11
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v12
        aese.16b v7, v12
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v13
        aese.16b v7, v13
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v14
        aese.16b v7, v14
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v15
        aese.16b v7, v15
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v1
        aese.16b v7, v1
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v2
        aese.16b v7, v2
    eor.16b v0, v0, v3
        eor.16b v7, v7, v3

    //load input
    ld1.16b {v4}, [x1], #16

    //encrypt
    eor.16b v4, v4, v0

        ld1.16b {v0}, [x1], #16

        eor.16b v0, v0, v7

    //store
    st1.16b {v4}, [x0], #16

        st1.16b {v0}, [x0], #16

    subs x2, x2, #32
	b.ne full_block
#endif
    finish:
    ret
#endif