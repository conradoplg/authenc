.align 4
.globl sc_aesctr_enc_low
.globl _sc_aesctr_enc_low

/**
 * Computes AES-CTR encryption.
 * @param[out] x0 Pointer to output.
 * @param[in] x1 Pointer to input.
 * @param[in] x2 Length of input/output.
 * @param[in] x3 Pointer to 16-byte nonce (16 bytes).
 * @param[in] x4 Pointer to expanded key (11 * 16 bytes).
 */
sc_aesctr_enc_low:
_sc_aesctr_enc_low:
    cbz x2, finish

    //load expanded key
    ld1.16b {v8, v9, v10, v11}, [x4], #64
    ld1.16b {v12, v13, v14, v15}, [x4], #64
    ld1.16b {v1, v2, v3}, [x4], #48

    //v5 = counter
    //v6 = counter + 1
    //w5 = right-most 32 bits of counter
    //w6 = right-most 32 bits of counter + 1
    ld1.16b {v5}, [x3], #16
    mov w5, v5.S[3]
    rev w5, w5
    mov.16b v6, v5
    mov w6, v6.S[3]
    rev w6, w6
    add w6, w6, #1
    rev w12, w6
    mov v6.S[3], w12

    cmp x2, #31
    b.ls leftover

    full_block:
    mov.16b v0, v5
        mov.16b v7, v6
    aese.16b v0, v8
        aese.16b v7, v8
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    aese.16b v0, v9
        aese.16b v7, v9
    add w5, w5, #2
        add w6, w6, #2
    aesmc.16b v0, v0
        aesmc.16b v7, v7
    rev w12, w5
        rev w3, w6
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
    cbz x2, finish

    leftover:
    mov.16b v0, v5
    aese.16b v0, v8
    aesmc.16b v0, v0
    aese.16b v0, v9
    add w5, w5, #2
    aesmc.16b v0, v0
    rev w12, w5
    aese.16b v0, v10
    mov v5.S[3], w12
    aesmc.16b v0, v0
    aese.16b v0, v11
    aesmc.16b v0, v0
    aese.16b v0, v12
    aesmc.16b v0, v0
    aese.16b v0, v13
    aesmc.16b v0, v0
    aese.16b v0, v14
    aesmc.16b v0, v0
    aese.16b v0, v15
    aesmc.16b v0, v0
    aese.16b v0, v1
    aesmc.16b v0, v0
    aese.16b v0, v2
    eor.16b v0, v0, v3
    //load input
    ld1.16b {v4}, [x1], #16
    //encrypt
    eor.16b v4, v4, v0
    //store
    st1.16b {v4}, [x0], #16

    finish:
    ret
