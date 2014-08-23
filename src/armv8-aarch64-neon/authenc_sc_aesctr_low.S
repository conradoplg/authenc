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
    ld1.16b {v16, v17, v18, v19}, [x4], #64
    ld1.16b {v20, v21, v22, v23}, [x4], #64
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
	    aese.16b v0, v16
	        aese.16b v7, v16
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v17
	        aese.16b v7, v17
	    add w5, w5, #2
	        add w6, w6, #2
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    rev w12, w5
	        rev w3, w6
	    aese.16b v0, v18
	        aese.16b v7, v18
	    mov v5.S[3], w12
	        mov v6.S[3], w3
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v19
	        aese.16b v7, v19
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v20
	        aese.16b v7, v20
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v21
	        aese.16b v7, v21
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v22
	        aese.16b v7, v22
	    aesmc.16b v0, v0
	        aesmc.16b v7, v7
	    aese.16b v0, v23
	        aese.16b v7, v23
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
    aese.16b v0, v16
    aesmc.16b v0, v0
    aese.16b v0, v17
    add w5, w5, #2
    aesmc.16b v0, v0
    rev w12, w5
    aese.16b v0, v18
    mov v5.S[3], w12
    aesmc.16b v0, v0
    aese.16b v0, v19
    aesmc.16b v0, v0
    aese.16b v0, v20
    aesmc.16b v0, v0
    aese.16b v0, v21
    aesmc.16b v0, v0
    aese.16b v0, v22
    aesmc.16b v0, v0
    aese.16b v0, v23
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
