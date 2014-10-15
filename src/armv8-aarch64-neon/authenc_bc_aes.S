.align 4
.globl bc_aes_4sbox
.globl _bc_aes_4sbox

bc_aes_4sbox:
_bc_aes_4sbox:
    movi.16b v0, #0x52
    movi.16b v1, #0
    mov v0.S[0], w0
    aese.16b v0, v1
    addv s0, v0.4s
    mov w0, v0.S[0]
    ret
