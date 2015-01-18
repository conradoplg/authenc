.align 4
.globl bc_aes_4sbox
.globl _bc_aes_4sbox

//Clang assembler does not allow aese/aesmc on armv7, even though it is supported.
//For this reason these macros are defined to insert the opcodes.

#define AESE(d, m) .word (0b11110011101100000000001100000000 \
 | ((m & 0x7) << 1) | ((m & 0x8) << 2) \
 | ((d & 0x7) << 13) | ((d & 0x8) << 19) )

bc_aes_4sbox:
_bc_aes_4sbox:
    vmov.i8 q0, #0x52
    vmov.i8 q1, #0
    vmov s0, r0
    AESE(0, 1)
    veor d0, d1
    vpadd.i32 d0, d0, d1
    vmov r0, s0
    bx lr
