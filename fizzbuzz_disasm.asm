# Reconstructed by mhc_disasm.py (comments and original label names are not recoverable)

        .data
D_10010000:
        .asciiz "Fizz"
D_10010005:
        .asciiz "Buzz"
D_1001000A:
        .asciiz "\n"

        .text
        .globl main
main:
        addiu $s0, $zero, 1
L_00400004:
        addiu $at, $zero, 100
        slt $at, $at, $s0
        bne $at, $zero, L_004000B0
        addiu $at, $zero, 15
        div $s0, $at
        mfhi $t0
        beq $t0, $zero, L_00400050
        addiu $at, $zero, 3
        div $s0, $at
        mfhi $t0
        beq $t0, $zero, L_00400074
        addiu $at, $zero, 5
        div $s0, $at
        mfhi $t0
        beq $t0, $zero, L_00400088
        addu $a0, $zero, $s0
        addiu $v0, $zero, 1
        syscall
        j L_00400098
L_00400050:
        la $a0, D_10010000
        addiu $v0, $zero, 4
        syscall
        la $a0, D_10010005
        addiu $v0, $zero, 4
        syscall
        j L_00400098
L_00400074:
        la $a0, D_10010000
        addiu $v0, $zero, 4
        syscall
        j L_00400098
L_00400088:
        la $a0, D_10010005
        addiu $v0, $zero, 4
        syscall
L_00400098:
        la $a0, D_1001000A
        addiu $v0, $zero, 4
        syscall
        addi $s0, $s0, 1
        j L_00400004
L_004000B0:
        addiu $v0, $zero, 10
        syscall
