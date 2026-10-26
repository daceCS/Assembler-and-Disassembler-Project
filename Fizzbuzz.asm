# FizzBuzz for 1..100 (MARS-style syscalls: 1 = print int, 4 = print string, 10 = exit)

        .data
fizz:     .asciiz "Fizz"
buzz:     .asciiz "Buzz"
newline:  .asciiz "\n"

        .text
        .globl main
main:
        li    $s0, 1                  # i = 1
loop:
        bgt   $s0, 100, done          # while (i <= 100)
        rem   $t0, $s0, 15
        beqz  $t0, do_fizzbuzz
        rem   $t0, $s0, 3
        beqz  $t0, do_fizz
        rem   $t0, $s0, 5
        beqz  $t0, do_buzz

        move  $a0, $s0                # print the number
        li    $v0, 1
        syscall
        j     print_newline

do_fizzbuzz:
        la    $a0, fizz
        li    $v0, 4
        syscall
        la    $a0, buzz
        li    $v0, 4
        syscall
        j     print_newline

do_fizz:
        la    $a0, fizz
        li    $v0, 4
        syscall
        j     print_newline

do_buzz:
        la    $a0, buzz
        li    $v0, 4
        syscall

print_newline:
        la    $a0, newline
        li    $v0, 4
        syscall
        addi  $s0, $s0, 1             # i++
        j     loop

done:
        li    $v0, 10                 # exit
        syscall