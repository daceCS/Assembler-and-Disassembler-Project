import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from mhc_asm import HEADER, MAGIC, Assembler, write_ascii, write_bin
from mhc_sim import run_bin

PY = sys.executable


def run(*args):
    return subprocess.run([PY, *args], capture_output=True, text=True)


EXPECTED = ["FizzBuzz" if i % 15 == 0 else "Fizz" if i % 3 == 0 else "Buzz" if i % 5 == 0 else str(i)
            for i in range(1, 101)]

with tempfile.TemporaryDirectory() as d:
    d = Path(d)

    # 1. Assemble the original FizzBuzz into both formats.
    p = run("mhc_asm.py", "fizzbuzz.asm", "-o", str(d / "orig"))
    assert p.returncode == 0, p.stderr
    orig_bin = (d / "orig.mhc-bin").read_bytes()
    orig_ascii = (d / "orig.mhc-ascii").read_bytes()

    # 2. Disassemble each format (auto-detected); the two results must agree.
    for fmt in ("mhc-bin", "mhc-ascii"):
        p = run("mhc_disasm.py", str(d / f"orig.{fmt}"), "-o", str(d / f"from_{fmt}.asm"))
        assert p.returncode == 0, p.stderr
        assert "Verified" in p.stdout, p.stdout
        print(f"[{fmt}] {p.stdout.strip().splitlines()[-1]}")
    a_bin = (d / "from_mhc-bin.asm").read_text()
    a_ascii = (d / "from_mhc-ascii.asm").read_text()
    assert a_bin == a_ascii
    print("Both formats give the same reconstructed program")

    # 3. Reassemble the reconstructed program: files must be byte-identical.
    p = run("mhc_asm.py", str(d / "from_mhc-bin.asm"), "-o", str(d / "again"))
    assert p.returncode == 0, p.stderr
    assert (d / "again.mhc-bin").read_bytes() == orig_bin
    assert (d / "again.mhc-ascii").read_bytes() == orig_ascii
    print("Reassembled mhc-bin and mhc-ascii are byte-for-byte identical to the originals")

    # 4. The reconstructed program still prints FizzBuzz.
    got = run_bin(d / "again.mhc-bin").split("\n")[:-1]
    assert got == EXPECTED
    print("Reconstructed program prints correct FizzBuzz for 1..100")

    # 5. A harder round trip: many instruction kinds, mixed data, unreferenced bytes.
    tricky = r'''
        .data
a:      .byte 1, 2, 255
b:      .asciiz "x#y \"q\"\n"
        .ascii  "tail"
        .text
main:   lui   $t0, 0x1234
        andi  $t1, $t0, 0xff
        xori  $t1, $t1, 7
        sw    $t1, -4($sp)
        lw    $t2, 8($sp)
        lb    $t3, 0($t0)
        sh    $t3, 2($t0)
        sll   $t4, $t3, 2
        srl   $t4, $t4, 1
        sra   $t4, $t4, 1
        mul   $t5, $t4, $t3
        mult  $t4, $t5
        mflo  $t6
        mfhi  $t7
        slt   $s0, $t6, $t7
        sltu  $s1, $t6, $t7
        xor   $s2, $s0, $s1
        nor   $s3, $s0, $s1
        li    $s4, 0x12345678
        la    $a0, a
        la    $a1, b
        jal   sub1
        beq   $t0, $t1, main
        bne   $t0, $t1, sub1
        nop
        jr    $ra
sub1:   jr    $ra
'''
    asm = Assembler(tricky)
    assert asm.assemble(), asm.errors
    write_bin(d / "tricky.mhc-bin", asm)
    write_ascii(d / "tricky.mhc-ascii", asm)
    for fmt in ("mhc-bin", "mhc-ascii"):
        p = run("mhc_disasm.py", str(d / f"tricky.{fmt}"), "-o", str(d / f"tricky_{fmt}.asm"))
        assert p.returncode == 0, (p.stdout, p.stderr)
        assert "Verified" in p.stdout
    print("Tricky program round-trips from both formats")
    print((d / "tricky_mhc-bin.asm").read_text())

    # 6. Error handling.
    def bad(name, content, frag):
        f = d / name
        f.write_bytes(content)
        p = run("mhc_disasm.py", str(f), "-o", str(d / "junk.asm"))
        assert p.returncode == 1 and frag in p.stderr, (name, p.returncode, p.stderr)
        print(f"ok error: {p.stderr.strip().splitlines()[0]}")

    good_hdr = lambda ts, ds: HEADER.pack(MAGIC, 0x00400000, 0x00400000, ts, 0x10010000, ds)
    bad("trunc.mhc-bin", good_hdr(8, 0) + b"\0" * 4, "truncated")
    bad("short.mhc-bin", MAGIC + b"\0\0", "too short")
    bad("opcode.mhc-bin", good_hdr(4, 0) + struct.pack(">I", 0xFFFFFFFF), "cannot decode word 0xFFFFFFFF")
    bad("bases.mhc-bin", HEADER.pack(MAGIC, 0, 0x1000, 0, 0x10010000, 0), "unsupported base addresses")
    bad("junk.mhc-ascii", b".entry 0x00400000\n.text base=0x00400000 bytes=4\nhello\n", "expected 32 binary digits")
    bad("nosec.mhc-ascii", b"00000000000000000000000000000000\n", "before any section marker")
    bad("noentry.mhc-ascii", b".text base=0x00400000 bytes=0\n", "missing .entry")
    bad("binary_garbage.mhc-ascii", b"\xff\xfe\xfd\xfc", "neither mhc-bin")

    p = run("mhc_disasm.py", str(d / "does_not_exist.mhc-bin"))
    assert p.returncode == 2 and "cannot read" in p.stderr
    print("ok error:", p.stderr.strip())

print("ALL DISASSEMBLER TESTS PASSED")
