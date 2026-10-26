"""Tiny MIPS interpreter for mhc-bin files (just enough for the FizzBuzz program).

Supports the integer instructions and syscalls 1 (print int), 4 (print string)
and 10 (exit). run_bin(path) returns everything the program printed.
"""
from pathlib import Path

from mhc_asm import HEADER


def s32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x & 0x80000000 else x


def run_bin(path, max_steps=1_000_000):
    b = Path(path).read_bytes()
    magic, entry, tb, ts, db, ds = HEADER.unpack_from(b)
    assert magic == b"MHC1"
    mem = {}
    for i, x in enumerate(b[HEADER.size:HEADER.size + ts]):
        mem[tb + i] = x
    for i, x in enumerate(b[HEADER.size + ts:HEADER.size + ts + ds]):
        mem[db + i] = x
    r = [0] * 32
    hi = lo = 0
    pc = entry
    out = []
    for _ in range(max_steps):
        w = int.from_bytes(bytes(mem[pc + i] for i in range(4)), "big")
        op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
        sh, fn, imm = (w >> 6) & 31, w & 63, w & 0xFFFF
        simm = imm - 65536 if imm & 0x8000 else imm
        npc = pc + 4
        if op == 0:
            if fn == 0x0C:
                v0 = r[2]
                if v0 == 1:
                    out.append(str(s32(r[4])))
                elif v0 == 4:
                    a = r[4]
                    while mem[a]:
                        out.append(chr(mem[a]))
                        a += 1
                elif v0 == 10:
                    return "".join(out)
            elif fn in (0x20, 0x21):
                r[rd] = (r[rs] + r[rt]) & 0xFFFFFFFF
            elif fn in (0x22, 0x23):
                r[rd] = (r[rs] - r[rt]) & 0xFFFFFFFF
            elif fn == 0x2A:
                r[rd] = int(s32(r[rs]) < s32(r[rt]))
            elif fn == 0x00:
                r[rd] = (r[rt] << sh) & 0xFFFFFFFF
            elif fn == 0x1A:
                a, b_ = s32(r[rs]), s32(r[rt])
                q = abs(a) // abs(b_) * (1 if (a < 0) == (b_ < 0) else -1)
                lo, hi = q & 0xFFFFFFFF, (a - q * b_) & 0xFFFFFFFF
            elif fn == 0x10:
                r[rd] = hi
            elif fn == 0x12:
                r[rd] = lo
            elif fn == 0x08:
                npc = r[rs]
            else:
                raise RuntimeError(f"sim: funct {fn:#x}")
        elif op in (8, 9):
            r[rt] = (r[rs] + simm) & 0xFFFFFFFF
        elif op == 0x0D:
            r[rt] = r[rs] | imm
        elif op == 0x0F:
            r[rt] = imm << 16
        elif op == 4:
            if r[rs] == r[rt]:
                npc = pc + 4 + simm * 4
        elif op == 5:
            if r[rs] != r[rt]:
                npc = pc + 4 + simm * 4
        elif op == 2:
            npc = (pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        else:
            raise RuntimeError(f"sim: opcode {op:#x}")
        r[0] = 0
        pc = npc
    raise RuntimeError("sim: did not halt")
