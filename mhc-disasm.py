#!/usr/bin/env python3
"""
mhc_disasm.py - disassembler for the MHC formats written by mhc_asm.py.

USAGE
    python mhc_disasm.py fizzbuzz.mhc-bin                  # -> fizzbuzz_disasm.asm
    python mhc_disasm.py fizzbuzz.mhc-ascii -o out.asm
    python mhc_disasm.py fizzbuzz.mhc-bin --no-verify

The input format (mhc-bin or mhc-ascii) is detected automatically: a file
starting with the bytes "MHC1" is binary, anything else is read as ASCII.

WHAT IT DOES
    * Reads the section markers / header to separate instructions from data,
      so data bytes are never decoded as instructions.
    * Decodes each text word back to a real MIPS instruction. Pseudo-
      instruction spellings are not recovered, with one exception: a
      lui/ori pair that builds an address inside the data section is
      written as 'la reg, label' so the program stays readable.
    * Creates labels: 'main' at the entry point, L_<addr> at every branch or
      jump target, and D_<addr> in the data section at every address that
      'la' refers to (and at the start of the data).
    * Rebuilds the data section as .asciiz / .ascii for printable
      NUL-terminated text, otherwise as .byte lists.
    * Original comments and label names are not recoverable.

VERIFICATION
    Unless --no-verify is given, the generated assembly is assembled again
    with mhc_asm.Assembler and compared with the input: text bytes, data
    bytes and entry address must all be identical. The exit status is 1
    if they differ.

LIMITS
    Only the instruction set supported by mhc_asm.py can be decoded, and
    the images must use the default base addresses (text 0x00400000,
    data 0x10010000). Anything else is reported as an error with its
    address, for example an unknown opcode or non-zero unused fields.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

from mhc_asm import (BRANCH, DATA_BASE, HEADER, I_SIGNED, I_UNSIGNED, JUMP, MAGIC,
                     MEM, MULDIV, R3, REG_NAMES, SHIFT, TEXT_BASE, Assembler)


class DisasmError(Exception):
    pass


class Image:
    """A loaded program: entry address plus text and data bytes."""

    def __init__(self, entry, text_base, text, data_base, data):
        self.entry, self.text_base, self.text = entry, text_base, bytes(text)
        self.data_base, self.data = data_base, bytes(data)


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------
def read_bin(raw):
    if len(raw) < HEADER.size:
        raise DisasmError(f"file is too short for the {HEADER.size}-byte header")
    magic, entry, tb, ts, db, ds = HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise DisasmError(f"bad magic {magic!r}, expected {MAGIC!r}")
    if ts % 4:
        raise DisasmError(f"text size {ts} is not a multiple of 4")
    if len(raw) < HEADER.size + ts + ds:
        raise DisasmError(
            f"file is truncated: header promises {ts} text + {ds} data bytes, "
            f"only {len(raw) - HEADER.size} bytes follow the header")
    text = raw[HEADER.size:HEADER.size + ts]
    data = raw[HEADER.size + ts:HEADER.size + ts + ds]
    return Image(entry, tb, text, db, data)


def read_ascii(raw):
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise DisasmError("input is neither mhc-bin (no 'MHC1' magic) nor ASCII text")
    entry = None
    sections = {}      # name -> [base, size, bytearray]
    current = None
    for ln, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        if line.startswith(".entry"):
            m = re.fullmatch(r"\.entry\s+0x([0-9A-Fa-f]+)", line)
            if not m:
                raise DisasmError(f"line {ln}: malformed .entry line: {line!r}")
            entry = int(m.group(1), 16)
        elif line.startswith("."):
            m = re.fullmatch(r"\.(text|data)\s+base=0x([0-9A-Fa-f]+)\s+bytes=(\d+)", line)
            if not m:
                raise DisasmError(f"line {ln}: malformed section marker: {line!r}")
            if m.group(1) in sections:
                raise DisasmError(f"line {ln}: duplicate .{m.group(1)} section")
            current = [int(m.group(2), 16), int(m.group(3)), bytearray()]
            sections[m.group(1)] = current
        elif re.fullmatch(r"[01]{32}", line):
            if current is None:
                raise DisasmError(f"line {ln}: machine-code word before any section marker")
            current[2] += int(line, 2).to_bytes(4, "big")
        else:
            raise DisasmError(f"line {ln}: expected 32 binary digits or a section marker, "
                              f"got {line[:40]!r}")
    if entry is None:
        raise DisasmError("missing .entry line")
    if "text" not in sections:
        raise DisasmError("missing .text section")
    tb, ts, text = sections["text"]
    db, ds, data = sections.get("data", [DATA_BASE, 0, bytearray()])
    if ts % 4 or len(text) != ts:
        raise DisasmError(f".text declares {ts} bytes but has {len(text)} bytes of words")
    if len(data) < ds or len(data) - ds > 3:
        raise DisasmError(f".data declares {ds} bytes but has {len(data)} bytes of words")
    return Image(entry, tb, text, db, bytes(data[:ds]))


def load(path):
    raw = Path(path).read_bytes()
    return read_bin(raw) if raw[:4] == MAGIC else read_ascii(raw)


# --------------------------------------------------------------------------
# Instruction decoding
# --------------------------------------------------------------------------
def invert(d):
    return {v: k for k, v in d.items()}


R3_REV, SHIFT_REV, MULDIV_REV = invert(R3), invert(SHIFT), invert(MULDIV)
I_SIGNED_REV, I_UNSIGNED_REV = invert(I_SIGNED), invert(I_UNSIGNED)
MEM_REV, BRANCH_REV, JUMP_REV = invert(MEM), invert(BRANCH), invert(JUMP)


def r(i):
    return "$" + REG_NAMES[i]


def decode(w, pc):
    """Return (mnemonic, operands, target) or None if the word is not decodable.
    A None operand marks the slot for a branch/jump target address."""
    op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
    sh, fn, imm = (w >> 6) & 31, w & 63, w & 0xFFFF
    simm = imm - 0x10000 if imm & 0x8000 else imm
    if w == 0:
        return "nop", [], None
    if op == 0:
        if fn in R3_REV and sh == 0:
            return R3_REV[fn], [r(rd), r(rs), r(rt)], None
        if fn in SHIFT_REV and rs == 0:
            return SHIFT_REV[fn], [r(rd), r(rt), str(sh)], None
        if fn in MULDIV_REV and rd == 0 and sh == 0:
            return MULDIV_REV[fn], [r(rs), r(rt)], None
        if fn in (0x10, 0x12) and rs == 0 and rt == 0 and sh == 0:
            return ("mfhi" if fn == 0x10 else "mflo"), [r(rd)], None
        if fn == 0x08 and rt == 0 and rd == 0 and sh == 0:
            return "jr", [r(rs)], None
        if w == 0x0C:
            return "syscall", [], None
        return None
    if op == 0x1C and fn == 0x02 and sh == 0:
        return "mul", [r(rd), r(rs), r(rt)], None
    if op in I_SIGNED_REV:
        return I_SIGNED_REV[op], [r(rt), r(rs), str(simm)], None
    if op in I_UNSIGNED_REV:
        return I_UNSIGNED_REV[op], [r(rt), r(rs), f"0x{imm:X}"], None
    if op == 0x0F and rs == 0:
        return "lui", [r(rt), f"0x{imm:X}"], None
    if op in MEM_REV:
        return MEM_REV[op], [r(rt), f"{simm}({r(rs)})"], None
    if op in BRANCH_REV:
        return BRANCH_REV[op], [r(rs), r(rt), None], pc + 4 + simm * 4
    if op in JUMP_REV:
        return JUMP_REV[op], [None], ((pc + 4) & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
    return None


# --------------------------------------------------------------------------
# Data rendering
# --------------------------------------------------------------------------
ESC = {10: "\\n", 9: "\\t", 13: "\\r", 92: "\\\\", 34: '\\"'}


def printable(c):
    return c in ESC or 32 <= c <= 126


def esc(bs):
    return "".join(ESC.get(c, chr(c)) for c in bs)


def render_chunk(b):
    """Directive lines for one run of data bytes."""
    segs, cur = [], bytearray()
    for c in b:
        if c == 0:
            segs.append(("asciiz", bytes(cur)))
            cur = bytearray()
        elif printable(c):
            cur.append(c)
        else:
            segs = None
            break
    if segs is not None:
        if cur:
            segs.append(("ascii", bytes(cur)))
        return [f'.{kind} "{esc(s)}"' for kind, s in segs]
    return [".byte " + ", ".join(f"0x{c:02X}" for c in b[i:i + 12])
            for i in range(0, len(b), 12)]


# --------------------------------------------------------------------------
# Disassembly
# --------------------------------------------------------------------------
def disassemble(img):
    if img.text_base != TEXT_BASE or (img.data and img.data_base != DATA_BASE):
        raise DisasmError(
            f"unsupported base addresses (text 0x{img.text_base:08X}, data 0x{img.data_base:08X}); "
            f"mhc_asm.py can only reproduce text 0x{TEXT_BASE:08X} and data 0x{DATA_BASE:08X}")
    tb, db = img.text_base, img.data_base
    n = len(img.text) // 4
    text_end = tb + len(img.text)
    words = [int.from_bytes(img.text[i * 4:i * 4 + 4], "big") for i in range(n)]

    decoded, errors = [], []
    for i, w in enumerate(words):
        d = decode(w, tb + 4 * i)
        if d is None:
            errors.append(f"  0x{tb + 4 * i:08X}: cannot decode word 0x{w:08X} "
                          f"({w:032b}) as a supported instruction")
        decoded.append(d)
    if errors:
        raise DisasmError("undecodable text words:\n" + "\n".join(errors))

    entry_ok = tb <= img.entry < text_end and img.entry % 4 == 0
    targets = {d[2] for d in decoded if d[2] is not None and tb <= d[2] < text_end}

    def tlabel(addr):
        return "main" if entry_ok and addr == img.entry else f"L_{addr:08X}"

    def dlabel(addr):
        return f"D_{addr:08X}"

    # Pass A: merge lui/ori address pairs into 'la' and collect data references.
    items, data_refs, i = [], set(), 0
    while i < n:
        pc = tb + 4 * i
        mn, ops, tgt = decoded[i]
        if (mn == "lui" and i + 1 < n and decoded[i + 1][0] == "ori"
                and pc + 4 not in targets):
            rt = (words[i] >> 16) & 31
            w2 = words[i + 1]
            if (w2 >> 21) & 31 == rt and (w2 >> 16) & 31 == rt:
                addr = ((words[i] & 0xFFFF) << 16) | (w2 & 0xFFFF)
                if db <= addr <= db + len(img.data):
                    data_refs.add(addr - db)
                    items.append((pc, f"la {r(rt)}, {dlabel(addr)}"))
                    i += 2
                    continue
        if tgt is not None:
            name = tlabel(tgt) if tgt in targets else f"0x{tgt:08X}"
            ops = [name if o is None else o for o in ops]
        items.append((pc, f"{mn} {', '.join(ops)}".rstrip()))
        i += 1

    out = ["# Reconstructed by mhc_disasm.py (comments and original label names are not recoverable)"]
    if img.data:
        out += ["", "        .data"]
        cuts = sorted({0} | {o for o in data_refs if o < len(img.data)})
        cuts.append(len(img.data))
        for a, b in zip(cuts, cuts[1:]):
            out.append(f"{dlabel(db + a)}:")
            out += [f"        {line}" for line in render_chunk(img.data[a:b])]
        if len(img.data) in data_refs:
            out.append(f"{dlabel(db + len(img.data))}:")
    out += ["", "        .text"]
    if entry_ok:
        out.append("        .globl main")
    for pc, line in items:
        if pc in targets or (entry_ok and pc == img.entry):
            out.append(f"{tlabel(pc)}:")
        out.append(f"        {line}")
    return "\n".join(out) + "\n"


def verify(source, img):
    """Reassemble `source`; return a list of problems (empty = identical)."""
    asm = Assembler(source)
    if not asm.assemble():
        return [f"reassembly failed: line {ln}: {msg}" for ln, msg in asm.errors]
    problems = []
    if asm.text_bytes != img.text:
        if len(asm.text_bytes) != len(img.text):
            problems.append(f"text size differs: {len(asm.text_bytes)} vs {len(img.text)} bytes")
        else:
            off = next(i for i, (x, y) in enumerate(zip(asm.text_bytes, img.text)) if x != y)
            problems.append(f"text differs first at offset {off} (0x{TEXT_BASE + off:08X})")
    if bytes(asm.data) != img.data:
        problems.append(f"data differs ({len(asm.data)} vs {len(img.data)} bytes)")
    if asm.entry != img.entry:
        problems.append(f"entry differs: 0x{asm.entry:08X} vs 0x{img.entry:08X}")
    return problems


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="a .mhc-bin or .mhc-ascii file")
    ap.add_argument("-o", "--output", help="output assembly file (default: <name>_disasm.asm)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip reassembling the result and comparing bytes")
    args = ap.parse_args(argv)

    src = Path(args.input)
    try:
        img = load(src)
        source = disassemble(img)
    except OSError as e:
        print(f"error: cannot read '{src}': {e.strerror}", file=sys.stderr)
        return 2
    except DisasmError as e:
        print(f"{src}: error: {e}", file=sys.stderr)
        return 1

    if args.output:
        dest = Path(args.output)
    else:
        stem = re.sub(r"\.mhc-(bin|ascii)$", "", src.name)
        dest = src.with_name(stem + "_disasm.asm")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(source, encoding="utf-8")
    print(f"Wrote {dest} ({len(img.text) // 4} instruction words, {len(img.data)} data bytes)")

    if args.no_verify:
        return 0
    problems = verify(source, img)
    if problems:
        print("VERIFICATION FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"Verified: reassembling {dest.name} reproduces the original "
          f"text ({len(img.text)} bytes), data ({len(img.data)} bytes) and entry point exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())