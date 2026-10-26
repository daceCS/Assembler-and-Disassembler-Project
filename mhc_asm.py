#!/usr/bin/env python3
"""
mhc_asm.py - a small two-pass MIPS-32 assembler that writes the MHC formats.

USAGE
    python mhc_asm.py fizzbuzz.asm                 # -> fizzbuzz.mhc-ascii, fizzbuzz.mhc-bin
    python mhc_asm.py fizzbuzz.asm -o out/fizz     # -> out/fizz.mhc-ascii, out/fizz.mhc-bin
    python mhc_asm.py fizzbuzz.asm --listing       # also writes fizzbuzz.lst

SUPPORTED SOURCE FEATURES
    Sections     .text  .data        (default section is .text)
    Ignored      .globl / .global / .extern
    Data         .word  .half  .byte  .ascii  .asciiz  .space  .align
                 .word/.half auto-align to 4/2 bytes, .align n aligns to 2**n.
                 .word/.half/.byte values may be numbers, 'c' characters, or
                 labels (label, label+4, label-4).
    Labels       name:   (may be alone on a line or followed by code/data)
    Comments     # to end of line (not inside string/char literals)
    Numbers      decimal, 0x hex, negative, 'A' character literals
    Registers    $zero $at $v0-$v1 $a0-$a3 $t0-$t9 $s0-$s7 $k0-$k1 $gp $sp
                 $fp(=$s8) $ra, or plain numbers $0-$31
    Real instructions
      R-type     add addu sub subu and or xor nor slt sltu   rd, rs, rt
                 sll srl sra   rd, rt, shamt
                 mult multu div divu   rs, rt          mfhi mflo   rd
                 mul   rd, rs, rt      jr   rs         syscall
      I-type     addi addiu slti sltiu   rt, rs, imm   (signed 16-bit)
                 andi ori xori           rt, rs, imm   (unsigned 16-bit)
                 lui   rt, imm
                 lb lbu lh lw sb sh sw   rt, offset($base)
                 beq bne   rs, rt, label
      J-type     j jal   label
    Pseudoinstructions (expanded in pass 1; sizes are fixed)
      nop                  -> sll $zero,$zero,0
      move rd, rs          -> addu rd,$zero,rs
      li rt, const         -> addiu | ori | lui [+ ori]   (1-2 instructions)
      la rt, label         -> lui + ori                    (always 2)
      b label              -> beq $zero,$zero,label
      beqz/bnez rs, label  -> beq/bne rs,$zero,label
      blt/bgt/ble/bge rs, rt|imm, label
                           -> [li $at,imm] + slt $at,.. + bne/beq $at,$zero,label
      div rd, rs, rt|imm   -> [li $at,imm] + div rs,rt + mflo rd
      rem rd, rs, rt|imm   -> [li $at,imm] + div rs,rt + mfhi rd
    $at is reserved for the assembler's own use by these expansions.

MEMORY MAP (same as MARS/SPIM defaults)
    .text starts at 0x00400000 and .data starts at 0x10010000.
    Instructions are 4 bytes and word aligned. Entry point = label 'main'
    if defined, otherwise 0x00400000.

BYTE ORDER
    Everything is BIG-ENDIAN: the most significant byte of each 32-bit
    word comes first (instruction 0x20080003 is stored 20 08 00 03), and
    the header fields below are big-endian too. This matches Part 2.

FILE LAYOUT
  fizzbuzz.mhc-bin   (binary)
      offset  size  field
      0       4     magic "MHC1"
      4       4     entry address
      8       4     text base address
      12      4     text size in bytes (always a multiple of 4)
      16      4     data base address
      20      4     data size in bytes (real size, before padding)
      24      T     text section: machine-code words
      24+T    D'    data section, zero-padded up to a multiple of 4 bytes
    Because the header gives the size and base address of each section, a
    loader can always tell instructions from data.

  fizzbuzz.mhc-ascii (text; one 32-character word of '0'/'1' per line)
      .entry 0x00400000
      .text base=0x00400000 bytes=N
      <N/4 lines of 32 binary digits: instructions>
      .data base=0x10010000 bytes=M
      <ceil(M/4) lines of 32 binary digits: data, zero-padded to a word>
    Lines beginning with '.' are section markers; every other line is one
    big-endian 32-bit word. Section markers are what separate instructions
    from data.

ERRORS
    Problems are reported as  file:line: error: message  with the offending
    source line, e.g. unsupported instruction (with a suggestion), bad
    register, undefined label, out-of-range immediate or branch, duplicate
    label, wrong operand count. No output files are written if any error
    is found.
"""

import argparse
import difflib
import re
import struct
import sys
from pathlib import Path

TEXT_BASE = 0x00400000
DATA_BASE = 0x10010000
MAGIC = b"MHC1"
HEADER = struct.Struct(">4s5I")  # magic, entry, text_base, text_size, data_base, data_size

LABEL_RE = r"[A-Za-z_.$][\w.$]*"


class AsmError(Exception):
    """An assembly error; the caller attaches the line number."""


# --------------------------------------------------------------------------
# Instruction tables
# --------------------------------------------------------------------------
REG_NAMES = (
    "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 "
    "s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra"
).split()
REGS = {name: i for i, name in enumerate(REG_NAMES)}
REGS["s8"] = 30

R3 = {"add": 0x20, "addu": 0x21, "sub": 0x22, "subu": 0x23, "and": 0x24,
      "or": 0x25, "xor": 0x26, "nor": 0x27, "slt": 0x2A, "sltu": 0x2B}
SHIFT = {"sll": 0x00, "srl": 0x02, "sra": 0x03}
MULDIV = {"mult": 0x18, "multu": 0x19, "div": 0x1A, "divu": 0x1B}
I_SIGNED = {"addi": 0x08, "addiu": 0x09, "slti": 0x0A, "sltiu": 0x0B}
I_UNSIGNED = {"andi": 0x0C, "ori": 0x0D, "xori": 0x0E}
MEM = {"lb": 0x20, "lh": 0x21, "lw": 0x23, "lbu": 0x24,
       "sb": 0x28, "sh": 0x29, "sw": 0x2B}
BRANCH = {"beq": 0x04, "bne": 0x05}
JUMP = {"j": 0x02, "jal": 0x03}

REAL = (set(R3) | set(SHIFT) | set(MULDIV) | set(I_SIGNED) | set(I_UNSIGNED)
        | set(MEM) | set(BRANCH) | set(JUMP)
        | {"lui", "jr", "syscall", "mfhi", "mflo", "mul"})
PSEUDO = {"nop", "move", "li", "la", "b", "beqz", "bnez",
          "blt", "bgt", "ble", "bge", "div", "rem"}
DATA_DIRECTIVES = {".word", ".half", ".byte", ".ascii", ".asciiz", ".space", ".align"}
IGNORED_DIRECTIVES = {".globl", ".global", ".extern"}


# --------------------------------------------------------------------------
# Small parsing helpers
# --------------------------------------------------------------------------
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0",
           "\\": "\\", '"': '"', "'": "'"}


def unescape(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            i += 1
            if i >= len(body) or body[i] not in ESCAPES:
                bad = body[i] if i < len(body) else ""
                raise AsmError(f"unsupported escape sequence '\\{bad}'")
            c = ESCAPES[body[i]]
        out.append(c)
        i += 1
    return "".join(out)


def try_int(tok):
    """Return the integer value of a numeric literal, or None if it isn't one."""
    tok = tok.strip()
    if len(tok) >= 3 and tok[0] == "'" and tok[-1] == "'":
        s = unescape(tok[1:-1])
        if len(s) != 1:
            raise AsmError(f"bad character literal {tok}")
        return ord(s)
    for base in (0, 10):  # base 10 accepts leading zeros like "007"
        try:
            return int(tok, base)
        except ValueError:
            pass
    return None


def strip_comment(line):
    out, quote, i = [], None, 0
    while i < len(line):
        c = line[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 1
            elif c == quote:
                quote = None
        else:
            if c == "#":
                break
            if c in "\"'":
                quote = c
            out.append(c)
        i += 1
    return "".join(out)


def split_operands(s):
    """Split on commas that are not inside quotes."""
    parts, cur, quote, i = [], [], None, 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c == ",":
            parts.append("".join(cur).strip())
            cur = []
        else:
            if c in "\"'":
                quote = c
            cur.append(c)
        i += 1
    last = "".join(cur).strip()
    if last or parts:
        parts.append(last)
    if any(p == "" for p in parts):
        raise AsmError("empty operand (check for stray or doubled commas)")
    return parts


def parse_strings(rest):
    rest, out, i = rest.strip(), [], 0
    if not rest:
        raise AsmError("expected a quoted string")
    while i < len(rest):
        if rest[i] != '"':
            raise AsmError(f"expected a quoted string, got '{rest[i:]}'")
        j = i + 1
        while j < len(rest) and rest[j] != '"':
            j += 2 if rest[j] == "\\" else 1
        if j >= len(rest):
            raise AsmError("unterminated string literal")
        out.append(unescape(rest[i + 1:j]))
        i = j + 1
        while i < len(rest) and rest[i] in " \t,":
            i += 1
    return out


def need(ops, n, mn):
    if len(ops) != n:
        raise AsmError(f"'{mn}' expects {n} operand{'s' if n != 1 else ''}, got {len(ops)}")


def reg(tok):
    tok = tok.strip()
    if not tok.startswith("$"):
        raise AsmError(f"expected a register like $t0, got '{tok}'")
    name = tok[1:].lower()
    if name.isdigit() and int(name) < 32:
        return int(name)
    if name in REGS:
        return REGS[name]
    raise AsmError(f"unknown register '{tok}'")


def lookup(name, syms):
    if name not in syms:
        hint = difflib.get_close_matches(name, syms.keys(), 1)
        extra = f" (did you mean '{hint[0]}'?)" if hint else ""
        raise AsmError(f"undefined label '{name}'{extra}")
    return syms[name]


def value(expr, syms):
    """Evaluate a number, label, label+/-N, %hi(expr) or %lo(expr)."""
    expr = expr.strip()
    m = re.fullmatch(r"%(hi|lo)\((.+)\)", expr)
    if m:
        v = value(m.group(2), syms) & 0xFFFFFFFF
        return (v >> 16) & 0xFFFF if m.group(1) == "hi" else v & 0xFFFF
    n = try_int(expr)
    if n is not None:
        return n
    if expr.startswith("$"):
        raise AsmError(f"expected an immediate or label, got register '{expr}'")
    m = re.fullmatch(rf"({LABEL_RE})\s*([+-])\s*(\w+)", expr)
    if m:
        off = try_int(m.group(3))
        if off is None:
            raise AsmError(f"bad offset in '{expr}'")
        base = lookup(m.group(1), syms)
        return base + off if m.group(2) == "+" else base - off
    if re.fullmatch(LABEL_RE, expr):
        return lookup(expr, syms)
    raise AsmError(f"cannot understand operand '{expr}'")


def imm16(expr, syms, signed):
    v = value(expr, syms)
    lo, hi = (-32768, 32767) if signed else (0, 0xFFFF)
    if not lo <= v <= hi:
        raise AsmError(f"immediate {v} is out of range ({lo}..{hi})")
    return v & 0xFFFF


def mem_operand(tok, syms):
    m = re.fullmatch(r"(.*)\(\s*(\$\w+)\s*\)", tok.strip())
    if not m:
        raise AsmError(f"expected a memory operand like 4($sp), got '{tok}'")
    return imm16(m.group(1).strip() or "0", syms, True), reg(m.group(2))


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------
def rtype(rs, rt, rd, shamt, funct):
    return (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct


def itype(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def encode(mn, ops, addr, syms):
    """Encode one REAL instruction at address `addr` into a 32-bit word."""
    if mn in R3:
        need(ops, 3, mn)
        rd, rs, rt = (reg(o) for o in ops)
        return rtype(rs, rt, rd, 0, R3[mn])
    if mn in SHIFT:
        need(ops, 3, mn)
        rd, rt = reg(ops[0]), reg(ops[1])
        sh = value(ops[2], syms)
        if not 0 <= sh <= 31:
            raise AsmError(f"shift amount {sh} is out of range (0..31)")
        return rtype(0, rt, rd, sh, SHIFT[mn])
    if mn in MULDIV:
        need(ops, 2, mn)
        return rtype(reg(ops[0]), reg(ops[1]), 0, 0, MULDIV[mn])
    if mn in ("mfhi", "mflo"):
        need(ops, 1, mn)
        return rtype(0, 0, reg(ops[0]), 0, 0x10 if mn == "mfhi" else 0x12)
    if mn == "mul":
        need(ops, 3, mn)
        rd, rs, rt = (reg(o) for o in ops)
        return (0x1C << 26) | (rs << 21) | (rt << 16) | (rd << 11) | 0x02
    if mn == "jr":
        need(ops, 1, mn)
        return rtype(reg(ops[0]), 0, 0, 0, 0x08)
    if mn == "syscall":
        need(ops, 0, mn)
        return 0x0C
    if mn in I_SIGNED or mn in I_UNSIGNED:
        need(ops, 3, mn)
        rt, rs = reg(ops[0]), reg(ops[1])
        if mn in I_SIGNED:
            return itype(I_SIGNED[mn], rs, rt, imm16(ops[2], syms, True))
        return itype(I_UNSIGNED[mn], rs, rt, imm16(ops[2], syms, False))
    if mn == "lui":
        need(ops, 2, mn)
        return itype(0x0F, 0, reg(ops[0]), imm16(ops[1], syms, False))
    if mn in MEM:
        need(ops, 2, mn)
        rt = reg(ops[0])
        off, base = mem_operand(ops[1], syms)
        return itype(MEM[mn], base, rt, off)
    if mn in BRANCH:
        need(ops, 3, mn)
        rs, rt = reg(ops[0]), reg(ops[1])
        target = value(ops[2], syms)
        if target & 3:
            raise AsmError(f"branch target 0x{target:08X} is not word aligned")
        off = (target - (addr + 4)) >> 2
        if not -32768 <= off <= 32767:
            raise AsmError(f"branch target '{ops[2]}' is too far away ({off} instructions)")
        return itype(BRANCH[mn], rs, rt, off)
    if mn in JUMP:
        need(ops, 1, mn)
        target = value(ops[0], syms)
        if target & 3:
            raise AsmError(f"jump target 0x{target:08X} is not word aligned")
        if (target >> 28) != ((addr + 4) >> 28):
            raise AsmError(f"jump target '{ops[0]}' is outside the current 256 MB region")
        return (JUMP[mn] << 26) | ((target >> 2) & 0x3FFFFFF)
    raise AsmError(f"internal error: no encoder for '{mn}'")


# --------------------------------------------------------------------------
# Pseudoinstruction expansion (sizes must not depend on label addresses)
# --------------------------------------------------------------------------
def expand_li(rt, tok):
    v = try_int(tok)
    if v is None:
        raise AsmError(f"'li' needs a numeric constant, got '{tok}' (use 'la' for labels)")
    if not -(2 ** 31) <= v < 2 ** 32:
        raise AsmError(f"constant {v} does not fit in 32 bits")
    if v >= 2 ** 31:
        v -= 2 ** 32
    if -32768 <= v <= 32767:
        return [("addiu", [rt, "$zero", str(v)])]
    if 0 <= v <= 0xFFFF:
        return [("ori", [rt, "$zero", str(v)])]
    u = v & 0xFFFFFFFF
    out = [("lui", [rt, str(u >> 16)])]
    if u & 0xFFFF:
        out.append(("ori", [rt, rt, str(u & 0xFFFF)]))
    return out


def expand(mn, ops):
    if mn == "nop":
        need(ops, 0, mn)
        return [("sll", ["$zero", "$zero", "0"])]
    if mn == "move":
        need(ops, 2, mn)
        return [("addu", [ops[0], "$zero", ops[1]])]
    if mn == "li":
        need(ops, 2, mn)
        return expand_li(ops[0], ops[1])
    if mn == "la":
        need(ops, 2, mn)
        return [("lui", [ops[0], f"%hi({ops[1]})"]),
                ("ori", [ops[0], ops[0], f"%lo({ops[1]})"])]
    if mn == "b":
        need(ops, 1, mn)
        return [("beq", ["$zero", "$zero", ops[0]])]
    if mn in ("beqz", "bnez"):
        need(ops, 2, mn)
        return [(mn[:-1], [ops[0], "$zero", ops[1]])]
    if mn in ("blt", "bgt", "ble", "bge"):
        need(ops, 3, mn)
        rs, rhs, label = ops
        pre = []
        if not rhs.startswith("$"):
            pre = expand_li("$at", rhs)
            rhs = "$at"
        if mn == "blt":
            cmp_, br = ("slt", ["$at", rs, rhs]), "bne"
        elif mn == "bgt":
            cmp_, br = ("slt", ["$at", rhs, rs]), "bne"
        elif mn == "ble":
            cmp_, br = ("slt", ["$at", rhs, rs]), "beq"
        else:
            cmp_, br = ("slt", ["$at", rs, rhs]), "beq"
        return pre + [cmp_, (br, ["$at", "$zero", label])]
    if mn in ("div", "rem"):
        if mn == "div" and len(ops) == 2:
            return [("div", ops)]
        need(ops, 3, mn)
        rd, rs, rt = ops
        pre = []
        if not rt.startswith("$"):
            pre = expand_li("$at", rt)
            rt = "$at"
        return pre + [("div", [rs, rt]), ("mfhi" if mn == "rem" else "mflo", [rd])]
    if mn in REAL:  # real instruction: nothing to expand
        return [(mn, ops)]
    raise AsmError(f"internal error: cannot expand '{mn}'")


# --------------------------------------------------------------------------
# The assembler
# --------------------------------------------------------------------------
class Assembler:
    def __init__(self, source):
        self.lines = source.splitlines()
        self.syms = {}
        self.sym_line = {}
        self.items = []          # (addr, mnemonic, operands, line)
        self.text_addr = TEXT_BASE
        self.data = bytearray()
        self.fixups = []         # (offset, size, expr, line)
        self.pending = []        # data labels that may move if the next directive aligns
        self.section = "text"
        self.errors = []
        self.words = []
        self.cur_line = 0

    # ---- pass 1: sizes, addresses, labels ----
    def pass1(self):
        for ln, raw in enumerate(self.lines, 1):
            self.cur_line = ln
            try:
                self.parse_line(ln, raw)
            except AsmError as e:
                self.errors.append((ln, str(e)))

    def define(self, name, ln):
        if name in self.syms:
            raise AsmError(f"label '{name}' is already defined on line {self.sym_line[name]}")
        self.sym_line[name] = ln
        if self.section == "text":
            self.syms[name] = self.text_addr
        else:
            self.syms[name] = DATA_BASE + len(self.data)
            self.pending.append(name)

    def parse_line(self, ln, raw):
        rest = strip_comment(raw)
        while True:
            m = re.match(rf"\s*({LABEL_RE})\s*:(.*)$", rest)
            if not m:
                break
            self.define(m.group(1), ln)
            rest = m.group(2)
        rest = rest.strip()
        if not rest:
            return
        parts = rest.split(None, 1)
        head = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if head.startswith("."):
            self.directive(head, args)
            return
        if self.section != "text":
            raise AsmError(f"instruction '{head}' is not allowed in the .data section")
        if head not in REAL and head not in PSEUDO:
            hint = difflib.get_close_matches(head, sorted(REAL | PSEUDO), 1)
            extra = f" (did you mean '{hint[0]}'?)" if hint else ""
            raise AsmError(f"unsupported instruction '{head}'{extra}")
        for mn, ops in expand(head, split_operands(args) if args else []):
            self.items.append((self.text_addr, mn, ops, ln))
            self.text_addr += 4

    def align(self, n):
        while len(self.data) % n:
            self.data.append(0)
        for name in self.pending:
            self.syms[name] = DATA_BASE + len(self.data)

    def directive(self, name, args):
        if name in (".text", ".data"):
            if args.strip():
                raise AsmError(f"'{name}' with an address argument is not supported")
            self.section = name[1:]
            self.pending.clear()
            return
        if name in IGNORED_DIRECTIVES:
            return
        if name not in DATA_DIRECTIVES:
            hint = difflib.get_close_matches(name, sorted(DATA_DIRECTIVES), 1)
            extra = f" (did you mean '{hint[0]}'?)" if hint else ""
            raise AsmError(f"unsupported directive '{name}'{extra}")
        if self.section != "data":
            raise AsmError(f"'{name}' is only allowed in the .data section")

        if name == ".align":
            n = try_int(args)
            if n is None or not 0 <= n <= 4:
                raise AsmError(".align needs a number from 0 to 4")
            self.align(1 << n)
        elif name in (".ascii", ".asciiz"):
            for s in parse_strings(args):
                try:
                    b = s.encode("ascii")
                except UnicodeEncodeError:
                    raise AsmError("string contains non-ASCII characters")
                self.data += b + (b"\0" if name == ".asciiz" else b"")
        elif name == ".space":
            n = try_int(args)
            if n is None or n < 0:
                raise AsmError(".space needs a non-negative number of bytes")
            self.data += bytes(n)
        else:  # .word / .half / .byte
            size = {".word": 4, ".half": 2, ".byte": 1}[name]
            vals = split_operands(args) if args.strip() else []
            if not vals:
                raise AsmError(f"'{name}' needs at least one value")
            if size > 1:
                self.align(size)
            for v in vals:
                self.fixups.append((len(self.data), size, v, self.cur_line))
                self.data += bytes(size)
        self.pending.clear()

    # ---- pass 2: resolve labels and encode ----
    def pass2(self):
        for addr, mn, ops, ln in self.items:
            try:
                word = encode(mn, ops, addr, self.syms)
            except AsmError as e:
                self.errors.append((ln, str(e)))
                word = 0
            self.words.append(word)
        ranges = {4: (-(2 ** 31), 2 ** 32 - 1), 2: (-32768, 65535), 1: (-128, 255)}
        for off, size, expr, ln in self.fixups:
            try:
                v = value(expr, self.syms)
                lo, hi = ranges[size]
                if not lo <= v <= hi:
                    raise AsmError(f"value {v} does not fit in {size} byte(s)")
                self.data[off:off + size] = (v & ((1 << (8 * size)) - 1)).to_bytes(size, "big")
            except AsmError as e:
                self.errors.append((ln, str(e)))

    def assemble(self):
        self.pass1()
        self.pass2()
        self.errors.sort()
        return not self.errors

    # ---- results ----
    @property
    def text_bytes(self):
        return b"".join(struct.pack(">I", w) for w in self.words)

    @property
    def entry(self):
        return self.syms.get("main", TEXT_BASE)


# --------------------------------------------------------------------------
# Output writers
# --------------------------------------------------------------------------
def padded(b):
    return bytes(b) + bytes(-len(b) % 4)


def word_lines(b):
    b = padded(b)
    return [format(int.from_bytes(b[i:i + 4], "big"), "032b") for i in range(0, len(b), 4)]


def write_ascii(path, asm):
    text, data = asm.text_bytes, bytes(asm.data)
    lines = [f".entry 0x{asm.entry:08X}",
             f".text base=0x{TEXT_BASE:08X} bytes={len(text)}", *word_lines(text),
             f".data base=0x{DATA_BASE:08X} bytes={len(data)}", *word_lines(data)]
    Path(path).write_text("\n".join(lines) + "\n", encoding="ascii")


def write_bin(path, asm):
    text, data = asm.text_bytes, bytes(asm.data)
    header = HEADER.pack(MAGIC, asm.entry, TEXT_BASE, len(text), DATA_BASE, len(data))
    Path(path).write_bytes(header + text + padded(data))


def write_listing(path, asm):
    out = ["; address   word      instruction (after pseudo-expansion)   | source line"]
    for (addr, mn, ops, ln), w in zip(asm.items, asm.words):
        instr = f"{mn} {', '.join(ops)}".strip()
        out.append(f"0x{addr:08X}  {w:08X}  {instr:<36} | {asm.lines[ln - 1].strip()}")
    out.append("")
    out.append("; data section")
    data = padded(asm.data)
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        out.append(f"0x{DATA_BASE + i:08X}  " + " ".join(f"{b:02X}" for b in chunk))
    out.append("")
    out.append("; symbols")
    for name, a in sorted(asm.syms.items(), key=lambda kv: kv[1]):
        out.append(f"0x{a:08X}  {name}")
    Path(path).write_text("\n".join(out) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", help="MIPS assembly source file")
    ap.add_argument("-o", "--output", metavar="PREFIX",
                    help="output path without extension (default: next to the source)")
    ap.add_argument("--listing", action="store_true", help="also write PREFIX.lst")
    args = ap.parse_args(argv)

    src = Path(args.source)
    try:
        source = src.read_text(encoding="utf-8")
    except OSError as e:
        print(f"error: cannot read '{src}': {e.strerror}", file=sys.stderr)
        return 2

    asm = Assembler(source)
    if not asm.assemble():
        for ln, msg in asm.errors:
            print(f"{src}:{ln}: error: {msg}", file=sys.stderr)
            print(f"    {ln:4d} | {asm.lines[ln - 1].rstrip()}", file=sys.stderr)
        n = len(asm.errors)
        print(f"\n{n} error{'s' if n != 1 else ''}; no output written.", file=sys.stderr)
        return 1

    prefix = Path(args.output) if args.output else src.with_suffix("")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    write_ascii(f"{prefix}.mhc-ascii", asm)
    write_bin(f"{prefix}.mhc-bin", asm)
    if args.listing:
        write_listing(f"{prefix}.lst", asm)
    print(f"Assembled {len(asm.words)} instructions ({len(asm.words) * 4} bytes text) "
          f"and {len(asm.data)} bytes of data -> {prefix}.mhc-ascii, {prefix}.mhc-bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())