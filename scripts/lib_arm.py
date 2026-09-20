"""
lib_arm.py —— AArch64 (ARM64) 与 ARM32/Thumb 指令解码器（纯标准库）

优先级说明：这一版**首要保证分支/调用/返回指令的识别与目标计算正确**，
因为它们是 CFG 与函数识别的唯一依据。其余指令只要长度与分类不错，
助记符允许简化（未收录的按 opcode 形式输出）。

AArch64：定长 4 字节，小端。
Thumb-2：16/32 位混合长度，按 16 位前缀判断是否需要读第二个半字。

公开接口与 lib_x86 保持一致：
    decode_one(code, off, bits=64, vma_base=0) -> Insn
    disasm_linear(code, base_vma, bits=64, max_insns=...) -> list[Insn]
"""

from lib_x86 import (Insn, K_CALL, K_JMP, K_CJMP, K_RET, K_HLT, K_INT,
                     K_OTHER, K_INVALID)

COND = ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv")

# X/W 寄存器名。31 号在 load/store 与栈运算里是 sp，在数据处理里是 zr
def _r(idx: int, sf: int, use_sp: bool = False) -> str:
    if idx == 31:
        if use_sp:
            return "sp"
        return "xzr" if sf else "wzr"
    return f"x{idx}" if sf else f"w{idx}"


def _sx(v: int, bits: int) -> int:
    if v >= (1 << (bits - 1)):
        return v - (1 << bits)
    return v


# ---------------------------------------------------------------- AArch64

def _arm64_decode(code: bytes, off: int, vma: int) -> Insn:
    ins = Insn()
    ins.offset = off
    ins.vma = vma
    if off + 4 > len(code):
        ins.size = max(0, len(code) - off)
        ins.bytes = code[off:]
        ins.mnem = "<truncated>"
        ins.kind = K_INVALID
        return ins

    w = int.from_bytes(code[off:off + 4], "little")
    ins.size = 4
    ins.bytes = code[off:off + 4]
    ins.mnem = "inst_%08x" % w
    ins.kind = K_OTHER

    top = w >> 24

    # ---- 分支类（CFG 依据，务必准确） ----
    if (w & 0xFC000000) == 0x14000000:            # B  imm26
        imm = _sx(w & 0x03FFFFFF, 26) * 4
        ins.mnem = "b"
        ins.ops = hex(vma + imm)
        ins.kind = K_JMP
        ins.target = vma + imm
        return ins
    if (w & 0xFC000000) == 0x94000000:            # BL imm26
        imm = _sx(w & 0x03FFFFFF, 26) * 4
        ins.mnem = "bl"
        ins.ops = hex(vma + imm)
        ins.kind = K_CALL
        ins.target = vma + imm
        return ins
    if (w & 0xFF000010) == 0x54000000:            # B.cond imm19
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        cond = COND[w & 0xF]
        ins.mnem = "b." + cond
        ins.ops = hex(vma + imm)
        ins.kind = K_CJMP
        ins.target = vma + imm
        return ins
    if (w & 0x7E000000) == 0x34000000:            # CBZ / CBNZ
        sf = (w >> 30) & 1
        op = (w >> 24) & 1
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        rt = w & 0x1F
        ins.mnem = "cbnz" if op else "cbz"
        ins.ops = f"{_r(rt, sf)}, {hex(vma + imm)}"
        ins.kind = K_CJMP
        ins.target = vma + imm
        return ins
    if (w & 0x7E000000) == 0x36000000:            # TBZ / TBNZ
        op = (w >> 24) & 1
        imm = _sx((w >> 5) & 0x3FFF, 14) * 4
        rt = w & 0x1F
        bit = ((w >> 19) & 0x1F) | (((w >> 31) & 1) << 5)
        ins.mnem = "tbnz" if op else "tbz"
        ins.ops = f"x{rt}, #{bit}, {hex(vma + imm)}"
        ins.kind = K_CJMP
        ins.target = vma + imm
        return ins
    # BR/BLR/RET：掩码必须覆盖 bits[15:10]=000000 与 bits[4:0]=00000，
    # 只留 Rn(bits 9:5) 自由 —— 用 0xFFE00C1F 会漏匹配，已改 0xFFFFFC1F
    if (w & 0xFFFFFC1F) == 0xD61F0000:            # BR
        ins.mnem = "br"
        ins.ops = f"x{(w >> 5) & 0x1F}"
        ins.kind = K_JMP
        return ins
    if (w & 0xFFFFFC1F) == 0xD63F0000:            # BLR
        ins.mnem = "blr"
        ins.ops = f"x{(w >> 5) & 0x1F}"
        ins.kind = K_CALL
        return ins
    if (w & 0xFFFFFC1F) == 0xD65F0000:            # RET
        ins.mnem = "ret"
        ins.ops = f"x{(w >> 5) & 0x1F}"
        ins.kind = K_RET
        return ins
    if w == 0xD503201F:
        ins.mnem = "nop"
        return ins
    if (w & 0xFF000000) == 0xD4000000 and ((w >> 21) & 3) == 0:
        ins.mnem = "svc"
        ins.ops = "#%d" % ((w >> 5) & 0xFFFF)
        ins.kind = K_INT
        return ins
    if (w & 0xFFE0001F) == 0xD4200000:
        ins.mnem = "brk"
        ins.ops = "#%d" % ((w >> 5) & 0xFFFF)
        ins.kind = K_INT
        return ins

    # ---- ADR / ADRP ----
    if (w & 0x9F000000) == 0x10000000:            # ADR
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = _sx((immhi << 2) | immlo, 21)
        ins.mnem = "adr"
        ins.ops = f"x{rd}, {hex(vma + imm)}"
        return ins
    if (w & 0x9F000000) == 0x90000000:            # ADRP
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = _sx((immhi << 2) | immlo, 21) << 12
        page = (vma & ~0xFFF) + imm
        ins.mnem = "adrp"
        ins.ops = f"x{rd}, {hex(page)}"
        return ins

    # ---- ADD/SUB immediate ----
    if (w & 0x7F000000) in (0x11000000, 0x51000000, 0x31000000, 0x71000000):
        sf = (w >> 31) & 1
        op = (w >> 30) & 1          # 0=add 1=sub
        s_bit = (w >> 29) & 1       # 置标志位
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = (w >> 10) & 0xFFF
        sh = (w >> 22) & 3
        imm = imm12 << 12 if sh else imm12
        ins.mnem = ("sub" if op else "add") + ("s" if s_bit else "")
        # 【已修 bug】31 号寄存器到底是 sp 还是 zr，取决于**是否置标志位**：
        #   S=0（add/sub）  → 31 是 sp（栈运算）
        #   S=1（adds/subs）→ 31 是 zr（cmp/cmn 的别名形态）
        # 旧实现无条件当 sp，导致 cmp w0, #0 被渲染成 "subs sp, w0, #0"。
        use_sp = (s_bit == 0)
        ins.ops = f"{_r(rd, sf, use_sp)}, {_r(rn, sf, use_sp)}, #{imm}"
        if s_bit and rd == 31:      # CMP / CMN 别名
            ins.mnem = "cmp" if op else "cmn"
            ins.ops = f"{_r(rn, sf, False)}, #{imm}"
        return ins

    # ---- MOVZ / MOVK / MOVN（wide immediate） ----
    # 判别特征：bits[28:23] = 0b100101；opc 在 bits[30:29]
    #   opc=00 MOVN / opc=10 MOVZ / opc=11 MOVK
    if ((w >> 23) & 0x3F) == 0x25:
        sf = (w >> 31) & 1
        opc = (w >> 29) & 3
        hw = (w >> 21) & 3
        imm16 = (w >> 5) & 0xFFFF
        rd = w & 0x1F
        ins.mnem = {0: "movn", 2: "movz", 3: "movk"}.get(opc, "movw")
        ins.ops = f"{_r(rd, sf)}, #{imm16}, lsl #{hw * 16}"
        return ins

    # ---- Load/Store pair ----
    # 判别必须带上 bit25：A64 顶层编码里 bits[28:25]=0100 才是 load/store，
    # 只查 bits[29:27]=101 会把 orr/eor（bits[28:25]=0101）误吞进来
    if ((w >> 25) & 0x1F) == 0b10100:
        size = (w >> 30) & 3
        l = (w >> 22) & 1        # opc=01 → load, opc=10 → store
        rt2 = (w >> 10) & 0x1F
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        imm7 = _sx((w >> 15) & 0x7F, 7)
        scale = 8 if size == 2 else 4
        off = imm7 * scale
        ins.mnem = "ldp" if l else "stp"
        # 【已修 bug】旧实现把三种寻址模式一律渲染成 [rn+imm]，后变址
        # (post-index) 的语义被彻底表达错：ldp x29,x30,[sp],#16 是先取 sp
        # 再加 16，写成 [sp+0x10] 会让读者以为基址被改过。
        mode = (w >> 23) & 3        # 01=后变址 10=有符号偏移 11=前变址
        base = _r(rn, 1, True)
        regs = f"{_r(rt, size == 2)}, {_r(rt2, size == 2)}"
        if mode == 1:               # post-index: [xn], #imm
            ins.ops = f"{regs}, [{base}], #{imm7 * scale}"
        elif mode == 3:             # pre-index: [xn, #imm]!
            ins.ops = f"{regs}, [{base}, #{imm7 * scale}]!"
        else:                       # signed offset: [xn, #imm]
            sign = "+" if off >= 0 else "-"
            ins.ops = f"{regs}, [{base}{sign}{hex(abs(off))}]"
        return ins

    # ---- Load/Store register (unsigned imm)：bits[28:25] = 0b1100 ----
    if ((w >> 25) & 0xF) == 0b1100:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm12 = ((w >> 10) & 0xFFF) << size
        tbl = {(0, 0): "strb", (0, 1): "ldrb", (0, 2): "ldrsb",
               (1, 0): "strh", (1, 1): "ldrh", (1, 2): "ldrsh",
               (2, 0): "str", (2, 1): "ldr", (2, 2): "ldrsw",
               (3, 0): "str", (3, 1): "ldr", (3, 2): "prfm"}
        ins.mnem = tbl.get((size, opc), "ldst")
        off = "" if imm12 == 0 else f"+{hex(imm12)}"
        ins.ops = f"{_r(rt, size >= 2)}, [{_r(rn, 1, True)}{off}]"
        return ins

    # ---- 逻辑/算术 register ----
    if (w & 0x7F000000) == 0x0A000000 or (w & 0x7F000000) == 0x2A000000 or \
       (w & 0x7F000000) == 0x4A000000 or (w & 0x7F000000) == 0x6A000000:
        sf = (w >> 31) & 1
        opc = (w >> 29) & 3
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        m = {0: "and", 1: "orr", 2: "eor", 3: "ands"}[opc]
        ins.mnem = m
        ins.ops = f"{_r(rd, sf)}, {_r(rn, sf)}, {_r(rm, sf)}"
        # MOV 别名：ORR Xd, XZR, Xm（无移位）就是 MOV Xd, Xm。
        # 逆向里 mov 遍地都是，还原别名能显著降低阅读负担。
        # 注意：ORR 是逻辑运算，Rm=31 一律解释为 zr（不是 sp），
        # 所以 orr x0,xzr,xzr 是 mov x0, xzr 而不是 mov x0, sp。
        if opc == 1 and rn == 31 and ((w >> 22) & 3) == 0 and ((w >> 10) & 0x3F) == 0:
            ins.mnem = "mov"
            ins.ops = f"{_r(rd, sf)}, {_r(rm, sf)}"
        return ins

    # ---- ADD/SUB shifted register ----
    if (w & 0x7F000000) in (0x0B000000, 0x2B000000, 0x4B000000, 0x6B000000):
        sf = (w >> 31) & 1
        op = (w >> 30) & 1
        s_bit = (w >> 29) & 1
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        # 【已修 bug】旧实现硬编码 adds/subs，把 S 位忽略掉了：
        # 0x0B / 0x4B 组（S=0）本应是 add / sub，却一律渲染成 adds / subs。
        ins.mnem = ("sub" if op else "add") + ("s" if s_bit else "")
        ins.ops = f"{_r(rd, sf)}, {_r(rn, sf)}, {_r(rm, sf)}"
        if s_bit and rd == 31:      # CMP / CMN（寄存器版）
            ins.mnem = "cmp" if op else "cmn"
            ins.ops = f"{_r(rn, sf)}, {_r(rm, sf)}"
        return ins

    # ---- 系统指令兜底 ----
    if (w & 0xFFF00000) == 0xD5000000:
        ins.mnem = "sys"
        return ins

    return ins


# ---------------------------------------------------------------- Thumb (ARM32)

def _thumb_decode(code: bytes, off: int, vma: int) -> Insn:
    ins = Insn()
    ins.offset = off
    ins.vma = vma
    if off + 2 > len(code):
        ins.size = max(0, len(code) - off)
        ins.bytes = code[off:]
        ins.mnem = "<truncated>"
        ins.kind = K_INVALID
        return ins

    hw = int.from_bytes(code[off:off + 2], "little")
    ins.size = 2
    ins.bytes = code[off:off + 2]
    ins.mnem = "thumb_%04x" % hw
    ins.kind = K_OTHER

    top = hw >> 11

    # 32 位 Thumb-2 前缀：11101 / 11110 / 11111
    if top in (0x1D, 0x1E, 0x1F):
        if off + 4 <= len(code):
            h2 = int.from_bytes(code[off + 2:off + 4], "little")
            ins.size = 4
            ins.bytes = code[off:off + 4]
            _thumb32(ins, hw, h2, vma)
            return ins

    # 条件分支 B<cond> (1101 cond imm8)
    if (hw & 0xF000) == 0xD000:
        cond = (hw >> 8) & 0xF
        imm = _sx(hw & 0xFF, 8) * 2
        ins.mnem = "b" + COND[cond]
        ins.ops = hex(vma + 4 + imm)
        ins.kind = K_CJMP
        ins.target = vma + 4 + imm
        return ins
    # 无条件分支 B (11100 imm11)
    if (hw & 0xF800) == 0xE000:
        imm = _sx(hw & 0x7FF, 11) * 2
        ins.mnem = "b"
        ins.ops = hex(vma + 4 + imm)
        ins.kind = K_JMP
        ins.target = vma + 4 + imm
        return ins
    # BX / BLX register (010001110 ...)
    if (hw & 0xFF87) == 0x4700:
        rm = (hw >> 3) & 0xF
        link = (hw >> 7) & 1
        ins.mnem = "blx" if link else "bx"
        ins.ops = f"r{rm}"
        ins.kind = K_CALL if link else K_JMP
        return ins
    # PUSH / POP (0101 0 1 0 L register_list)
    if (hw & 0xFE00) == 0xB400:
        l = (hw >> 11) & 1
        ins.mnem = "pop" if l else "push"
        ins.ops = "{%s}" % ", ".join(f"r{i}" for i in range(8) if hw & (1 << i))
        return ins
    if hw == 0xBF00:
        ins.mnem = "nop"
        return ins
    if (hw & 0xFF00) == 0xDF00:
        ins.mnem = "svc"
        ins.ops = "#%d" % (hw & 0xFF)
        ins.kind = K_INT
        return ins
    return ins


def _thumb32(ins: Insn, hw: int, h2: int, vma: int) -> None:
    """32 位 Thumb-2：主要处理 BL/BLX imm 与分支。"""
    ins.mnem = "thumb32_%04x_%04x" % (hw, h2)
    ins.kind = K_OTHER
    # BL: 11110 S imm10 | 11 J1 1 J2 imm11
    if (hw & 0xF800) == 0xF000:
        s = (hw >> 10) & 1
        imm10 = hw & 0x3FF
        j1 = (h2 >> 13) & 1
        j2 = (h2 >> 11) & 1
        imm11 = h2 & 0x7FF
        if (h2 & 0xD000) == 0xD000:               # BL
            i1 = 1 - (j1 ^ s)
            i2 = 1 - (j2 ^ s)
            imm = _sx((s << 24) | (i1 << 23) | (i2 << 22) |
                      (imm10 << 12) | (imm11 << 1), 25)
            ins.mnem = "bl"
            ins.ops = hex(vma + 4 + imm)
            ins.kind = K_CALL
            ins.target = vma + 4 + imm
            return
        if (h2 & 0xD000) == 0xC000:               # BLX imm
            i1 = 1 - (j1 ^ s)
            i2 = 1 - (j2 ^ s)
            imm = _sx((s << 24) | (i1 << 23) | (i2 << 22) |
                      (imm10 << 12) | (imm11 << 2), 25)
            ins.mnem = "blx"
            ins.ops = hex((vma + 4 + imm) & ~1)
            ins.kind = K_CALL
            ins.target = (vma + 4 + imm) & ~1
            return
        if (h2 & 0xD000) == 0x8000:               # B.W (宽分支)
            i1 = 1 - (j1 ^ s)
            i2 = 1 - (j2 ^ s)
            imm = _sx((s << 24) | (i1 << 23) | (i2 << 22) |
                      (imm10 << 12) | (imm11 << 1), 25)
            ins.mnem = "b.w"
            ins.ops = hex(vma + 4 + imm)
            ins.kind = K_JMP
            ins.target = vma + 4 + imm
            return
    # 32 位 LDR/STR/数据处理等：保持 opcode 形式（分支已覆盖，够 CFG 用）
    return


# ---------------------------------------------------------------- 统一入口

def decode_one(code: bytes, off: int, bits: int = 64, vma_base: int = 0,
               code_start: int = 0, thumb: bool = False) -> Insn:
    """解码一条 ARM 指令。bits=64 → AArch64；否则按 Thumb/ARM32。"""
    vma = vma_base + off
    if bits == 64:
        return _arm64_decode(code, off, vma)
    return _thumb_decode(code, off, vma)


def disasm_linear(code: bytes, base_vma: int = 0, bits: int = 64,
                  max_insns: int = 200000, start: int = 0,
                  end: int | None = None) -> list[Insn]:
    out: list[Insn] = []
    if end is None:
        end = len(code)
    off = start
    step = 4 if bits == 64 else 2
    while off < end and len(out) < max_insns:
        # 末段不足一条指令长度时补齐判断，避免越界
        if bits == 64 and off + 4 > end:
            break
        if bits != 64 and off + 2 > end:
            break
        ins = decode_one(code, off, bits=bits, vma_base=base_vma)
        if ins.size <= 0:
            ins.size = step
        out.append(ins)
        off += ins.size
    return out
