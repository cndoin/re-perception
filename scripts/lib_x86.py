"""
lib_x86.py —— x86 / x86-64 指令解码器（纯标准库，零第三方依赖）

设计取舍（重要，读代码前先看这段）：
  1. 本解码器首要保证 **指令长度正确** 与 **控制流目标正确**。这两项是
     函数识别、CFG、XREF 的地基；助记符与操作数渲染允许不完美。
  2. 覆盖 Intel 64 位模式下编译器（MSVC/GCC/Clang）实际产出的绝大部分指令：
     通用整数指令、SSE/AVX(VEX/EVEX)、系统指令、特权指令。
  3. 遇到未收录或非法编码时返回 size>=1 的 invalid 指令，**绝不抛异常**，
     保证线性扫描永远能向前推进（不会死循环、不会卡死）。

单位约定（曾经踩过的坑，别再混）：
    opsize / addrsize / 寄存器 size 一律用 **位宽**（64/32/16/8）；
    只有渲染内存操作数时的 byte/word/dword/qword 前缀才换算成字节。

公开接口：
    decode_one(code, off, bits=64, vma_base=0) -> Insn
    disasm_linear(code, base_vma, bits=64, max_insns=...) -> list[Insn]
"""

# ---------------------------------------------------------------- 数据结构

K_OTHER = "other"
K_CALL = "call"
K_JMP = "jmp"
K_CJMP = "cjmp"
K_RET = "ret"
K_HLT = "hlt"        # hlt / ud2 —— 程序终止点
K_INT = "int"        # int3 / int1 / syscall
K_INVALID = "invalid"

# 解码 flag（位标志）
F_MODRM = 1 << 0
F_IMM8 = 1 << 1
F_IMMZ = 1 << 2      # 16/32 位立即数（随 operand-size）
F_IMM16 = 1 << 3
F_REL8 = 1 << 4
F_RELZ = 1 << 5
F_IMMV = 1 << 6      # B8+r: REX.W 时 imm64
F_MOFFS = 1 << 7     # A0-A3: moffs（随 address-size）
F_ENTER = 1 << 8
F_3AIMM = 1 << 9
F_IMM8_GRP = 1 << 10  # F6/F7：仅 reg<2 (test) 带立即数


class Insn:
    """一条解码后的指令。"""

    __slots__ = ("offset", "vma", "size", "bytes", "mnem", "ops",
                 "kind", "target", "prefixes", "imm", "disp", "mem_ref")

    def __init__(self):
        self.offset = 0
        self.vma = 0
        self.size = 0
        self.bytes = b""
        self.mnem = ""
        self.ops = ""
        self.kind = K_OTHER
        self.target = None
        self.prefixes = []
        self.imm = None      # 立即数（原始值，供字符串/常量交叉引用使用）
        self.disp = None     # 内存操作数位移（RIP 相对时是相对量）
        # 内存操作数**指向的地址**（间接调用/引用的地址）。
        # 例：call qword ptr [rip+0x27b3e] 的 target 是 None（运行时才知道），
        # 但它引用的 IAT 槽位是确定的 —— 记在这里，语义层据此还原 API 名。
        self.mem_ref = None

    # 会改变语义、必须在反汇编里看见的前缀（lock / rep / repne）。
    # 像 rex、opsize、vex 这类只是编码细节，不进显示。
    SHOW_PREFIXES = ("lock", "repne", "rep")

    @property
    def text(self) -> str:
        # 只在真正是"重复前缀"时才显示：SSE 里 F3/F2 是强制前缀，
        # 显示成 "rep movdqu" 会误导（解码时已把它们从 prefixes 里摘掉）。
        pre = ""
        for p in self.SHOW_PREFIXES:
            if p in self.prefixes:
                pre = p + " "
                break
        return f"{pre}{self.mnem} {self.ops}".strip()

    def to_dict(self) -> dict:
        return {
            "offset": self.offset, "vma": hex(self.vma), "size": self.size,
            "bytes": self.bytes.hex(), "mnem": self.mnem, "ops": self.ops,
            "kind": self.kind,
            "target": hex(self.target) if self.target is not None else None,
            "prefixes": self.prefixes,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Insn {self.vma:#x} sz={self.size} {self.text}>"


# ---------------------------------------------------------------- 寄存器表

REG64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
REG32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
         "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
REG16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
         "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w")
REG8_REX = ("al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
            "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b")
REG8_NOREX = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
SEGS = ("es", "cs", "ss", "ds", "fs", "gs")
CC = ("o", "no", "b", "ae", "e", "ne", "be", "a",
      "s", "ns", "p", "np", "l", "ge", "le", "g")

GRP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
GRP2 = ("rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar")
GRP3 = ("test", "test", "not", "neg", "mul", "imul", "div", "idiv")
GRP4 = ("inc", "dec", "?", "?", "?", "?", "?", "?")
GRP5 = ("inc", "dec", "call", "lcall", "jmp", "ljmp", "push", "?")
GRP6 = ("sldt", "str", "lldt", "ltr", "verr", "verw", "?", "?")
GRP7 = ("sgdt", "sidt", "lgdt", "lidt", "smsw", "?", "lmsw", "invlpg")
GRP8 = ("?", "?", "?", "?", "bt", "bts", "btr", "btc")
GRP9 = ("?", "cmpxchg8b", "?", "?", "?", "?", "rdrand", "rdseed")
GRP15 = ("fxsave", "fxrstor", "ldmxcsr", "stmxcsr", "?", "lfence",
         "mfence", "sfence")
GRP_PS_71 = {2: "psrlw", 4: "psraw", 6: "psllw"}
GRP_PS_72 = {2: "psrld", 4: "psrad", 6: "pslld"}
GRP_PS_73 = {2: "psrlq", 3: "psrldq", 6: "psllq", 7: "psldq"}

PTR = {8: "byte", 16: "word", 32: "dword", 64: "qword", 128: "xmmword",
       256: "ymmword", 512: "zmmword"}


def _reg(idx: int, size: int, rex: int) -> str:
    """按位宽取寄存器名。idx 已含 REX 扩展（0-15）。size 为位宽。"""
    if size == 64:
        return REG64[idx & 15]
    if size == 32:
        return REG32[idx & 15]
    if size == 16:
        return REG16[idx & 15]
    if rex:
        return REG8_REX[idx & 15]
    return REG8_NOREX[idx & 7]


def _vec(idx: int, size: int) -> str:
    """向量寄存器名：128 xmm / 256 ymm / 512 zmm。"""
    pfx = {128: "xmm", 256: "ymm", 512: "zmm"}.get(size, "xmm")
    return f"{pfx}{idx & 31}"


def _sx(v: int, bits: int) -> int:
    if v >= (1 << (bits - 1)):
        return v - (1 << bits)
    return v


# ---------------------------------------------------------------- 指令表
# 每项: (助记符, flags, 操作数模板)
# 模板记号: E=rm  G=reg  R=opcode低3位选寄存器  I=立即数  A=累加器
#           S=段寄存器  C=控制寄存器  D=调试寄存器  O=moffs  J=相对目标
#           M=内存      X=DX端口     1=常量1      cl=CL
# 宽度后缀(位宽): b=8 v=opsize z=16/32 w=16 d=32 q=64 x=向量

T1: dict[int, tuple] = {}
_ARITH = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
for _i, _n in enumerate(_ARITH):
    _b = _i * 8
    T1[_b + 0] = (_n, F_MODRM, "Eb,Gb")
    T1[_b + 1] = (_n, F_MODRM, "Ev,Gv")
    T1[_b + 2] = (_n, F_MODRM, "Gb,Eb")
    T1[_b + 3] = (_n, F_MODRM, "Gv,Ev")
    T1[_b + 4] = (_n, F_IMM8, "Ab,Ib")
    T1[_b + 5] = (_n, F_IMMZ, "Av,Iz")

for _i in range(8):
    T1[0x50 + _i] = ("push", 0, "Rv")
    T1[0x58 + _i] = ("pop", 0, "Rv")
    T1[0xB0 + _i] = ("mov", F_IMM8, "Rb,Ib")
    T1[0xB8 + _i] = ("mov", F_IMMV, "Rv,Iv")

for _i, _c in enumerate(CC):
    T1[0x70 + _i] = ("j" + _c, F_REL8, "Jb")

for _i in range(8):
    T1[0xD8 + _i] = ("x87_%d" % _i, F_MODRM, None)

# 串指令（A4-AF）：**没有** ModRM 也没有立即数。
# 【已修 bug】旧实现把它们和 in/out 写在同一个 tuple 里，用 `_o <= 0xE7`
# 判断是否带 imm8 —— 结果 0xA4-0xAF 全被套上 "Ab,Ib"：不仅凭空渲染出
# "movsb al, 0x0"，还会**多吃一个字节**，让后续指令流整体错位。
# rep movsb / rep stosq 是识别 memset/memcpy 的关键特征，必须先修对。
for _o, _n in ((0xA4, "movsb"), (0xA5, "movs"), (0xA6, "cmpsb"), (0xA7, "cmps"),
               (0xAA, "stosb"), (0xAB, "stos"), (0xAC, "lodsb"), (0xAD, "lods"),
               (0xAE, "scasb"), (0xAF, "scas")):
    T1[_o] = (_n, 0, None)
# in/out：只有端口立即数版本（E4-E7）带 imm8
for _o, _n in ((0xE4, "in"), (0xE5, "in"), (0xE6, "out"), (0xE7, "out")):
    T1[_o] = (_n, F_IMM8, "Ab,Ib")
for _o, _n in ((0xEC, "in"), (0xED, "in"), (0xEE, "out"), (0xEF, "out")):
    T1[_o] = (_n, 0, None)

# 串指令的"全宽"形式：位宽后缀由 operand-size 决定
STR_WIDE = {0xA5: "movs", 0xA7: "cmps", 0xAB: "stos", 0xAD: "lods", 0xAF: "scas"}
STR_SUFFIX = {16: "w", 32: "d", 64: "q"}

T1.update({
    0x63: ("movsxd", F_MODRM, "Gv,Ed"),
    0x68: ("push", F_IMMZ, "Iz"),
    0x69: ("imul", F_MODRM | F_IMMZ, "Gv,Ev,Iz"),
    0x6A: ("push", F_IMM8, "Ib"),
    0x6B: ("imul", F_MODRM | F_IMM8, "Gv,Ev,Ib"),
    0x80: (" Grp1", F_MODRM | F_IMM8, "Eb,Ib"),
    0x81: (" Grp1", F_MODRM | F_IMMZ, "Ev,Iz"),
    0x83: (" Grp1", F_MODRM | F_IMM8, "Ev,Ib"),
    0x84: ("test", F_MODRM, "Eb,Gb"),
    0x85: ("test", F_MODRM, "Ev,Gv"),
    0x86: ("xchg", F_MODRM, "Eb,Gb"),
    0x87: ("xchg", F_MODRM, "Ev,Gv"),
    0x88: ("mov", F_MODRM, "Eb,Gb"),
    0x89: ("mov", F_MODRM, "Ev,Gv"),
    0x8A: ("mov", F_MODRM, "Gb,Eb"),
    0x8B: ("mov", F_MODRM, "Gv,Ev"),
    0x8C: ("mov", F_MODRM, "Ev,Sw"),
    0x8D: ("lea", F_MODRM, "Gv,Ev"),
    0x8E: ("mov", F_MODRM, "Sw,Ew"),
    0x8F: ("pop", F_MODRM, "Ev"),
    0x90: ("nop", 0, None),
    0x91: ("xchg", 0, "Av,Rv"), 0x92: ("xchg", 0, "Av,Rv"),
    0x93: ("xchg", 0, "Av,Rv"), 0x94: ("xchg", 0, "Av,Rv"),
    0x95: ("xchg", 0, "Av,Rv"), 0x96: ("xchg", 0, "Av,Rv"),
    0x97: ("xchg", 0, "Av,Rv"),
    0x98: ("cwde", 0, None),
    0x99: ("cdq", 0, None),
    0x9C: ("pushf", 0, None),
    0x9D: ("popf", 0, None),
    0x9E: ("sahf", 0, None),
    0x9F: ("lahf", 0, None),
    0xA0: ("mov", F_MOFFS, "Ab,Ob"),
    0xA1: ("mov", F_MOFFS, "Av,Ov"),
    0xA2: ("mov", F_MOFFS, "Ob,Ab"),
    0xA3: ("mov", F_MOFFS, "Ov,Av"),
    0xA8: ("test", F_IMM8, "Ab,Ib"),
    0xA9: ("test", F_IMMZ, "Av,Iz"),
    0xC0: (" Grp2", F_MODRM | F_IMM8, "Eb,Ib"),
    0xC1: (" Grp2", F_MODRM | F_IMM8, "Ev,Ib"),
    0xC2: ("ret", F_IMM16, "Iw"),
    0xC3: ("ret", 0, None),
    0xC6: ("mov", F_MODRM | F_IMM8, "Eb,Ib"),
    0xC7: ("mov", F_MODRM | F_IMMZ, "Ev,Iz"),
    0xC8: ("enter", F_ENTER, "Iw,Ib"),
    0xC9: ("leave", 0, None),
    0xCA: ("retf", F_IMM16, "Iw"),
    0xCB: ("retf", 0, None),
    0xCC: ("int3", 0, None),
    0xCD: ("int", F_IMM8, "Ib"),
    0xCF: ("iret", 0, None),
    0xD0: (" Grp2", F_MODRM, "Eb,1"),
    0xD1: (" Grp2", F_MODRM, "Ev,1"),
    0xD2: (" Grp2", F_MODRM, "Eb,cl"),
    0xD3: (" Grp2", F_MODRM, "Ev,cl"),
    0xD7: ("xlat", 0, None),
    0xE0: ("loopne", F_REL8, "Jb"),
    0xE1: ("loope", F_REL8, "Jb"),
    0xE2: ("loop", F_REL8, "Jb"),
    0xE3: ("jrcxz", F_REL8, "Jb"),
    0xE8: ("call", F_RELZ, "Jz"),
    0xE9: ("jmp", F_RELZ, "Jz"),
    0xEB: ("jmp", F_REL8, "Jb"),
    0xF4: ("hlt", 0, None),
    0xF5: ("cmc", 0, None),
    0xF6: (" Grp3", F_MODRM | F_IMM8_GRP, "Eb"),
    0xF7: (" Grp3", F_MODRM | F_IMM8_GRP, "Ev"),
    0xF8: ("clc", 0, None), 0xF9: ("stc", 0, None),
    0xFA: ("cli", 0, None), 0xFB: ("sti", 0, None),
    0xFC: ("cld", 0, None), 0xFD: ("std", 0, None),
    0xFE: (" Grp4", F_MODRM, "Eb"),
    0xFF: (" Grp5", F_MODRM, "Ev"),
})

# ---------------------------------------------------------------- 0F 表

T2: dict[int, tuple] = {}
for _i, _c in enumerate(CC):
    T2[0x40 + _i] = ("cmov" + _c, F_MODRM, "Gv,Ev")
    T2[0x80 + _i] = ("j" + _c, F_RELZ, "Jz")
    T2[0x90 + _i] = ("set" + _c, F_MODRM, "Eb")

_T2_SSE = {
    0x10: "movups", 0x11: "movups", 0x12: "movlps", 0x13: "movlps",
    0x14: "unpcklps", 0x15: "unpckhps", 0x16: "movhps", 0x17: "movhps",
    0x28: "movaps", 0x29: "movaps", 0x2A: "cvtpi2ps", 0x2B: "movntps",
    0x2C: "cvttps2pi", 0x2D: "cvtps2pi", 0x2E: "ucomiss", 0x2F: "comiss",
    0x50: "movmskps", 0x51: "sqrtps", 0x52: "rsqrtps", 0x53: "rcpps",
    0x54: "andps", 0x55: "andnps", 0x56: "orps", 0x57: "xorps",
    0x58: "addps", 0x59: "mulps", 0x5A: "cvtps2pd", 0x5B: "cvtdq2ps",
    0x5C: "subps", 0x5D: "minps", 0x5E: "divps", 0x5F: "maxps",
    0x60: "punpcklbw", 0x61: "punpcklwd", 0x62: "punpckldq", 0x63: "packsswb",
    0x64: "pcmpgtb", 0x65: "pcmpgtw", 0x66: "pcmpgtd", 0x67: "packuswb",
    0x68: "punpckhbw", 0x69: "punpckhwd", 0x6A: "punpckhdq", 0x6B: "packssdw",
    0x6C: "punpcklqdq", 0x6D: "punpckhqdq", 0x6E: "movq", 0x6F: "movdqa",
    0x70: "pshufd", 0x74: "pcmpeqb", 0x75: "pcmpeqw", 0x76: "pcmpeqd",
    0x7C: "haddps", 0x7D: "hsubps", 0x7E: "movq", 0x7F: "movdqu",
    0xC2: "cmpps", 0xC4: "pinsrw", 0xC5: "pextrw", 0xC6: "shufps",
    0xD0: "addsubps", 0xD1: "psrlw", 0xD2: "psrld", 0xD3: "psrlq",
    0xD4: "paddq", 0xD5: "pmullw", 0xD6: "movq", 0xD7: "pmovmskb",
    0xD8: "psubusb", 0xD9: "psubusw", 0xDA: "pminub", 0xDB: "pand",
    0xDC: "paddusb", 0xDD: "paddusw", 0xDE: "pmaxub", 0xDF: "pandn",
    0xE0: "pavgb", 0xE1: "psraw", 0xE2: "psrad", 0xE3: "pavgw",
    0xE4: "pmulhuw", 0xE5: "pmulhw", 0xE6: "cvttpd2dq", 0xE7: "movntdq",
    0xE8: "psubsb", 0xE9: "psubsw", 0xEA: "pminsw", 0xEB: "por",
    0xEC: "paddsb", 0xED: "paddsw", 0xEE: "pmaxsw", 0xEF: "pxor",
    0xF1: "psllw", 0xF2: "pslld", 0xF3: "psllq", 0xF4: "pmuludq",
    0xF5: "pmaddwd", 0xF6: "psadbw", 0xF7: "maskmovq", 0xF8: "psubb",
    0xF9: "psubw", 0xFA: "psubd", 0xFB: "psubq", 0xFC: "paddb",
    0xFD: "paddw", 0xFE: "paddd", 0xFF: "ud0",
}
for _o, _n in _T2_SSE.items():
    T2[_o] = (_n, F_MODRM, "Gx,Ex")

# 带 imm8 的 SSE 指令：pshufd / cmpps / pinsrw / pextrw / shufps。
# 【已修 bug】旧表统一给成 "Gx,Ex"，漏掉 imm8 —— 既渲染不出 shuffle 掩码，
# 又少读一字节导致整条指令流错位（pshufd/cmpps 在向量化代码里极常见）。
for _o in (0x70, 0xC2, 0xC4, 0xC5, 0xC6):
    T2[_o] = (T2[_o][0], F_MODRM | F_IMM8, "Gx,Ex,Ib")

# 强制前缀改写表：同一 opcode 在 无前缀 / 66 / F3 / F2 下是四条不同指令。
# 索引即 pp：0=无, 1=66, 2=F3, 3=F2；None 表示沿用 T2 里的基础助记符。
# VEX/EVEX 的 pp 字段与传统前缀等价，共用这张表（vmovdqa / vmovdqu 分工靠它）。
T2_PP: dict[int, tuple[str | None, ...]] = {
    0x10: ("movups", "movupd", "movss", "movsd"),
    0x11: ("movups", "movupd", "movss", "movsd"),
    0x12: ("movlps", "movlpd", "movsldup", "movddup"),
    0x13: ("movlps", "movlpd", None, None),
    0x14: ("unpcklps", "unpcklpd", None, None),
    0x15: ("unpckhps", "unpckhpd", None, None),
    0x16: ("movhps", "movhpd", "movshdup", None),
    0x17: ("movhps", "movhpd", None, None),
    0x28: ("movaps", "movapd", None, None),
    0x29: ("movaps", "movapd", None, None),
    0x2A: ("cvtpi2ps", "cvtpi2pd", "cvtsi2ss", "cvtsi2sd"),
    0x2B: ("movntps", "movntpd", None, None),
    0x2C: ("cvtps2pi", "cvtpd2pi", "cvttss2si", "cvttsd2si"),
    0x2D: ("cvtps2pi", "cvtpd2pi", "cvtss2si", "cvtsd2si"),
    0x2E: ("ucomiss", "ucomisd", None, None),
    0x2F: ("comiss", "comisd", None, None),
    0x50: ("movmskps", "movmskpd", None, None),
    0xB8: ("popcnt", None, "popcnt", None),      # F3 0F B8 = POPCNT
    0xBC: ("bsf", None, "tzcnt", None),          # F3 0F BC = TZCNT
    0xBD: ("bsr", None, "lzcnt", None),          # F3 0F BD = LZCNT
    0x51: ("sqrtps", "sqrtpd", "sqrtss", "sqrtsd"),
    0x52: ("rsqrtps", None, "rsqrtss", None),
    0x53: ("rcpps", None, "rcpss", None),
    0x54: ("andps", "andpd", None, None),
    0x55: ("andnps", "andnpd", None, None),
    0x56: ("orps", "orpd", None, None),
    0x57: ("xorps", "xorpd", None, None),
    0x58: ("addps", "addpd", "addss", "addsd"),
    0x59: ("mulps", "mulpd", "mulss", "mulsd"),
    0x5A: ("cvtps2pd", "cvtpd2ps", "cvtss2sd", "cvtsd2ss"),
    0x5B: ("cvtdq2ps", "cvtps2dq", "cvttps2dq", None),
    0x5C: ("subps", "subpd", "subss", "subsd"),
    0x5D: ("minps", "minpd", "minss", "minsd"),
    0x5E: ("divps", "divpd", "divss", "divsd"),
    0x5F: ("maxps", "maxpd", "maxss", "maxsd"),
    0x6F: ("movq", "movdqa", "movdqu", None),
    0x70: ("pshufw", "pshufd", "pshufhw", "pshuflw"),
    0x7F: ("movq", "movdqa", "movdqu", None),
    0xC2: ("cmpps", "cmppd", "cmpss", "cmpsd"),
    0xC6: (None, "shufpd", "shufps", None),
    0xD0: (None, "addsubpd", None, "addsubps"),
    0xE0: ("pavgb", None, None, None),
    0xE1: ("psraw", None, None, None),
    0xE2: ("psrad", None, None, None),
    0xE3: ("pavgw", None, None, None),
    0xE4: ("pmulhuw", None, None, None),
    0xE5: ("pmulhw", None, None, None),
    0xE6: (None, "cvtpd2dq", "cvtdq2pd", "cvttpd2dq"),
    0xE7: ("movntq", "movntdq", None, None),
    0xEB: ("pmulhrsw", None, None, None),
}


def _pp_legacy(prefixes: list[str]) -> int:
    """从传统前缀列表还原 pp 字段：0=无, 1=66(opsize), 2=F3(rep), 3=F2(repne)。"""
    has66 = "opsize" in prefixes
    if "rep" in prefixes:
        return 2
    if "repne" in prefixes:
        return 3
    return 1 if has66 else 0

T2.update({
    0x00: ("Grp6", F_MODRM, None),
    0x01: ("Grp7", F_MODRM, None),
    0x02: ("lar", F_MODRM, "Gv,Ew"),
    0x03: ("lsl", F_MODRM, "Gv,Ew"),
    0x05: ("syscall", 0, None),
    0x06: ("clts", 0, None),
    0x07: ("sysret", 0, None),
    0x08: ("invd", 0, None),
    0x09: ("wbinvd", 0, None),
    0x0B: ("ud2", 0, None),
    0x0D: ("prefetch", F_MODRM, "Eb"),
    0x0E: ("femms", 0, None),
    0x1E: ("nop", F_MODRM, "Ev"),          # endbr64 = F3 0F 1E FA
    0x1F: ("nop", F_MODRM, "Ev"),
    0x20: ("mov", F_MODRM, "Cq,Gq"),
    0x21: ("mov", F_MODRM, "Dq,Gq"),
    0x22: ("mov", F_MODRM, "Gq,Cq"),
    0x23: ("mov", F_MODRM, "Gq,Dq"),
    0x30: ("wrmsr", 0, None), 0x31: ("rdtsc", 0, None),
    0x32: ("rdmsr", 0, None), 0x33: ("rdpmc", 0, None),
    0x34: ("sysenter", 0, None), 0x35: ("sysexit", 0, None),
    0x38: ("3byte38", F_MODRM, "Gx,Ex"),
    0x3A: ("3byte3A", F_MODRM | F_3AIMM, "Gx,Ex,Ib"),
    0x71: ("GrpPS71", F_MODRM | F_IMM8, "Ex,Ib"),
    0x72: ("GrpPS72", F_MODRM | F_IMM8, "Ex,Ib"),
    0x73: ("GrpPS73", F_MODRM | F_IMM8, "Ex,Ib"),
    0x77: ("emms", 0, None),
    0x78: ("vmread", F_MODRM, "Ev,Gv"),
    0x79: ("vmwrite", F_MODRM, "Gv,Ev"),
    0xA2: ("cpuid", 0, None),
    0xA3: ("bt", F_MODRM, "Ev,Gv"),
    0xA4: ("shld", F_MODRM | F_IMM8, "Ev,Gv,Ib"),
    0xA5: ("shld", F_MODRM, "Ev,Gv,cl"),
    0xAB: ("bts", F_MODRM, "Ev,Gv"),
    0xAC: ("shrd", F_MODRM | F_IMM8, "Ev,Gv,Ib"),
    0xAD: ("shrd", F_MODRM, "Ev,Gv,cl"),
    0xAE: ("Grp15", F_MODRM, "Ev"),
    0xAF: ("imul", F_MODRM, "Gv,Ev"),
    0xB0: ("cmpxchg", F_MODRM, "Eb,Gb"),
    0xB1: ("cmpxchg", F_MODRM, "Ev,Gv"),
    0xB2: ("lss", F_MODRM, "Gv,Mp"),
    0xB3: ("btr", F_MODRM, "Ev,Gv"),
    0xB4: ("lfs", F_MODRM, "Gv,Mp"),
    0xB5: ("lgs", F_MODRM, "Gv,Mp"),
    0xB6: ("movzx", F_MODRM, "Gv,Eb"),
    0xB7: ("movzx", F_MODRM, "Gv,Ew"),
    0xB8: ("popcnt", F_MODRM, "Gv,Ev"),
    0xB9: ("ud1", F_MODRM, None),
    0xBA: ("Grp8", F_MODRM | F_IMM8, "Ev,Ib"),
    0xBB: ("btc", F_MODRM, "Ev,Gv"),
    0xBC: ("bsf", F_MODRM, "Gv,Ev"),
    0xBD: ("bsr", F_MODRM, "Gv,Ev"),
    0xBE: ("movsx", F_MODRM, "Gv,Eb"),
    0xBF: ("movsx", F_MODRM, "Gv,Ew"),
    0xC0: ("xadd", F_MODRM, "Eb,Gb"),
    0xC1: ("xadd", F_MODRM, "Ev,Gv"),
    0xC3: ("movnti", F_MODRM, "Ev,Gv"),
    0xC7: ("Grp9", F_MODRM, "Ev"),
})
for _i in range(8):
    T2[0xC8 + _i] = ("bswap", 0, "Rv")
for _o in range(0x18, 0x20):
    T2.setdefault(_o, ("nop", F_MODRM, "Ev"))
for _o in range(0x00, 0x100):
    T2.setdefault(_o, ("op0f_%02x" % _o, F_MODRM, "Gx,Ex"))

# 0F 表中少数指令**没有** ModRM（兜底默认给了 F_MODRM，这里纠正，否则长度错）
# 0x04/0x0A/0x0C/0x0F 未定义，0x37=getsec，0xAA=rsm
for _o in (0x04, 0x0A, 0x0C, 0x0F, 0x37, 0xAA):
    T2[_o] = (T2[_o][0], 0, None)

# ---------------------------------------------------------------- VEX 0F38/0F3A
# 只列编译器/密码库里高频出现的，未收录的用 vgrp38_xx / vgrp3a_xx 兜底。
# 兜底不影响长度正确性（长度由 ModRM/imm 决定），只影响可读性。

T38: dict[int, str] = {
    0x00: "pshufb", 0x01: "phaddw", 0x02: "phaddd", 0x03: "phaddsw",
    0x04: "pmaddubsw", 0x05: "phsubw", 0x06: "phsubd", 0x07: "phsubsw",
    0x08: "psignb", 0x09: "psignw", 0x0A: "psignd", 0x0B: "pmulhrsw",
    0x0C: "vpermilps", 0x0D: "vpermilpd", 0x0E: "vtestps", 0x0F: "vtestpd",
    0x18: "vbroadcastss", 0x19: "vbroadcastsd", 0x1A: "vbroadcastf128",
    0x1C: "vpabsb", 0x1D: "vpabsw", 0x1E: "vpabsd",
    0x20: "vpmovsxbw", 0x21: "vpmovsxbd", 0x22: "vpmovsxbq",
    0x23: "vpmovsxwd", 0x24: "vpmovsxwq", 0x25: "vpmovsxdq",
    0x30: "vpmovzxbw", 0x31: "vpmovzxbd", 0x32: "vpmovzxbq",
    0x33: "vpmovzxwd", 0x34: "vpmovzxwq", 0x35: "vpmovzxdq",
    0x36: "vpermd", 0x37: "vpcmpgtq",
    0x38: "vpminsb", 0x39: "vpminsd", 0x3A: "vpminsuw", 0x3B: "vpminsud",
    0x3C: "vpmaxsb", 0x3D: "vpmaxsd", 0x3E: "vpmaxuw", 0x3F: "vpmaxud",
    0x40: "vpmulld", 0x41: "vphminposuw",
    0x98: "vfmadd132ps", 0x99: "vfmadd132ss", 0x9A: "vfmsub132ps",
    0x9B: "vfmsub132ss", 0x9C: "vfnmadd132ps", 0x9D: "vfnmadd132ss",
    0xA8: "vfmadd213ps", 0xA9: "vfmadd213ss",
    0xB8: "vfmadd231ps", 0xB9: "vfmadd231ss",
    0xDC: "vaesenc", 0xDD: "vaesenclast", 0xDE: "vaesdec",
    0xDF: "vaesdeclast",
    0xD5: "vpmullw", 0xF8: "vpsubb", 0xF9: "vpsubw", 0xFA: "vpsubd",
    0xFB: "vpsubq", 0xFC: "vpaddb", 0xFD: "vpaddw", 0xFE: "vpaddd",
}

T3A: dict[int, str] = {
    0x0C: "vblendps", 0x0D: "vblendpd", 0x0E: "vblendw", 0x0F: "vpalignr",
    0x14: "vpextrb", 0x15: "vpextrw", 0x16: "vpextrd", 0x17: "vextractps",
    0x20: "vpinsrb", 0x21: "vpinsrd", 0x22: "vpinsrq",
    0x4A: "vblendvps", 0x4B: "vblendvpd",
    0x61: "vpcmpestri", 0x62: "vpcmpestrm", 0x63: "vpcmpistri",
}

# ---------------------------------------------------------------- vvvv 属性
# VEX/EVEX 指令分两类：
#   VEX.NDS —— vvvv 是**第一个源操作数**（三操作数，如 vxorps xmm0,xmm1,xmm2）
#   VEX.NDD —— vvvv 未使用（两操作数，如 vmovaps xmm0,[rax]）
# 这两类无法从 vvvv 字段值区分（1111b 既是合法的 xmm0 也是"未使用"的编码），
# 必须查指令属性表。搞错会把两操作数指令渲染成三操作数，反之亦然。
#
# 0F 表：只列 NDS 的（保守白名单，未列出的按 NDD 处理）
VEX_NDS_0F = frozenset({
    0x51, 0x52, 0x53,                          # sqrtps/rsqrtps/rcpps
    0x54, 0x55, 0x56, 0x57,                    # and/andn/or/xor ps
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,        # punpck*/pack*/pcmpgt*
    0x70,                                      # pshufd
    0x74, 0x75, 0x76,                          # pcmpeq*
    0x7C, 0x7D,                                # haddps/hsubps
    0xC2, 0xC6,                                # cmpps/shufps
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,       # addsubps/psrl*/paddq/pmullw
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
})

# 0F38 / 0F3A 组默认都是 NDS，只有这些是 NDD（源来自内存/立即数）
VEX_NDD_38 = frozenset({
    0x18, 0x19, 0x1A,                          # vbroadcast*
    0x0E, 0x0F,                                # vtestps/vtestpd
    0x1C, 0x1D, 0x1E,                          # vpabsb/w/d
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25,        # vpmovsx*
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35,        # vpmovzx*
    0x41,                                      # vphminposuw
})
VEX_NDD_3A = frozenset({0x14, 0x15, 0x16, 0x17})   # vpextr*/vextractps


# 0F3A 组的操作数模板（默认 "Gx,Ex" 对这条组里的指令大多不适用：
# 目标可能是 GPR、源可能是立即数，必须逐条声明）
T3A_TMPL: dict[int, str] = {
    0x0C: "Gx,Ex,Ib", 0x0D: "Gx,Ex,Ib", 0x0E: "Gx,Ex,Ib", 0x0F: "Gx,Ex,Ib",
    # 注：目标/源的 GPR 一律按 32 位显示（与 objdump 一致：
    # vpextrb eax, xmm0, 0x0 而不是 al），可读性优先于手册的 r/m8 记法
    0x14: "Ev,Gx,Ib",      # vpextrb r32, xmm, imm8
    0x15: "Ev,Gx,Ib",      # vpextrw r32, xmm, imm8
    0x16: "Ev,Gx,Ib",      # vpextrd r32, xmm, imm8
    0x17: "Ev,Gx,Ib",      # vextractps r32, xmm, imm8
    0x20: "Gx,Ev,Ib",      # vpinsrb xmm, xmm, r32, imm8
    0x21: "Gx,Ev,Ib",      # vpinsrd
    0x22: "Gx,Ev,Ib",      # vpinsrq
    0x4A: "Gx,Ex,Ib", 0x4B: "Gx,Ex,Ib",
}

# 0F 表中"写内存"的指令：操作数顺序是 [mem], reg，与 Gx,Ex 相反
STORE_0F = frozenset({
    0x11,        # movups store
    0x13,        # movlps store
    0x17,        # movhps store
    0x29,        # movaps store
    0x2B,        # movntps store
    0x7F,        # movdqu/movdqa store
    0xD6,        # movq store
    0xE7,        # movntdq store
})


def _vex_has_vvvv(op: int, two_byte: bool, mm: int) -> bool:
    """该 VEX/EVEX 指令是否使用 vvvv 作为源操作数。"""
    if mm == 2:
        return op not in VEX_NDD_38
    if mm == 3:
        return op not in VEX_NDD_3A
    if two_byte:
        return op in VEX_NDS_0F
    return False

PREFIX_SEG = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es", 0x64: "fs", 0x65: "gs"}


# ---------------------------------------------------------------- 核心解码

def decode_one(code: bytes, off: int, bits: int = 64, vma_base: int = 0,
               code_start: int = 0) -> Insn:
    ins = Insn()
    start = off
    n = len(code)
    ins.offset = start + code_start
    ins.vma = vma_base + start

    if off >= n:
        ins.size = 0
        ins.mnem = "<eof>"
        ins.kind = K_INVALID
        return ins

    # ---------- 前缀 ----------
    # 段前缀（fs:/gs: 是读 PEB/TEB 的标志性模式，逆向里必须看得见）
    rex = 0
    opsize_ov = False
    addrsize_ov = False
    rep = None
    seg = None
    prefixes = []
    while off < n:
        b = code[off]
        if b in PREFIX_SEG:
            seg = PREFIX_SEG[b]; prefixes.append(seg); off += 1; continue
        if b == 0xF0:
            prefixes.append("lock"); off += 1; continue
        if b == 0xF3:
            rep = "rep"; prefixes.append("rep"); off += 1; continue
        if b == 0xF2:
            rep = "repne"; prefixes.append("repne"); off += 1; continue
        if b == 0x66:
            opsize_ov = True; prefixes.append("opsize"); off += 1; continue
        if b == 0x67:
            addrsize_ov = True; prefixes.append("addrsize"); off += 1; continue
        if bits == 64 and 0x40 <= b <= 0x4F:
            rex = b; prefixes.append("rex"); off += 1; continue
        break
    ins.prefixes = prefixes

    rex_w = bool(rex & 8)
    rex_r = bool(rex & 4)
    rex_x = bool(rex & 2)
    rex_b = bool(rex & 1)

    # ---------- VEX / EVEX ----------
    vex = None        # (mm, W, vvvv, L, pp)
    evex = False
    evex_z = 0        # EVEX.z：归并掩码归零
    evex_aaa = 0      # EVEX.aaa：操作掩码寄存器 k0-k7（0 = 无掩码）
    if bits == 64 and off < n:
        b0 = code[off]
        if b0 == 0xC5 and off + 1 < n:
            b1 = code[off + 1]
            vex = (1, 0, 15 - ((b1 >> 3) & 0xF), (b1 >> 2) & 1, b1 & 3)
            rex_r = not (b1 & 0x80)
            off += 2
            prefixes.append("vex")
        elif b0 == 0xC4 and off + 2 < n:
            b1, b2 = code[off + 1], code[off + 2]
            vex = (b1 & 0x1F, (b2 >> 7) & 1, 15 - ((b2 >> 3) & 0xF),
                   (b2 >> 2) & 1, b2 & 3)
            rex_r = not (b1 & 0x80); rex_x = not (b1 & 0x40); rex_b = not (b1 & 0x20)
            off += 3
            prefixes.append("vex")
        elif b0 == 0x62 and off + 3 < n:
            p0, p1, p2 = code[off + 1], code[off + 2], code[off + 3]
            vex = (p0 & 3, (p1 >> 7) & 1, 15 - ((p1 >> 3) & 0xF), (p2 >> 5) & 3, p1 & 3)
            rex_r = not (p0 & 0x80); rex_x = not (p0 & 0x40); rex_b = not (p0 & 0x20)
            evex_z = (p2 >> 7) & 1
            evex_aaa = p2 & 7
            evex = True
            off += 4
            prefixes.append("evex")

    if bits == 64:
        opsize = 64 if rex_w else (16 if opsize_ov else 32)
        addrsize = 32 if addrsize_ov else 64
    else:
        opsize = 16 if opsize_ov else 32
        addrsize = 16 if addrsize_ov else 32
    if vex is not None and vex[1]:
        opsize = 64
    # 向量宽度：EVEX 用 L'L(0=128,1=256,2=512)，VEX 用 L(0=128,1=256)
    if vex is not None:
        vecsize = ({0: 128, 1: 256, 2: 512}.get(vex[3], 128) if evex
                   else (256 if vex[3] else 128))
    else:
        vecsize = 128

    # ---------- opcode ----------
    # VEX/EVEX 的 mmmmm 字段本身就已经指明 opcode 映射表（1=0F, 2=0F38, 3=0F3A），
    # 因此 opcode 只应读一次。
    # 【已修 bug】旧实现先读一个 opcode、再在 mm==2/3 分支里又读一个，导致
    # 3 字节 VEX 指令多吃一字节：整条指令流从此错位，后续全部解成 (bad)。
    table = T1
    two_byte = False

    if vex is not None:
        mm = vex[0]
        if mm == 1:
            if off >= n:
                return _bad(ins, code, start, off)
            op = code[off]; off += 1
            two_byte = True
            table = T2
        elif mm == 2:
            if off >= n:
                return _bad(ins, code, start, off)
            op = code[off]; off += 1
            table = None
            mnem, flags, tmpl = T38.get(op, "vgrp38_%02x" % op), F_MODRM, "Gx,Ex"
        elif mm == 3:
            if off >= n:
                return _bad(ins, code, start, off)
            op = code[off]; off += 1
            table = None
            mnem, flags, tmpl = (T3A.get(op, "vgrp3a_%02x" % op),
                                 F_MODRM | F_3AIMM, T3A_TMPL.get(op, "Gx,Ex"))
        else:
            # mmmmm = 0 / 4..0x1F 是保留值
            return _bad(ins, code, start, off)
    else:
        if off >= n:
            return _bad(ins, code, start, off + 1)
        op = code[off]; off += 1
        if op == 0x0F:
            if off >= n:
                return _bad(ins, code, start, off)
            op = code[off]; off += 1
            two_byte = True
            table = T2

    if table is not None:
        ent = table.get(op)
        if ent is None:
            return _bad(ins, code, start, off)
        mnem, flags, tmpl = ent

    # 写内存的 SSE/AVX 指令：操作数顺序反转成 [mem], reg
    if two_byte and op in STORE_0F and tmpl == "Gx,Ex":
        tmpl = "Ex,Gx"

    # 0F 38 / 0F 3A 三字节转义
    if two_byte and op in (0x38, 0x3A):
        if off >= n:
            return _bad(ins, code, start, off)
        op3 = code[off]; off += 1
        if op == 0x38:
            mnem, flags, tmpl = "grp38_%02x" % op3, F_MODRM, "Gx,Ex"
        else:
            mnem, flags, tmpl = "grp3a_%02x" % op3, F_MODRM | F_3AIMM, "Gx,Ex"

    op_low3 = op & 7

    # ---------- ModRM / SIB ----------
    modrm = None
    mod = reg = rm = 0
    disp = 0
    has_mem = False
    mem_txt = ""
    # 内存操作数的基址/变址寄存器 —— 供后面算 mem_ref（内存操作数指向的地址）。
    # 必须在这里先声明：ModRM 分支不一定执行（无 ModRM 的指令）。
    base = index = None

    if flags & F_MODRM:
        if off >= n:
            return _bad(ins, code, start, off)
        modrm = code[off]; off += 1
        mod = (modrm >> 6) & 3
        reg = ((modrm >> 3) & 7) | (8 if rex_r else 0)
        rm = modrm & 7

        if mod != 3:
            has_mem = True
            base = index = None
            scale = 1
            if rm == 4:                                   # SIB
                if off >= n:
                    return _bad(ins, code, start, off)
                sib = code[off]; off += 1
                scale = 1 << ((sib >> 6) & 3)
                idx = ((sib >> 3) & 7) | (8 if rex_x else 0)
                bs = sib & 7
                if ((sib >> 3) & 7) != 4:
                    index = _reg(idx, addrsize, rex)
                if bs == 5 and mod == 0:
                    disp = _sx(int.from_bytes(_grab(code, off, 4), "little"), 32)
                    off += 4
                else:
                    base = _reg(bs | (8 if rex_b else 0), addrsize, rex)
            elif rm == 5 and mod == 0:
                disp = _sx(int.from_bytes(_grab(code, off, 4), "little"), 32)
                off += 4
                if bits == 64:
                    base = "rip"
            else:
                base = _reg(rm | (8 if rex_b else 0), addrsize, rex)

            if mod == 1:
                disp = _sx(_grab(code, off, 1)[0] if off < n else 0, 8)
                off += 1
            elif mod == 2:
                disp = _sx(int.from_bytes(_grab(code, off, 4), "little"), 32)
                off += 4

            # 组装内存表达式（纯寄存器部分）
            parts = []
            if base:
                parts.append(base)
            if index:
                parts.append(index + ("*%d" % scale if scale > 1 else ""))
            seg_txt = "+".join(parts)
            if disp > 0:
                seg_txt += ("+" if seg_txt or base == "rip" else "") + hex(disp)
            elif disp < 0:
                seg_txt += "-" + hex(-disp)
            elif mod in (1, 2) or (mod == 0 and rm == 5):
                seg_txt += ("+" if seg_txt else "") + "0x0"
            mem_txt = seg_txt

    # ---------- 立即数 / 相对偏移 ----------
    imm = rel = None
    if flags & F_IMM8:
        imm = code[off] if off < n else 0
        off += 1
    elif flags & F_IMM8_GRP:
        if modrm is not None and ((modrm >> 3) & 7) < 2:
            sz = 1 if op == 0xF6 else (2 if opsize == 16 else 4)
            imm = int.from_bytes(_grab(code, off, sz), "little")
            off += sz
    elif flags & F_IMM16:
        imm = int.from_bytes(_grab(code, off, 2), "little"); off += 2
    elif flags & F_IMMZ:
        sz = 2 if opsize == 16 else 4
        imm = int.from_bytes(_grab(code, off, sz), "little"); off += sz
    elif flags & F_IMMV:
        sz = 8 if (bits == 64 and rex_w) else (2 if opsize == 16 else 4)
        imm = int.from_bytes(_grab(code, off, sz), "little"); off += sz
    elif flags & F_REL8:
        rel = _sx(code[off] if off < n else 0, 8); off += 1
    elif flags & F_RELZ:
        sz = 2 if opsize == 16 else 4
        rel = _sx(int.from_bytes(_grab(code, off, sz), "little"), sz * 8); off += sz
    elif flags & F_MOFFS:
        sz = 8 if addrsize == 64 else (4 if addrsize == 32 else 2)
        imm = int.from_bytes(_grab(code, off, sz), "little"); off += sz
    elif flags & F_ENTER:
        imm = int.from_bytes(_grab(code, off, 2), "little"); off += 3

    if flags & F_3AIMM:
        # 0F3A 组结尾的 imm8（如 vpextrb 的索引）—— 存进 imm 供 "Ib" 渲染
        imm = code[off] if off < n else 0
        off += 1

    # 【已修 bug】缓冲区末尾的截断指令：前面 _grab() 越界补零会让 off 推过头，
    # 产出 size 大于实际剩余字节数的指令（后续按 size 切片就会越界）。这里夹紧。
    ins.size = max(1, min(off - start, n - start))
    ins.bytes = code[start:start + ins.size]
    ins.imm = imm
    ins.disp = disp if has_mem else None

    # 内存操作数**指向的地址**（静态可求时才算得出来）。
    # 这是还原 MSVC 导入调用的关键：call qword ptr [rip+0x27b3e] 的调用目标
    # 运行时才知道（target=None），但它引用的 IAT 槽位是编译期常量 —— 记在
    # mem_ref 里，语义层拿它去 iat_map 查 dll!FuncName。
    if has_mem:
        if bits == 64 and base == "rip":
            # RIP 相对寻址：基准是**下一条指令**的地址
            ins.mem_ref = (ins.vma + ins.size + disp) & ((1 << 64) - 1)
        elif base is None and index is None:
            # 绝对地址（mod=0 & rm=5 的 disp32，32 位模式下即绝对地址）
            ins.mem_ref = disp & ((1 << bits) - 1)

    # ---------- 助记符定型 ----------
    m = mnem
    rg = ((modrm >> 3) & 7) if modrm is not None else 0
    if m == " Grp1":
        m = GRP1[rg]
    elif m == " Grp2":
        m = GRP2[rg]
    elif m == " Grp3":
        m = GRP3[rg]
    elif m == " Grp4":
        m = GRP4[rg]
    elif m == " Grp5":
        m = GRP5[rg]
    elif m == "Grp6":
        m = GRP6[rg]
    elif m == "Grp7":
        m = GRP7[rg]
    elif m == "Grp8":
        m = GRP8[rg]
    elif m == "Grp9":
        m = GRP9[rg]
    elif m == "Grp15":
        m = GRP15[rg]
    elif m == "GrpPS71":
        m = GRP_PS_71.get(rg, "psop")
    elif m == "GrpPS72":
        m = GRP_PS_72.get(rg, "psop")
    elif m == "GrpPS73":
        m = GRP_PS_73.get(rg, "psop")

    if m == "cwde" and bits == 64 and not opsize_ov:
        m = "cdqe"
    if m == "cdq" and bits == 64 and not opsize_ov:
        m = "cqo"
    if m == "jrcxz" and addrsize == 32:
        m = "jecxz"
    # endbr64 / endbr32：F3 0F 1E FA / F3 0F 1E FB
    if op == 0x1E and two_byte and rep == "rep" and modrm in (0xFA, 0xFB):
        m = "endbr64" if modrm == 0xFA else "endbr32"
        tmpl = None
    # 串指令的位宽后缀：movs/stos/cmps/lods/scas 的"全宽"形式按 operand-size
    # 变 movsq/stosq/cmpsq/... （REX.W 时是 q，否则 d；16 位模式是 w）
    if not two_byte and vex is None and op in STR_WIDE:
        m = STR_WIDE[op] + STR_SUFFIX.get(opsize, "d")

    # 强制前缀（mandatory prefix）：66 / F3 / F2 会改变同一 opcode 的助记符。
    # 漏掉它 F3 0F 6F 会显示成 movdqa（实为 movdqu），SSE 代码整段看不懂。
    # VEX/EVEX 的 pp 字段与传统前缀等价，用同一张表。
    if two_byte and op in T2_PP:
        pp = vex[4] if vex is not None else _pp_legacy(prefixes)
        nm = T2_PP[op][pp]
        if nm:
            m = nm

    # 两字节 opcode 上的 F3/F2 是"强制前缀"而非重复前缀（popcnt/tzcnt/movdqu/…），
    # 摘掉以免渲染出莫名其妙的 "rep movdqu"。
    # 顺序要紧：必须在上面算完 pp **之后** 再摘，否则 pp 永远算成 0。
    if two_byte or vex is not None:
        if "rep" in prefixes or "repne" in prefixes:
            prefixes = [p for p in prefixes if p not in ("rep", "repne")]
            ins.prefixes = prefixes

    if vex is not None and not m.startswith("v"):
        m = "v" + m

    # x86-64 的 operand-size 特例：push/pop 与 near call/jmp 默认 64 位
    # （不能被 REX.W 影响，也不能被 0x66 之外的手段改成 32 位）
    if bits == 64 and not opsize_ov and m in ("push", "pop", "call", "jmp",
                                              "lcall", "ljmp"):
        opsize = 64

    # ---------- 操作数渲染 ----------
    ins.mnem = m
    vvvv = vex[2] if vex is not None else 0
    # EVEX 掩码：aaa != 0 时才有 {k1}..{k7}，z=1 时再补 {z}
    mask = None
    if evex and evex_aaa:
        mask = "{k%d}" % evex_aaa + ("{z}" if evex_z else "")
    use_vvvv = vex is not None and _vex_has_vvvv(op, two_byte, vex[0])
    ins.ops = _render(m, tmpl, opsize, addrsize, rex, rex_b, rex_r, modrm, mod,
                      reg, has_mem, mem_txt, imm, rel, ins, op_low3, vecsize,
                      bits, vvvv=vvvv if use_vvvv else None, mask=mask, seg=seg)
    if ins.mnem == "(bad)":
        ins.kind = K_INVALID
        return ins

    _classify(ins, m, rel, modrm, bits)
    return ins


def _grab(code: bytes, off: int, sz: int) -> bytes:
    """安全取 sz 字节，越界补零（保证解码永不崩溃）。"""
    if off < 0:
        return b"\x00" * sz
    end = off + sz
    if end > len(code):
        return code[off:] + b"\x00" * (end - len(code))
    return code[off:end]


def _bad(ins: Insn, code: bytes, start: int, off: int) -> Insn:
    ins.size = max(1, min(off - start, len(code) - start)) if start < len(code) else 1
    ins.bytes = code[start:start + ins.size]
    ins.mnem = "(bad)"
    ins.kind = K_INVALID
    return ins


def _render(m, tmpl, opsize, addrsize, rex, rex_b, rex_r, modrm, mod, reg,
            has_mem, mem_txt, imm, rel, ins, op_low3, vecsize, bits,
            vvvv: int | None = None, mask: str | None = None,
            seg: str | None = None) -> str:
    """
    渲染 Intel 风格操作数。出错返回空串，不抛异常。

    vvvv: VEX/EVEX 的 vvvv 字段（已取反，0 表示该字段未使用）。
          Intel 语法里它是**第一个源操作数**，插在 dst 与 rm 之间。
    mask: EVEX 操作掩码后缀，如 "{k1}{z}"，附加到目标操作数上。
    """
    if not tmpl:
        return ""

    # VEX/EVEX 的三操作数形态：Gx,Ex -> Gx,Hx,Ex（H = vvvv 指定的源寄存器）。
    # 由调用方按指令属性决定是否传 vvvv（传 None 表示这条指令不用 vvvv 字段）。
    if vvvv is not None:
        parts = [p.strip() for p in tmpl.split(",")]
        if len(parts) == 2 and parts[0].startswith("G") and parts[1].startswith("E"):
            tmpl = "%s,H%s,%s" % (parts[0], parts[1][1:], parts[1])

    def rm_str(sz: int, is_vec: bool = False) -> str:
        if modrm is None:
            return "?"
        if has_mem:
            # lea 取的是地址本身，不是内存内容 —— 不加 size 前缀
            ptr = "" if m == "lea" else PTR.get(sz, "")
            body = mem_txt if mem_txt else "0x0"
            sp = f"{seg}:" if seg else ""
            return f"{ptr} ptr {sp}[{body}]" if ptr else f"{sp}[{body}]"
        if is_vec:
            return _vec((modrm & 7) | (8 if rex_b else 0), vecsize)
        return _reg((modrm & 7) | (8 if rex_b else 0), sz, rex)

    def opreg_str(sz: int) -> str:
        return _reg(op_low3 | (8 if rex_b else 0), sz, rex)

    out = []
    for tok in tmpl.split(","):
        tok = tok.strip()
        if not tok:
            continue
        body, suf = tok[:-1], tok[-1]
        if suf == "b":
            sz = 8
        elif suf == "v":
            sz = opsize
        elif suf == "z":
            sz = 16 if opsize == 16 else 32
        elif suf == "w":
            sz = 16
        elif suf == "d":
            sz = 32
        elif suf == "q":
            sz = 64
        elif suf == "x":
            sz = vecsize
        elif suf == "p":
            sz = 64
        else:
            sz = opsize

        if body == "E":
            out.append(rm_str(sz, is_vec=(suf == "x")))
        elif body == "G":
            out.append(_vec(reg, vecsize) if suf == "x" else _reg(reg, sz, rex))
        elif body == "H":
            # VEX vvvv 源操作数。VEX 隐含 REX 语义，8 位寄存器按 REX 命名。
            r8 = rex if rex else 1
            v = vvvv or 0
            out.append(_vec(v, vecsize) if suf == "x" else _reg(v, sz, r8))
        elif body == "R":
            out.append(opreg_str(sz))
        elif body == "A":
            out.append(_reg(0, sz, rex))
        elif body == "C":
            out.append("cr%d" % reg)
        elif body == "D":
            out.append("dr%d" % reg)
        elif body == "S":
            out.append(SEGS[reg & 7] if (reg & 7) < 6 else "segr")
        elif body == "O":
            out.append(f"[{hex(imm) if imm is not None else '?'}]")
        elif body == "I":
            out.append(hex(imm) if imm is not None else "?")
        elif body == "J":
            if rel is None:
                out.append("?")
            else:
                out.append(hex(ins.vma + ins.size + rel))
        elif body == "M":
            ptr = PTR.get(sz, "")
            out.append(f"{ptr} ptr [{mem_txt}]" if ptr else f"[{mem_txt}]")
        elif body == "X":
            out.append("dx")
        elif body in ("1", "cl"):
            out.append(body)
        else:
            out.append(tok)

    if mask and out:
        out[0] = out[0] + mask      # EVEX 掩码修饰目标寄存器
    return ", ".join(out)


def _classify(ins: Insn, m: str, rel, modrm, bits: int) -> None:
    if rel is not None:
        ins.target = ins.vma + ins.size + rel
        if m == "call":
            ins.kind = K_CALL
        elif m == "jmp":
            ins.kind = K_JMP
        elif m.startswith("j") or m.startswith("loop"):
            ins.kind = K_CJMP
        else:
            ins.kind = K_OTHER
        return
    if m in ("ret", "retf", "iret"):
        ins.kind = K_RET
        return
    if m in ("hlt", "ud2"):
        ins.kind = K_HLT
        return
    if m.startswith("int") or m in ("syscall", "sysenter", "sysret", "sysretq"):
        ins.kind = K_INT
        return
    if modrm is not None:
        rg = (modrm >> 3) & 7
        if m == "call" and rg in (2, 3):
            ins.kind = K_CALL
            return
        if m == "jmp" and rg in (4, 5):
            ins.kind = K_JMP
            return
    ins.kind = K_OTHER


# ---------------------------------------------------------------- 线性扫描

def disasm_linear(code: bytes, base_vma: int = 0, bits: int = 64,
                  max_insns: int = 200000, start: int = 0,
                  end: int | None = None) -> list[Insn]:
    """线性反汇编。非法指令按 1 字节推进，绝不卡死。"""
    out: list[Insn] = []
    if end is None:
        end = len(code)
    off = start
    guard = 0
    limit = max_insns * 4
    while off < end and len(out) < max_insns:
        ins = decode_one(code, off, bits=bits, vma_base=base_vma, code_start=0)
        if ins.size <= 0:
            break
        out.append(ins)
        off += ins.size
        guard += 1
        if guard > limit:
            break
    return out
