"""IR gọn cho bytecode Dalvik: block + lệnh đã tách thanh ghi/tham chiếu, move-result gắn vào lệnh gọi."""
from __future__ import annotations

import re

INVOKE = set(range(0x6E, 0x73)) | set(range(0x74, 0x79)) | {0xFA, 0xFB, 0xFC, 0xFD}
STATIC_LIKE = {0x70, 0x71, 0x76, 0x77, 0x6F, 0x75}   # direct/static/super: không dispatch ảo
MOVE_RESULT = {0x0A, 0x0B, 0x0C}
FILLED_NEW = {0x24, 0x25}


class Insn:
    __slots__ = ("off", "op", "regs", "ref", "lit", "res")

    def __init__(self, off, op, regs, ref, lit):
        self.off, self.op, self.regs, self.ref, self.lit = off, op, regs, ref, lit
        self.res = None          # thanh ghi nhận kết quả (move-result sau invoke / filled-new-array)

    def __repr__(self):
        return f"{self.off:04x} op={self.op:#x} r={self.regs} ref={self.ref} lit={self.lit} res={self.res}"


class Block:
    __slots__ = ("idx", "start", "insns", "succs", "handlers")

    def __init__(self, idx, start):
        self.idx, self.start, self.insns, self.succs, self.handlers = idx, start, [], [], []


class MethodIR:
    __slots__ = ("ma", "blocks", "nregs", "param_regs", "param_types", "is_static", "ret_type")


PARAM_RX = re.compile(r"\[*(?:L[^;]+;|[ZBSCIJFD])")


def split_desc(desc: str) -> tuple[list[str], str]:
    d = desc.replace(" ", "")
    i = d.index(")")
    return PARAM_RX.findall(d[1:i]), d[i + 1:]


def lift(ma) -> MethodIR | None:
    em = ma.get_method()
    code = em.get_code()
    if code is None:
        return None
    m = MethodIR()
    m.ma = ma
    m.nregs = code.get_registers_size()
    params, m.ret_type = split_desc(ma.descriptor)
    m.is_static = bool(em.get_access_flags() & 0x8)
    types = ([] if m.is_static else [ma.class_name]) + params
    r = m.nregs - code.get_ins_size()
    m.param_regs, m.param_types = [], types
    for t in types:
        m.param_regs.append(r)
        r += 2 if t in ("J", "D") else 1

    bbs = list(ma.get_basic_blocks().get())
    index = {id(bb): i for i, bb in enumerate(bbs)}
    by_start = {bb.get_start(): i for i, bb in enumerate(bbs)}
    blocks = []
    last = None          # move-result có thể nằm ở block sau lệnh invoke (invoke trong try)
    for i, bb in enumerate(bbs):
        b = Block(i, bb.get_start())
        off = bb.get_start()
        for ins in bb.get_instructions():
            op = ins.get_op_value()
            regs, ref, lit = [], None, None
            try:
                for o in ins.get_operands():
                    k = o[0]
                    kv = getattr(k, "value", k)
                    if kv == 0:                       # REGISTER
                        regs.append(o[1])
                    elif kv == 1:                     # LITERAL
                        lit = o[1]
                    elif kv == 3 and 0x32 <= op <= 0x3D:   # OFFSET của if-*: lưu đích nhảy tuyệt đối
                        lit = off + o[1] * 2
                    elif kv >= 0x100 and len(o) > 2:  # KIND + ...
                        ref = o[2]
            except Exception:
                pass
            if op in MOVE_RESULT and last is not None and (last.op in INVOKE or last.op in FILLED_NEW):
                last.res = regs[0] if regs else None
            it = Insn(off, op, regs, ref, lit)
            b.insns.append(it)
            last = it
            off += ins.get_length()
        for c in bb.childs:
            child = c[2] if len(c) > 2 else None
            j = index.get(id(child)) if child is not None else by_start.get(c[1])
            if j is not None and j not in b.succs:
                b.succs.append(j)
        ea = bb.exception_analysis
        if ea:
            for e in ea.exceptions:
                tgt = e[2] if len(e) > 2 and not isinstance(e[2], int) else None
                j = index.get(id(tgt)) if tgt is not None else by_start.get(e[1])
                if j is not None and j not in b.handlers:
                    b.handlers.append(j)
        blocks.append(b)
    m.blocks = blocks
    return m
