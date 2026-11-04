"""Engine luồng giá trị (value-flow) cho bytecode Dalvik.

Mỗi thanh ghi mang một giá trị trừu tượng  Val = (consts, taint, allocs):
  consts : tập hằng khả dĩ (str/int, ("C", class), ("M", class, method)); {TOP} = quá nhiều
  taint  : nhãn nguồn — int = id nguồn cụ thể, ("p", i) = "đến từ tham số i" (để tóm tắt method)
  allocs : nơi cấp phát object -> heap[alloc] = taint của nội dung object (alias trong method)

  * trong method: dataflow theo CFG, gập hằng số nguyên + bỏ nhánh chết khi điều kiện là hằng
  * giữa các method: tóm tắt (summary): tham số i -> return / sink / field / object tham số k
  * field: theo field (field-based, quy về class khai báo), dùng chung toàn chương trình
  * gọi ảo/interface: CHA; reflection (Method.invoke) giải bằng hằng số; AsyncTask.execute -> doInBackground
  * API framework: "taint wrapper" — kết quả mang taint của mọi đối số; method thay đổi object
    (append/put/add/write/set*...) làm bẩn object nhận; mảng truyền vào bị ghi (getChars, read...)
  * exception: taint của giá trị bị throw đi tới move-exception trong cùng method
Lặp toàn chương trình tới khi summary + field ổn định.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .ir import FILLED_NEW, INVOKE, MOVE_RESULT, MethodIR, lift, split_desc

TOP = ("⊤",)
E = frozenset()
EMPTY = (E, E, E)
MAX_CONSTS = 8
MAX_CHAIN = 8
MAX_REFS = 16
THROWN = ("thrown",)

CLEAN = re.compile(r"^(?:length|size|isEmpty|equals\w*|hashCode|compareTo\w*|contains\w*|startsWith|endsWith|"
                   r"indexOf|lastIndexOf|getClass|matches|hasNext|isNull|has|containsKey|exists|isDirectory|canRead|"
                   r"findViewById|getSystemService|getApplicationContext|getContext|getResources)$")
MUTATOR = re.compile(r"^(?:<init>|append|put\w*|add\w*|set\w*|write\w*|insert|offer\w*|push|print\w*|update|"
                     r"load\w*|replace\w*|send|obtain\w*|format|init)$")
STRB = ("Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;")
# object bọc object khác và ghi/đọc xuyên qua nó
WRAPPER = re.compile(r"^L(?:java/io/|java/util/Formatter;|java/util/zip/|java/util/Scanner;|"
                     r"javax/crypto/Cipher(?:In|Out)putStream;|java/nio/channels/)")
M32 = 0xFFFFFFFF


TOPSET = frozenset((TOP,))
MAY = ("~",)          # "còn có thể là giá trị khác": giữ ứng viên cho reflection, nhưng không dùng để bỏ nhánh


def jc(a: frozenset, b: frozenset) -> frozenset:
    """Gộp tập hằng (may-set). E = không rõ: gộp với hằng -> giữ ứng viên + MAY."""
    if a == b:
        return a
    if not a:
        a = frozenset((MAY,))
    if not b:
        b = frozenset((MAY,))
    if TOP in a or TOP in b:
        return TOPSET
    u = a | b
    return u if len(u) <= MAX_CONSTS + 1 else TOPSET


def join(a, b):
    if a is b:
        return a
    return (jc(a[0], b[0]), a[1] | b[1], a[2] | b[2])


def single(c: frozenset):
    """Giá trị hằng CHẮC CHẮN (dùng để bỏ nhánh / gọi hàm giải mã)."""
    if len(c) == 1:
        v = next(iter(c))
        if v is not TOP and v is not MAY and v != MAY:
            return v
    return None


def s32(x: int) -> int:
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def arith(kind: int, a: int, b: int):
    try:
        if kind == 0: return s32(a + b)
        if kind == 1: return s32(a - b)
        if kind == 2: return s32(a * b)
        if kind == 3: return s32(int(a / b)) if b else None
        if kind == 4: return s32(a - b * int(a / b)) if b else None
        if kind == 5: return s32(a & b)
        if kind == 6: return s32(a | b)
        if kind == 7: return s32(a ^ b)
        if kind == 8: return s32(a << (b & 31))
        if kind == 9: return s32(a >> (b & 31))
        if kind == 10: return s32((a & M32) >> (b & 31))
    except Exception:
        return None
    return None


LIT16 = [0, "r", 2, 3, 4, 5, 6, 7]            # 0xD0..0xD7: add rsub mul div rem and or xor
LIT8 = [0, "r", 2, 3, 4, 5, 6, 7, 8, 9, 10]   # 0xD8..0xE2


class Summary:
    __slots__ = ("p2ret", "ret_src", "ret_consts", "p2sink", "p2field", "p2p", "src2p", "crypto")

    def __init__(self):
        self.crypto: set = set()     # (site_ma, off, objK, argK, objP, argP): doFinal phụ thuộc tham số
        self.p2ret, self.ret_src, self.ret_consts = set(), set(), E
        self.p2sink: dict[int, set] = defaultdict(set)
        self.p2field: dict[int, set] = defaultdict(set)
        self.p2p: set = set()
        self.src2p: dict[int, set] = defaultdict(set)

    def key(self):
        return (frozenset(self.p2ret), frozenset(self.ret_src), self.ret_consts,
                frozenset((k, frozenset(v)) for k, v in self.p2sink.items()),
                frozenset((k, frozenset(v)) for k, v in self.p2field.items()),
                frozenset(self.p2p), frozenset((k, frozenset(v)) for k, v in self.src2p.items()),
                frozenset(self.crypto))


class SourceSite:
    __slots__ = ("id", "ma", "off", "sig", "kind")

    def __init__(self, id_, ma, off, sig, kind):
        self.id, self.ma, self.off, self.sig, self.kind = id_, ma, off, sig, kind


class Flow:
    __slots__ = ("src", "sink_ma", "sink_off", "sink_sig", "chain")

    def __init__(self, src, sink_ma, sink_off, sink_sig, chain):
        self.src, self.sink_ma, self.sink_off, self.sink_sig, self.chain = src, sink_ma, sink_off, sink_sig, chain


class Spec:
    """Nguồn/đích cần theo dõi. source item: ('api'|'cb'|'field', regex); sink item: regex trên chữ ký API."""

    def __init__(self, sources: list[tuple[str, re.Pattern]], sinks: list[re.Pattern]):
        self.api_src = [p for k, p in sources if k == "api"]
        self.cb_src = [p for k, p in sources if k == "cb"]
        self.field_src = [p for k, p in sources if k == "field"]
        self.sinks = sinks
        self._c: dict = {}

    def _m(self, kind, pats, s):
        k = (kind, s)
        r = self._c.get(k)
        if r is None:
            r = self._c[k] = any(p.search(s) for p in pats)
        return r

    def is_src(self, sig):
        return bool(self.api_src) and self._m("a", self.api_src, sig)

    def is_sink(self, sig):
        return bool(self.sinks) and self._m("s", self.sinks, sig)

    def is_field_src(self, f):
        return bool(self.field_src) and self._m("f", self.field_src, f)

    def cb_match(self, sigs: list[str]) -> str | None:
        for s in sigs:
            if self.cb_src and self._m("c", self.cb_src, s):
                return s
        return None


class Ctx:
    __slots__ = ("ma", "S", "heap", "ret", "fw_t", "fw_c", "this_cls")

    def __init__(self, ma, S, heap, fw_t, fw_c, this_cls):
        self.ma, self.S, self.heap, self.fw_t, self.fw_c, self.this_cls = ma, S, heap, fw_t, fw_c, this_cls
        self.ret = None


class FlowEngine:
    def __init__(self, dx, cha, spec: Spec, is_lib, include_libs=False, decrypted: dict | None = None,
                 res_string=None, max_rounds: int = 8, max_insns: int = 20000, inv: dict | None = None,
                 interesting=None, budget: float = 180.0, fields: tuple | None = None):
        self.dx, self.cha, self.spec = dx, cha, spec
        self.is_lib, self.include_libs = is_lib, include_libs
        self.decrypted = decrypted or {}
        self.dec_sigs = {k[0] for k in self.decrypted}
        self.res_string = res_string
        self.max_rounds, self.max_insns = max_rounds, max_insns
        self.summ: dict = {}
        self.sources: list[SourceSite] = []
        self._src_idx: dict = {}
        self.flows: dict = {}
        self.f_taint: dict[str, frozenset] = {}
        self.f_consts: dict[str, frozenset] = {}
        self.reflect: dict = {}                       # (ma, off) -> (api, {(cls, name)})
        self.const_calls: dict = defaultdict(dict)    # sig -> {(ma, off): args}
        self.irs: dict = {}
        self.rounds = 0
        self._by_name: dict[str, list] | None = None
        self.extra_edges: set = set()                 # cạnh gọi giải được qua reflection / callback framework
        self.label_str = None                         # hàm str -> bool: hằng nào được gắn nhãn ("k", s)
        self.inv = inv                                # sig -> [(ma, off)] (để cắt lát)
        self.interesting = interesting                # sig -> bool: API cần hằng số (reflection, crypto...)
        self.budget = budget
        self.fields = fields                          # (đọc, ghi): "tên kiểu" field -> {method}
        self.truncated = False
        self.n_total = 0
        self.crypto_sites: list = []                  # (ma, off, sig, nhãn object Cipher, nhãn đối số)
        self._csites: set = set()

    # ------------------------------------------------------------------ driver
    def methods(self):
        out = []
        for cls in self.cha.internal:
            if not self.include_libs and self.is_lib(cls):
                continue
            out.extend(self.cha.meth[cls].values())
        return out

    def _slice(self, ms: list) -> list:
        """Chỉ giữ method trên đường tới nguồn/đích/API quan tâm: caller (mọi tầng) + callee (3 tầng)."""
        if self.inv is None:
            return ms
        mset = set(ms)
        seeds = set()
        for sig, occ in self.inv.items():
            if self.spec.is_src(sig) or self.spec.is_sink(sig) or (self.interesting and self.interesting(sig)):
                seeds.update(m for m, _ in occ if m in mset)
        if self.spec.cb_src:
            seeds.update(m for m in ms if self.spec.cb_match(self.cha.overrides(m)))
        rel = set(seeds)
        q = list(seeds)
        while q:                                   # caller: taint đi lên qua giá trị trả về / field
            m = q.pop()
            for c, _ in self.cha.preds(m):
                if c in mset and c not in rel:
                    rel.add(c)
                    q.append(c)
        frontier = set(rel)
        for _ in range(3):                         # callee: hàm phụ biến đổi / lưu dữ liệu
            nxt = set()
            for m in frontier:
                for c in self.cha.callees.get(m, ()):
                    if c in mset and c not in rel:
                        rel.add(c)
                        nxt.add(c)
            frontier = nxt
        # <clinit> / constructor ghi field hằng (tên class cho reflection, key...)
        rel.update(m for m in ms if m.name in ("<clinit>",))
        rel = self._close(rel, mset)
        return [m for m in ms if m in rel]

    def _close(self, rel: set, mset: set) -> set:
        """Field: method đọc field mà lát đang ghi (vd onBind: d2 = d1) cũng thuộc lát; lặp tới ổn định.
        Mỗi method thêm vào kéo theo caller của nó (giá trị có thể được trả lên)."""
        if not self.fields:
            return rel
        fr, fw = self.fields
        wr_of: dict = defaultdict(set)
        for f, ms_ in fw.items():
            for m in ms_:
                wr_of[m].add(f)
        done_f: set = set()
        changed = True
        while changed:
            changed = False
            written = set()
            for m in rel:
                written |= wr_of.get(m, set())
            for f in written - done_f:
                done_f.add(f)
                for m in fr.get(f, ()):
                    if m in mset and m not in rel:
                        rel.add(m)
                        changed = True
                        q = [m]
                        while q:
                            x = q.pop()
                            for c, _ in self.cha.preds(x):
                                if c in mset and c not in rel:
                                    rel.add(c)
                                    q.append(c)
        return rel

    def run(self):
        import time as _t
        t0 = _t.time()
        all_ms = [m for m in self.methods() if m.get_method().get_code() is not None]
        self.n_total = len(all_ms)
        ms = self._slice(all_ms)
        order, seen = [], set()
        for root in ms:                      # callee trước caller (postorder DFS)
            if root in seen:
                continue
            stack = [(root, iter(self.cha.callees.get(root, ())))]
            seen.add(root)
            while stack:
                node, it = stack[-1]
                nxt = next(it, None)
                if nxt is None:
                    stack.pop()
                    order.append(node)
                elif nxt not in seen and nxt.get_method().get_code() is not None:
                    seen.add(nxt)
                    stack.append((nxt, iter(self.cha.callees.get(nxt, ()))))
        dirty = set(order)
        for r in range(self.max_rounds):
            if _t.time() - t0 > self.budget:
                self.truncated = True
                break
            self.rounds = r + 1
            fw_t: dict = defaultdict(frozenset)
            fw_c: dict = {}
            changed_m = set()
            for ma in order:
                ir = self.irs.get(ma)
                if ir is None:
                    ir = lift(ma)
                    if ir is None:
                        continue
                    if sum(len(b.insns) for b in ir.blocks) > self.max_insns:
                        ir.blocks = []
                    self.irs[ma] = ir
                if ma not in dirty:
                    continue
                s = self._analyze(ir, fw_t, fw_c)
                old = self.summ.get(ma)
                if old is None or old.key() != s.key():
                    changed_m.add(ma)
                self.summ[ma] = s
            changed_f = False
            for f, t in fw_t.items():
                nt = self.f_taint.get(f, E) | t
                if nt != self.f_taint.get(f, E):
                    self.f_taint[f] = nt
                    changed_f = True
            for f, c in fw_c.items():
                nc = c if f not in self.f_consts else jc(self.f_consts[f], c)
                if nc != self.f_consts.get(f, E):
                    self.f_consts[f] = nc
                    changed_f = True
            if not changed_m and not changed_f:
                ext = self._extend_slice(order, all_ms)
                if not ext:
                    break
                order = ext + order          # method mới (callee) trước
                dirty = set(order)
                continue
            # vòng sau: field đổi -> chạy lại tất cả; chỉ summary đổi -> chạy lại caller của chúng
            if changed_f:
                dirty = set(order)
            else:
                dirty = set()
                for m in changed_m:
                    dirty |= {c for c, _ in self.cha.callers.get(m, ())}
                    dirty.add(m)
        if self.extra_edges:
            self.cha.extend(self.extra_edges)
        return self

    def _extend_slice(self, order: list, all_ms: list) -> list:
        """Đích reflection / callback tìm ra lúc chạy nhưng nằm ngoài lát -> thêm vào (kèm callee 3 tầng)."""
        have = set(order)
        mset = set(all_ms)
        new = {b for _, b in self.extra_edges if b in mset and b not in have}
        if not new:
            return []
        frontier = set(new)
        for _ in range(3):
            nxt = set()
            for m in frontier:
                for c in self.cha.callees.get(m, ()):
                    if c in mset and c not in have and c not in new:
                        new.add(c)
                        nxt.add(c)
            frontier = nxt
        new = self._close(new | have, mset) - have
        return [m for m in all_ms if m in new]

    def _src(self, ma, off, sig, kind) -> int:
        k = (ma, off)
        i = self._src_idx.get(k)
        if i is None:
            i = self._src_idx[k] = len(self.sources)
            self.sources.append(SourceSite(i, ma, off, sig, kind))
        return i

    def _flow(self, src, sink_ma, sink_off, sig, chain):
        k = (src, sink_ma, sink_off)
        if k not in self.flows:
            self.flows[k] = Flow(src, sink_ma, sink_off, sig, chain)

    # ------------------------------------------------------------------ intra-procedural
    def _analyze(self, ir: MethodIR, fw_t, fw_c) -> Summary:
        ma = ir.ma
        S = Summary()
        heap: dict = defaultdict(frozenset)
        init = {}
        cb = self.spec.cb_match(self.cha.overrides(ma)) if self.spec.cb_src else None
        for i, (r, t) in enumerate(zip(ir.param_regs, ir.param_types)):
            taint = {("p", i)}
            if cb and (i > 0 or ir.is_static):
                taint.add(self._src(ma, -1 - i, cb, "param"))
            init[r] = (E, frozenset(taint), frozenset((("pa", i),)) if t[0] in "L[" else E)
        if not ir.blocks:
            return S
        C = Ctx(ma, S, heap, fw_t, fw_c, None if ir.is_static else ma.class_name)
        by_start = {b.start: b.idx for b in ir.blocks}
        for _ in range(3):
            hsnap = dict(heap)
            ins_state = {0: dict(init)}
            work, inq, visits = [0], {0}, 0
            while work and visits < 20 * len(ir.blocks) + 50:
                bi = work.pop()
                inq.discard(bi)
                visits += 1
                b = ir.blocks[bi]
                st = dict(ins_state[bi])
                for ins in b.insns:
                    self._step(ins, st, C)
                succs = self._prune(b, st, by_start) + b.handlers
                for j in succs:
                    cur = ins_state.get(j)
                    if cur is None:
                        ins_state[j] = dict(st)
                        changed = True
                    else:
                        changed = False
                        for r, v in st.items():
                            o = cur.get(r)
                            if o is None:
                                cur[r] = v
                                changed = True
                            else:
                                n = join(o, v)
                                if n != o:
                                    cur[r] = n
                                    changed = True
                    if changed and j not in inq:
                        inq.add(j)
                        work.append(j)
            if heap == hsnap:
                break
        rv = C.ret or EMPTY
        for x in self._eff(rv, heap):
            if isinstance(x, int):
                S.ret_src.add(x)
            elif x[0] == "p":
                S.p2ret.add(x[1])
        S.ret_consts = rv[0]
        for a, t in heap.items():
            if isinstance(a, tuple) and a[0] == "f":
                conc = frozenset(x for x in t if isinstance(x, int))
                if conc:
                    fw_t[a[1]] = fw_t[a[1]] | conc
                for x in t:
                    if not isinstance(x, int) and x[0] == "p":
                        S.p2field[x[1]].add(a[1])
                continue
            if isinstance(a, tuple) and a[0] == "pa":
                k = a[1]
                for x in t:
                    if isinstance(x, int):
                        S.src2p[k].add(x)
                    elif x[0] == "p" and x[1] != k:
                        S.p2p.add((x[1], k))
        return S

    @staticmethod
    def _prune(b, st, by_start) -> list[int]:
        """Bỏ nhánh không thể đi khi điều kiện if-* là hằng."""
        if not b.insns or len(b.succs) != 2:
            return b.succs
        ins = b.insns[-1]
        op = ins.op
        if not (0x32 <= op <= 0x3D) or ins.lit is None:
            return b.succs
        a = single(st.get(ins.regs[0], EMPTY)[0])
        if op <= 0x37:
            c = single(st.get(ins.regs[1], EMPTY)[0]) if len(ins.regs) > 1 else None
        else:
            c = 0
        if not isinstance(a, int) or not isinstance(c, int) or isinstance(a, bool):
            return b.succs
        k = (op - 0x32) % 6
        taken = (a == c, a != c, a < c, a >= c, a > c, a <= c)[k]
        tgt = by_start.get(ins.lit)
        if tgt is None or tgt not in b.succs:
            return b.succs
        other = [s for s in b.succs if s != tgt]
        return [tgt] if taken else other

    def _eff(self, v, heap) -> frozenset:
        t = v[1]
        for a in v[2]:
            h = heap.get(a)
            if h:
                t = t | h
            if a[0] == "f":
                ft = self.f_taint.get(a[1])
                if ft:
                    t = t | ft
        return t

    # ------------------------------------------------------------------ transfer
    def _step(self, ins, st, C: Ctx):
        op = ins.op
        r = ins.regs
        if op in INVOKE:
            return self._invoke(ins, st, C)
        if op in MOVE_RESULT or op in (0x00, 0x0E, 0x1D, 0x1E, 0x1F, 0x26, 0x28, 0x29, 0x2A, 0x2B, 0x2C) \
                or 0x32 <= op <= 0x3D:
            return
        heap = C.heap
        g = st.get
        if 0x01 <= op <= 0x09:
            st[r[0]] = g(r[1], EMPTY)
        elif op in (0x0F, 0x10, 0x11):
            v = g(r[0], EMPTY)
            C.ret = v if C.ret is None else join(C.ret, v)
        elif 0x12 <= op <= 0x19:
            lit = ins.lit
            if op == 0x15 and lit is not None and abs(lit) < 0x10000:
                lit <<= 16
            st[r[0]] = (frozenset((lit,)) if lit is not None else E, E, E)
        elif op in (0x1A, 0x1B):
            lab = E
            if self.label_str is not None and self.label_str(ins.ref):
                lab = frozenset((("k", ins.ref),))
            st[r[0]] = (frozenset((ins.ref,)), lab, E)
        elif op == 0x1C:
            st[r[0]] = (frozenset((("C", ins.ref),)), E, E)
        elif op == 0x27:                                    # throw
            t = self._eff(g(r[0], EMPTY), heap)
            if t and not t <= heap[THROWN]:
                heap[THROWN] = heap[THROWN] | t
        elif op == 0x0D:                                    # move-exception
            st[r[0]] = (E, heap.get(THROWN, E), E)
        elif op in (0x20, 0x21) or 0x2D <= op <= 0x31:
            st[r[0]] = EMPTY
        elif op == 0x22:
            st[r[0]] = (frozenset(("",)) if ins.ref in STRB else E, E, frozenset((("a", ins.off),)))
        elif op == 0x23:
            st[r[0]] = (E, E, frozenset((("a", ins.off),)))
        elif op in FILLED_NEW:
            if ins.res is not None:
                a = ("a", ins.off)
                t = E
                for x in r:
                    t = t | self._eff(g(x, EMPTY), heap)
                heap[a] = heap[a] | t
                st[ins.res] = (E, E, frozenset((a,)))
        elif 0x44 <= op <= 0x4A:
            av = g(r[1], EMPTY)
            st[r[0]] = (E, self._eff(av, heap), av[2] if op == 0x46 else E)
        elif 0x4B <= op <= 0x51:
            t = self._eff(g(r[0], EMPTY), heap)
            av = g(r[1], EMPTY)
            if av[2]:
                for a in av[2]:
                    if not t <= heap[a]:
                        heap[a] = heap[a] | t
            elif t:
                st[r[1]] = (av[0], av[1] | t, av[2])
        elif 0x52 <= op <= 0x58 or 0x60 <= op <= 0x66:
            f = self.cha.canon_field(ins.ref)
            t = self.f_taint.get(f, E)
            if self.spec.field_src and self.spec.is_field_src(f):
                t = t | {self._src(C.ma, ins.off, f, "field")}
            if op <= 0x58 and f.split("->", 1)[0] not in self.cha.internal:
                t = t | self._eff(g(r[1], EMPTY), heap)      # field của class framework (PointF.x...)
            # object đọc từ field: ghi vào nội dung của nó (aput, list.add...) = làm bẩn field
            st[r[0]] = (self.f_consts.get(f, E), t, frozenset((("f", f),)) if op in (0x54, 0x62) else E)
        elif 0x59 <= op <= 0x5F or 0x67 <= op <= 0x6D:
            f = self.cha.canon_field(ins.ref)
            v = g(r[0], EMPTY)
            if op <= 0x5F and f.split("->", 1)[0] not in self.cha.internal:
                self._taint_obj(self._eff(v, heap), g(r[1], EMPTY), r[1], st, heap)
            t = self._eff(v, heap)
            conc = frozenset(x for x in t if isinstance(x, int))
            if conc:
                C.fw_t[f] = C.fw_t[f] | conc
            for x in t:
                if not isinstance(x, int) and x[0] == "p":
                    C.S.p2field[x[1]].add(f)
            C.fw_c[f] = v[0] if f not in C.fw_c else jc(C.fw_c[f], v[0])
        elif 0x7B <= op <= 0x8F:
            v = g(r[1], EMPTY)
            c = E
            if op in (0x8D, 0x8E, 0x8F, 0x7B, 0x7C):        # int-to-byte/char/short, neg, not
                x = single(v[0])
                if isinstance(x, int):
                    c = frozenset(({0x8D: lambda z: ((z + 128) & 0xFF) - 128, 0x8E: lambda z: z & 0xFFFF,
                                    0x8F: lambda z: ((z + 0x8000) & 0xFFFF) - 0x8000, 0x7B: lambda z: s32(-z),
                                    0x7C: lambda z: s32(~z)}[op](x),))
            st[r[0]] = (c, self._eff(v, heap), E)
        elif 0x90 <= op <= 0xAF or 0xB0 <= op <= 0xCF:
            two = op >= 0xB0
            a, b = (g(r[0], EMPTY), g(r[1], EMPTY)) if two else (g(r[1], EMPTY), g(r[2], EMPTY))
            base = op - (0xB0 if two else 0x90)
            c = E
            if base <= 10:
                x, y = single(a[0]), single(b[0])
                if isinstance(x, int) and isinstance(y, int):
                    z = arith(base, x, y)
                    c = frozenset((z,)) if z is not None else E
            st[r[0]] = (c, self._eff(a, heap) | self._eff(b, heap), E)
        elif 0xD0 <= op <= 0xE2:
            a = g(r[1], EMPTY)
            c = E
            x, y = single(a[0]), ins.lit
            if isinstance(x, int) and isinstance(y, int):
                k = LIT16[op - 0xD0] if op <= 0xD7 else LIT8[op - 0xD8]
                z = arith(1, y, x) if k == "r" else arith(k, x, y)
                c = frozenset((z,)) if z is not None else E
            st[r[0]] = (c, self._eff(a, heap), E)

    # ------------------------------------------------------------------ invoke
    def _apply(self, t, args, regs_k, st, C: Ctx, res):
        """Áp tóm tắt của method nội bộ t lên đối số args. res = [consts, taint, allocs] (cập nhật tại chỗ)."""
        s = self.summ.get(t)
        if s is None:
            return
        eff, heap, S, ma = self._eff, C.heap, C.S, C.ma
        c = None
        for i in s.p2ret:
            if i < len(args):
                res[1] |= eff(args[i], heap)
                res[2] |= args[i][2]
                c = args[i][0] if c is None else jc(c, args[i][0])
        res[1] |= s.ret_src
        if s.p2ret and s.ret_consts:
            c = jc(c, s.ret_consts) if c is not None else s.ret_consts
        elif not s.p2ret:
            c = s.ret_consts
        res[0] = c if res[0] is None else jc(res[0], c)
        for i, refs in s.p2sink.items():
            if i >= len(args):
                continue
            et = eff(args[i], heap)
            if not et:
                continue
            for (sm, so, ss, chain) in refs:
                if len(chain) >= MAX_CHAIN or ma in chain:
                    continue
                nc = (ma,) + chain
                for x in et:
                    if isinstance(x, int):
                        self._flow(x, sm, so, ss, nc)
                    elif x[0] == "p" and len(S.p2sink[x[1]]) < MAX_REFS:
                        S.p2sink[x[1]].add((sm, so, ss, nc))
        for i, fs in s.p2field.items():
            if i >= len(args):
                continue
            for x in eff(args[i], heap):
                if isinstance(x, int):
                    for f in fs:
                        C.fw_t[f] = C.fw_t[f] | {x}
                elif x[0] == "p":
                    S.p2field[x[1]].update(fs)
        for (sm, so, ok, ak, op_, ap_) in s.crypto:
            ok2, ak2, opn, apn = set(ok), set(ak), set(), set()
            for idx, dk, dp in ((op_, ok2, opn), (ap_, ak2, apn)):
                for i in idx:
                    if i < len(args):
                        k_, p_ = self._labs(args[i], heap)
                        dk |= k_
                        dp |= p_
            self._crypto(C, sm, so, frozenset(ok2), frozenset(ak2), frozenset(opn), frozenset(apn))
        for (i, k) in s.p2p:
            if i < len(args) and k < len(args):
                self._taint_obj(eff(args[i], heap), args[k], regs_k[k], st, heap)
        for k, srcs in s.src2p.items():
            if k < len(args):
                self._taint_obj(frozenset(srcs), args[k], regs_k[k], st, heap)

    def _labs(self, v, heap):
        """(nhãn hằng crypto ("k"), chỉ số tham số ("p")) trong giá trị v."""
        k, p = set(), set()
        for x in self._eff(v, heap):
            if isinstance(x, tuple):
                if x[0] == "k":
                    k.add(x[1])
                elif x[0] == "p":
                    p.add(x[1])
        return frozenset(k), frozenset(p)

    def _crypto(self, C, site_ma, off, ok, ak, op_, ap_):
        if ak:
            key = (site_ma, off, ok, ak)
            if key not in self._csites:
                self._csites.add(key)
                self.crypto_sites.append((site_ma, off, "Ljavax/crypto/Cipher;->doFinal", ok, ak))
        if (op_ or ap_) and len(C.S.crypto) < MAX_REFS:
            C.S.crypto.add((site_ma, off, ok, ak, op_, ap_))

    def _sink(self, sig, args, static, C: Ctx, off):
        S, ma = C.S, C.ma
        for i, a in enumerate(args):
            if i == 0 and not static:
                continue
            for x in self._eff(a, C.heap):
                if isinstance(x, int):
                    self._flow(x, ma, off, sig, (ma,))
                elif x[0] == "p" and len(S.p2sink[x[1]]) < MAX_REFS:
                    S.p2sink[x[1]].add((ma, off, sig, (ma,)))

    def _invoke(self, ins, st, C: Ctx):
        sig = ins.ref
        if not sig or "->" not in sig:
            return
        op = ins.op
        static = op in (0x71, 0x77)
        cls, rest = sig.split("->", 1)
        try:
            name = rest[:rest.index("(")]
            params, rtype = split_desc(rest[len(name):])
        except ValueError:
            return
        regs = ins.regs
        pos, p = [], 0
        if not static:
            pos.append(0)
            p = 1
        for t in params:
            pos.append(p)
            p += 2 if t in ("J", "D") else 1
        g = st.get
        args = [g(regs[x], EMPTY) if x < len(regs) else EMPTY for x in pos]
        regs_k = [regs[x] if x < len(regs) else None for x in pos]
        eff, heap = self._eff, C.heap

        if self.spec.is_sink(sig):
            self._sink(sig, args, static, C, ins.off)
        if self.label_str is not None and cls == "Ljavax/crypto/Cipher;" and name == "doFinal" and len(args) > 1:
            (ok, op_), (ak, ap_) = self._labs(args[0], heap), self._labs(args[1], heap)
            self._crypto(C, C.ma, ins.off, ok, ak, op_, ap_)

        res = [None, E, E]
        targets = self.cha.resolve(op, sig) if cls in self.cha.internal or not static else []
        if cls not in self.cha.internal and (cls == "Ljava/lang/Object;" or len(targets) > 8):
            targets = []
        targets = [t for t in targets if t in self.irs or t in self.summ]
        if targets:
            for t in targets:
                self._apply(t, args, regs_k, st, C, res)
            if rtype[0] in "L[":
                res[2] |= frozenset((("a", ins.off),))
        else:
            bridged = self._bridges(cls, name, args, regs_k, st, C, res, ins)
            # method framework gọi trên object của app (this.getIntent(), this.setTitle(x)...): receiver là
            # Activity/Context -> không truyền taint qua receiver (tránh "this" bẩn kéo theo mọi thứ)
            ctx_recv = not static and cls in self.cha.internal
            if not bridged and not CLEAN.match(name):
                for i, a in enumerate(args):
                    if i == 0 and ctx_recv:
                        continue
                    res[1] |= eff(a, heap)
                if not static and not ctx_recv and len(args) > 1 and MUTATOR.match(name):
                    t = E
                    for a in args[1:]:
                        t |= eff(a, heap)
                    self._taint_obj(t, args[0], regs_k[0], st, heap)
                if name == "<init>" and not static and regs_k[0] is not None and WRAPPER.match(cls):
                    # object bọc object khác (Formatter(buf), PrintWriter(out), BufferedReader(in)...): chung heap
                    extra = E
                    for i, pt in enumerate(params):
                        if pt[0] == "L" and pt != "Ljava/lang/String;" and i + 1 < len(args):
                            extra |= args[i + 1][2]
                    if extra:
                        o = st.get(regs_k[0], EMPTY)
                        st[regs_k[0]] = (o[0], o[1], o[2] | extra)
                store = self._store_key(cls, name, params, args)
                if store is not None:
                    key, is_put = store
                    if is_put:
                        t = eff(args[2], heap) if len(args) > 2 else E
                        conc = frozenset(x for x in t if isinstance(x, int))
                        if conc:
                            C.fw_t[key] = C.fw_t[key] | conc
                        for x in t:
                            if not isinstance(x, int) and x[0] == "p":
                                C.S.p2field[x[1]].add(key)
                    else:
                        res[1] |= self.f_taint.get(key, E)
                if cls == "Ljava/lang/System;" and name == "arraycopy" and len(args) >= 3:
                    self._taint_obj(eff(args[0], heap), args[2], regs_k[2], st, heap)
                # mảng truyền vào API framework có thể bị ghi (getChars, read(buf)...)
                off0 = 0 if static else 1
                for i, pt in enumerate(params):
                    if pt[0] == "[" and i + off0 < len(args):
                        t = E
                        for j, a in enumerate(args):
                            if j != i + off0:
                                t |= eff(a, heap)
                        self._taint_obj(t, args[i + off0], regs_k[i + off0], st, heap)
            if rtype[0] in "L[":
                res[2] = res[2] | frozenset((("a", ins.off),))
                if not static and (rtype == cls or name in ("append", "insert")):
                    res[2] |= args[0][2]
        res[0] = self._consts(sig, cls, name, static, params, args, regs, st, C, ins,
                              E if res[0] is None else res[0])
        if self.spec.is_src(sig):
            res[1] = res[1] | {self._src(C.ma, ins.off, sig, "api")}
        if ins.res is not None:
            st[ins.res] = (res[0], frozenset(res[1]), frozenset(res[2]))

    def _bridges(self, cls, name, args, regs_k, st, C, res, ins) -> bool:
        """Framework gọi ngược code của app: AsyncTask.execute -> doInBackground; Method.invoke (reflection)."""
        eff, heap = self._eff, C.heap
        if name in ("execute", "executeOnExecutor") and cls in self.cha.internal:
            tg = self.cha.resolve(0x6E, f"{cls}->doInBackground([Ljava/lang/Object;)Ljava/lang/Object;")
            if tg:
                arr = args[-1]
                cargs = [args[0], (E, eff(arr, heap), arr[2])]
                for t in tg:
                    self._edge(C.ma, t)
                    self._apply(t, cargs, [regs_k[0], regs_k[-1]], st, C, [None, E, E])
                return False
        if cls == "Ljava/lang/reflect/Method;" and name == "invoke" and len(args) >= 2:
            targets = [x for x in args[0][0] if isinstance(x, tuple) and x[0] == "M"]
            if not targets:
                return False
            arr = args[2] if len(args) > 2 else EMPTY
            elem = (E, eff(arr, heap), E)
            for _, c, m in targets:
                cands = []
                if c and c in self.cha.internal:
                    cc = c
                    while cc in self.cha.internal and not cands:
                        cands = [mm for k, mm in self.cha.meth[cc].items() if k.startswith(m + "(")]
                        cc = self.cha.sup.get(cc)
                elif c is None:
                    cands = self._methods_named(m)[:3]
                for t in cands:
                    self._edge(C.ma, t)
                    st_ = bool(t.get_method().get_access_flags() & 0x8)
                    n = len(split_desc(t.descriptor)[0])
                    cargs = ([] if st_ else [args[1]]) + [elem] * n
                    self._apply(t, cargs, [None] * len(cargs), st, C, res)
                if c and c not in self.cha.internal:
                    pseudo = f"{c}->{m}("
                    if self.spec.is_src(pseudo) or any(p.search(pseudo) for p in self.spec.api_src):
                        res[1] |= {self._src(C.ma, ins.off, pseudo + ")", "api")}
                    if any(p.search(pseudo) for p in self.spec.sinks):
                        self._sink(pseudo + ")", [args[1], elem], False, C, ins.off)
            return True
        return False

    STORES = (("Landroid/content/SharedPreferences$Editor;", "put", "@prefs"),
              ("Landroid/content/SharedPreferences;", "get", "@prefs"),
              ("Landroid/os/Bundle;", "put", "@bundle"), ("Landroid/os/Bundle;", "get", "@bundle"),
              ("Landroid/os/BaseBundle;", "put", "@bundle"), ("Landroid/os/BaseBundle;", "get", "@bundle"))

    def _store_key(self, cls, name, params, args):
        """SharedPreferences / Bundle như một kho chung theo key: put(k, v) ... get(k)."""
        for c, pre, store in self.STORES:
            if cls == c and name.startswith(pre) and params and params[0] == "Ljava/lang/String;" and len(args) > 1:
                k = single(args[1][0])
                return (f"{store}:{k if isinstance(k, str) else '*'}", pre == "put")
        return None

    def _edge(self, a, b):
        if (a, b) not in self.extra_edges:
            self.extra_edges.add((a, b))
            self.cha.callers[b].add((a, "reflect"))     # để caller được phân tích lại khi b đổi

    def _methods_named(self, n):
        if self._by_name is None:
            self._by_name = defaultdict(list)
            for m in self.irs:
                self._by_name[m.name].append(m)
        return self._by_name.get(n, [])

    @staticmethod
    def _taint_obj(t, target, reg, st, heap):
        if not t:
            return
        if target[2]:
            for a in target[2]:
                if not t <= heap[a]:
                    heap[a] = heap[a] | t
        elif reg is not None:
            st[reg] = (target[0], target[1] | t, target[2])

    def _consts(self, sig, cls, name, static, params, args, regs, st, C, ins, cur):
        ma = C.ma
        if cls in STRB:
            if name == "<init>":
                c = args[1][0] if len(args) > 1 else frozenset(("",))
                if len(args) > 1 and not all(isinstance(x, str) for x in c):
                    c = E
                o = st.get(regs[0], EMPTY)
                st[regs[0]] = (c, o[1], o[2])
                return cur
            if name == "append" and len(args) > 1:
                a, b = args[0][0], args[1][0]
                o = st.get(regs[0], EMPTY)
                c = E
                if a and b and TOP not in a and TOP not in b and len(a) * len(b) <= MAX_CONSTS:
                    ch = params and params[0] == "C"
                    c = frozenset(x + (chr(y & 0xFFFF) if ch and isinstance(y, int) else str(y))
                                  for x in a for y in b if isinstance(x, str) and not isinstance(y, tuple))
                st[regs[0]] = (c, o[1], o[2])
                return c
            if name == "toString":
                return args[0][0]
        if cls == "Ljava/lang/String;":
            if name == "concat" and len(args) == 2:
                a, b = args[0][0], args[1][0]
                if a and b and TOP not in a and TOP not in b and len(a) * len(b) <= MAX_CONSTS:
                    return frozenset(x + y for x in a for y in b if isinstance(x, str) and isinstance(y, str))
            if name in ("valueOf", "intern", "trim", "toString") and args:
                c = args[0][0]
                if c and TOP not in c:
                    ch = params and params[0] == "C"
                    return frozenset(chr(x & 0xFFFF) if ch and isinstance(x, int) else str(x)
                                     for x in c if not isinstance(x, tuple))
                return E
        if name == "getString" and params == ["I"] and self.res_string:
            v = single(args[-1][0])
            if isinstance(v, int):
                s = self.res_string(v)
                if s is not None:
                    return frozenset((s,))
        if cls == "Ljava/lang/Object;" and name == "getClass" and args and C.this_cls \
                and ("pa", 0) in args[0][2]:
            return frozenset((("C", C.this_cls),))
        if cls == "Ljava/lang/reflect/Method;" and name == "getName" and args:
            return frozenset(x[2] for x in args[0][0] if isinstance(x, tuple) and x[0] == "M" and x[2])
        if (name == "forName" and cls == "Ljava/lang/Class;") or name == "loadClass":
            c = args[1][0] if name == "loadClass" and len(args) > 1 else (args[0][0] if args else E)
            names = frozenset(x for x in c if isinstance(x, str))
            self.reflect[(ma, ins.off)] = ("Class.forName" if name == "forName" else "loadClass",
                                           frozenset((n, None) for n in names))
            return frozenset(("C", "L" + n.replace(".", "/") + ";") for n in names)
        if cls == "Ljava/lang/Class;" and name in ("getMethod", "getDeclaredMethod", "getField", "getDeclaredField"):
            rc = args[0][0] if args else E
            classes = [x[1] for x in rc if isinstance(x, tuple) and x[0] == "C"] or [None]
            mn = [x for x in (args[1][0] if len(args) > 1 else E) if isinstance(x, str)] or [None]
            self.reflect[(ma, ins.off)] = (name, frozenset((c, m) for c in classes for m in mn))
            return frozenset(("M", c, m) for c in classes for m in mn if m)
        if static and sig.endswith(")Ljava/lang/String;") and not sig.startswith(("Ljava/", "Landroid/")):
            vals = []
            for a in args:
                v = single(a[0])
                if v is None or isinstance(v, tuple):
                    return cur
                vals.append(v)
            if vals:
                vals = tuple(vals)
                self.const_calls[sig][(ma, ins.off)] = vals
                p = self.decrypted.get((sig, vals))
                if p is not None:
                    return frozenset((p,))
        return cur

    # ------------------------------------------------------------------ query
    def flows_for(self, src_pats: list[tuple[str, re.Pattern]], sink_pats: list[re.Pattern]) -> list[Flow]:
        out = []
        for f in self.flows.values():
            s = self.sources[f.src]
            ok = False
            for kind, p in src_pats:
                if (kind == "api" and s.kind == "api" or kind == "cb" and s.kind == "param"
                        or kind == "field" and s.kind == "field") and p.search(s.sig):
                    ok = True
                    break
            if ok and any(p.search(f.sink_sig) for p in sink_pats):
                out.append(f)
        return out
