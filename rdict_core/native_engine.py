"""Engine phân tích ELF (.so) bằng lief + capstone.

Thay vì chỉ 'strings':
  * imports/exports thật từ bảng symbol động
  * phân giải PLT stub -> tìm CALL SITE thật của ptrace/strstr/... (địa chỉ + hàm chứa nó)
  * xref string: adrp+add (arm64), lea [rip+x] (x86_64), [ebx+x] (x86 PIC) -> biết hàm nào dùng chuỗi "frida"
  * call graph native + root (JNI export, JNI_OnLoad, .init_array) -> đường gọi tới đoạn mã
  * entropy section, section header bị xóa, hàm trong .init_array
"""
from __future__ import annotations

import bisect
import re
from collections import defaultdict, deque

import capstone as cs
import lief

from .model import Hit, Rule
from .text_engine import ScanFile

lief.logging.disable()

MAX_CODE = 12 * 1024 * 1024
CALL_MN = {"bl", "blx", "call", "b", "jmp", "b.w", "bl.w"}
TAIL_MN = {"b", "jmp", "b.w"}
HEX = re.compile(r"#?(0x[0-9a-f]+)\b")
JCLASS = re.compile(r"^[A-Za-z_$][\w$]*(?:/[\w$]+)+$")
JNAME = re.compile(r"^(?:<init>|[A-Za-z_$][\w$]*)$")
JSIG = re.compile(r"^\((?:\[*(?:[ZBCSIJFD]|L[\w/$]+;))*\)\[*(?:[ZBCSIJFDV]|L[\w/$]+;)$")
STD_SECTIONS = {
    "", ".text", ".rodata", ".data", ".bss", ".dynsym", ".dynstr", ".gnu.hash", ".hash", ".rela.dyn", ".rela.plt",
    ".rel.dyn", ".rel.plt", ".eh_frame", ".eh_frame_hdr", ".ARM.exidx", ".ARM.extab", ".gcc_except_table",
    ".init_array", ".fini_array", ".data.rel.ro", ".dynamic", ".got", ".got.plt", ".note.android.ident",
    ".note.gnu.build-id", ".comment", ".gnu.version", ".gnu.version_r", ".gnu.version_d", ".plt", ".symtab",
    ".strtab", ".shstrtab", ".tbss", ".tdata", ".interp", ".relr.dyn", ".android.rel.dyn", ".preinit_array",
    ".debug_info", ".debug_abbrev", ".debug_line", ".debug_str", ".debug_ranges", ".debug_loc", ".gnu_debugdata",
}


def _arch(b):
    A = lief.ELF.ARCH
    m = b.header.machine_type
    arm64 = getattr(cs, "CS_ARCH_ARM64", None) or getattr(cs, "CS_ARCH_AARCH64")
    if m == A.AARCH64:
        return "arm64", cs.Cs(arm64, cs.CS_MODE_ARM)
    if m == A.X86_64:
        return "x86_64", cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    if m == A.I386:
        return "x86", cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    if m == A.ARM:
        return "arm", cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
    return None, None


class NativeLib:
    def __init__(self, sf: ScanFile):
        self.sf = sf
        self.rel = sf.rel
        self.name = sf.path.name
        self.ok = False
        self.reason = ""
        b = lief.ELF.parse(str(sf.path))
        if b is None:
            self.reason = "lief không parse được"
            return
        self.b = b
        self.arch, self.md = _arch(b)
        self.imports = sorted({f.name for f in b.imported_functions if f.name})
        self.exports = {f.name: f.address & ~1 for f in b.exported_functions if f.name}
        self.sections = list(b.sections)
        self.stubs: dict[int, str] = {}
        self.insns: list[tuple[int, int, str, str]] = []
        self.addrs: list[int] = []
        self.calls: list[tuple[int, int]] = []           # (addr, target)
        self.str_xrefs: dict[int, list[int]] = defaultdict(list)
        self.callees: dict[int, set] = defaultdict(set)  # func -> {func | 'imp:name'}
        self.callers: dict = defaultdict(set)            # func | 'imp:name' -> {func}
        # hàm: eh_frame + symbol + export
        names: dict[int, str] = {}
        for f in b.functions:
            a = f.address & ~1
            fn = "" if (f.name or "").startswith("__dt_") else (f.name or "")
            if a and (a not in names or (fn and not names[a])):
                names[a] = fn
        for n, a in self.exports.items():
            names[a] = n
        self.fnames = names
        self.fstarts = sorted(names)
        self.roots: dict[int, str] = {}
        for n, a in self.exports.items():
            if n.startswith("Java_") or n == "JNI_OnLoad":
                self.roots[a] = "JNI" if n.startswith("Java_") else "JNI_OnLoad"
        try:
            for f in b.ctor_functions:
                self.roots[f.address & ~1] = ".init_array"
        except Exception:
            pass
        # map string va -> text
        self.va_str: dict[int, str] = {}
        text = sf.raw()
        for s, off in zip(text.split("\n"), sf.offsets or []):
            try:
                self.va_str[b.offset_to_virtual_address(off)] = s
            except Exception:
                pass
        if not self.md:
            self.reason = f"chưa hỗ trợ kiến trúc {b.header.machine_type}"
            return
        self.md.skipdata = True
        if self.arch == "arm":          # ARM32: mỗi hàm có thể là ARM hoặc Thumb (bit 0 của symbol / mapping symbol)
            self.md_arm = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
            self.md_arm.skipdata = True
            self.thumb: dict[int, bool] = {}
            for sym in b.symbols:
                v = sym.value
                if not v:
                    continue
                if sym.name in ("$a", "$t") or sym.name.startswith(("$a.", "$t.")):
                    self.thumb[v] = sym.name.startswith("$t")
                elif sym.type == lief.ELF.Symbol.TYPE.FUNC:
                    self.thumb.setdefault(v & ~1, bool(v & 1))
        try:
            self._plt()
            self._disasm()
            self._graph()
            self.ok = True
        except Exception as e:  # pragma: no cover
            self.reason = f"lỗi disassemble: {e}"

    # ------------------------------------------------------------------ PLT
    def _plt(self) -> None:
        b = self.b
        got = {}
        for r in b.pltgot_relocations:
            if r.has_symbol and r.symbol.name:
                got[r.address] = r.symbol.name
        plt = b.get_section(".plt")
        if plt is None or not got:
            return
        code = bytes(plt.content)
        va = plt.virtual_address
        if self.arch == "arm64":
            page = {}
            last = None
            for a, _, mn, op in self.md.disasm_lite(code, va):
                if mn == "adrp":
                    r, imm = op.split(", ")
                    page[r] = int(imm.lstrip("#"), 16)
                    last = a
                elif mn == "ldr" and (m := re.match(r"(\w+), \[(\w+), #(0x[0-9a-f]+)\]", op)):
                    g = page.get(m.group(2), 0) + int(m.group(3), 16)
                    if g in got and last is not None:
                        self.stubs[last] = got[g]
        elif self.arch == "x86_64":
            for a, s, mn, op in self.md.disasm_lite(code, va):
                if mn == "jmp" and (m := re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", op)):
                    g = a + s + (int(m.group(2), 16) * (1 if m.group(1) == "+" else -1))
                    if g in got:
                        self.stubs[a] = got[g]
        elif self.arch == "x86":
            gp = b.get_section(".got.plt") or b.get_section(".got")
            base = gp.virtual_address if gp else 0
            for a, s, mn, op in self.md.disasm_lite(code, va):
                if mn == "jmp" and (m := re.search(r"\[ebx ([+-]) (0x[0-9a-f]+)\]", op)):
                    g = base + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                    if g in got:
                        self.stubs[a] = got[g]
        if not self.stubs:  # fallback theo layout chuẩn
            hdr, ent = {"arm": (20, 12), "x86": (16, 16), "x86_64": (16, 16), "arm64": (32, 16)}[self.arch]
            for i, r in enumerate(b.pltgot_relocations):
                if r.has_symbol:
                    self.stubs[va + hdr + i * ent] = r.symbol.name

    # ------------------------------------------------------------------ disasm
    def _disasm(self) -> None:
        b = self.b
        execs = [s for s in self.sections if s.name != ".plt" and s.size
                 and (s.flags & 0x4)]  # SHF_EXECINSTR
        if sum(s.size for s in execs) > MAX_CODE:
            self.reason = "code quá lớn, chỉ phân tích imports/strings"
            raise RuntimeError(self.reason)
        data_ranges = [(s.virtual_address, s.virtual_address + s.size) for s in self.sections
                       if s.virtual_address and not (s.flags & 0x4)]
        self.fptr_refs: list[tuple[int, int]] = []
        fset = set(self.fstarts)
        gp = b.get_section(".got.plt") or b.get_section(".got")
        gbase = gp.virtual_address if gp else 0

        def in_data(x: int) -> bool:
            return any(lo <= x < hi for lo, hi in data_ranges)

        for sec in execs:
            page: dict[str, int] = {}
            lit: dict[str, int] = {}
            code = bytes(sec.content)
            for a, s, mn, op, thumb in self._chunks(code, sec.virtual_address):
                self.insns.append((a, s, mn, op))
                if mn in CALL_MN or mn.startswith("bl"):
                    if (m := HEX.match(op)):
                        self.calls.append((a, int(m.group(1), 16) & ~1))
                    continue
                ref = None
                if self.arch == "arm64":
                    if mn == "adrp":
                        r, imm = op.split(", ")
                        page[r] = int(imm.lstrip("#"), 16)
                    elif mn == "add" and (m := re.match(r"(\w+), (\w+), #(0x[0-9a-f]+|\d+)$", op)) and m.group(2) in page:
                        ref = page[m.group(2)] + int(m.group(3), 0)
                    elif mn == "adr" and (m := re.match(r"\w+, #(0x[0-9a-f]+)$", op)):
                        ref = int(m.group(1), 16)     # lld nới adrp+add -> nop; adr (cùng trang ±1MB)
                elif self.arch == "x86_64":
                    if (m := re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", op)):
                        ref = a + s + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                elif self.arch == "x86":
                    if mn == "lea" and (m := re.search(r"\[e[a-d]x ([+-]) (0x[0-9a-f]+)\]", op)):
                        ref = gbase + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                elif self.arch == "arm":
                    # literal pool: ldr rX, [pc, #imm]  (+ add rX, pc / add rX, pc, rX khi PIC)
                    pcv = a + (4 if thumb else 8)
                    if mn.startswith("ldr") and (m := re.match(r"(r\d+|ip|lr), \[pc, #(-?0x[0-9a-f]+|-?\d+)\]$", op)):
                        w = self._word(((a + 4) & ~3 if thumb else pcv) + int(m.group(2), 0))
                        if w is not None:
                            lit[m.group(1)] = w
                            if in_data(w):
                                ref = w
                    elif mn.startswith("add") and (m := re.match(r"(r\d+|ip), (?:(r\d+|ip|pc), )?(r\d+|ip|pc)$", op)):
                        rd, r1, r2 = m.group(1), m.group(2) or m.group(1), m.group(3)
                        other = r2 if r1 == "pc" else r1 if r2 == "pc" else None
                        if other in lit:
                            ref = (lit[other] + pcv) & 0xFFFFFFFF
                            lit[rd] = ref
                if ref is not None:
                    if in_data(ref):
                        self.str_xrefs[ref].append(a)
                    elif ref in fset or (ref | 1) in fset:
                        self.fptr_refs.append((a, ref & ~1))
        self.insns.sort()
        self.addrs = [i[0] for i in self.insns]

    def _word(self, va: int) -> int | None:
        for lo, hi, data in self._code_bytes:
            if lo <= va and va + 4 <= hi:
                return int.from_bytes(data[va - lo:va - lo + 4], "little")
        return None

    def _chunks(self, code: bytes, va: int):
        """Disassemble 1 section -> (addr, size, mn, op, thumb). ARM32: tách theo hàm, chọn ARM/Thumb từng đoạn."""
        if self.arch != "arm":
            for a, s, mn, op in self.md.disasm_lite(code, va):
                yield a, s, mn, op, False
            return
        if not hasattr(self, "_code_bytes"):
            self._code_bytes = [(x.virtual_address, x.virtual_address + x.size, bytes(x.content))
                                for x in self.sections if x.size and x.virtual_address and x.type != lief.ELF.Section.TYPE.NOBITS]
        end = va + len(code)
        cuts = sorted({va} | {a for a in set(self.thumb) | set(self.fstarts) if va < a < end})
        prev = None
        for i, lo in enumerate(cuts):
            hi = cuts[i + 1] if i + 1 < len(cuts) else end
            part = code[lo - va:hi - va]
            mode = self.thumb.get(lo, prev)
            if mode is None:     # không có symbol: chọn chế độ ít byte rác hơn
                bad = [sum(1 for x in md.disasm_lite(part[:2048], lo) if x[2] == ".byte") for md in (self.md_arm, self.md)]
                mode = bad[1] < bad[0]
            prev = mode
            for a, s, mn, op in (self.md if mode else self.md_arm).disasm_lite(part, lo):
                yield a, s, mn, op, mode

    def add_funcs(self, fs: dict) -> None:
        """Thêm điểm bắt đầu hàm (vd địa chỉ lấy từ RegisterNatives) rồi dựng lại call graph."""
        new = {f: r for f, r in fs.items() if f and f not in self.fnames}
        if not new:
            return
        for f, r in new.items():
            self.fnames[f] = ""
            self.roots.setdefault(f, r)
        self.fstarts = sorted(self.fnames)
        self.callees.clear()
        self.callers.clear()
        if self.ok:
            self._graph()
        for k in ("_fstr",):
            self.__dict__.pop(k, None)

    def func_of(self, addr: int) -> int | None:
        i = bisect.bisect_right(self.fstarts, addr) - 1
        return self.fstarts[i] if i >= 0 else None

    def fname(self, f: int | None) -> str:
        if f is None:
            return "?"
        n = self.fnames.get(f) or ""
        return n if n else f"sub_{f:x}"

    def _graph(self) -> None:
        fs = set(self.fstarts)
        for a, t in self.calls:
            caller = self.func_of(a)
            if caller is None:
                continue
            if t in self.stubs:
                callee = "imp:" + self.stubs[t]
            elif t in fs and t != caller:
                callee = t
            else:
                continue
            self.callees[caller].add(callee)
            self.callers[callee].add(caller)
        # cạnh callback: hàm A lấy địa chỉ hàm B (truyền cho pthread_create, signal, ...)
        self.cb_edges = set()
        for a, t in self.fptr_refs:
            caller = self.func_of(a)
            if caller is not None and t != caller:
                self.callees[caller].add(t)
                self.callers[t].add(caller)
                self.cb_edges.add((caller, t))

    def path_to(self, f: int, max_depth: int = 10) -> list[str] | None:
        prev = {f: None}
        q = deque([(f, 0)])
        while q:
            n, d = q.popleft()
            if n in self.roots:
                out, cur, pending = [], n, f"[{self.roots[n]}] "
                while cur is not None:
                    out.append(pending + self.fname(cur))
                    nxt = prev[cur]
                    pending = "⇢(callback) " if nxt is not None and (cur, nxt) in getattr(self, "cb_edges", ()) else ""
                    cur = nxt
                return out
            if d < max_depth:
                for p in self.callers.get(n, ()):
                    if p not in prev:
                        prev[p] = n
                        q.append((p, d + 1))
        return None

    def reach_imports(self, f: int, depth: int = 3) -> list[str]:
        seen, out, q = {f}, [], deque([(f, 0)])
        while q:
            n, d = q.popleft()
            for c in self.callees.get(n, ()):
                if isinstance(c, str):
                    if c[4:] not in out:
                        out.append(c[4:])
                elif c not in seen and d < depth:
                    seen.add(c)
                    q.append((c, d + 1))
        return out

    # ------------------------------------------------------------------ JNI: native gọi ngược Java
    def func_strings(self, f: int) -> list[str]:
        """Chuỗi hàm f tham chiếu, theo thứ tự địa chỉ lệnh."""
        if not hasattr(self, "_rev"):
            self._rev = {a: v for v, al in self.str_xrefs.items() for a in al}
        if not hasattr(self, "_fstr"):
            self._fstr: dict[int, list[str]] = defaultdict(list)
            for a in sorted(self._rev):
                v = self.va_str.get(self._rev[a])
                g = self.func_of(a)
                if v is not None and g is not None:
                    self._fstr[g].append(v)
        out = list(self._fstr.get(f, ()))
        if getattr(self, "_emu", None):          # chuỗi dựng trên stack (đã giả lập) cũng tính
            out += self._emu.stack_strings.get(f, [])
        return out

    def jni_calls(self, f: int) -> list[tuple[str | None, str, str]]:
        """(class|None, tên, chữ ký) của method Java mà hàm f lấy qua GetMethodID/GetStaticMethodID:
        ghép chuỗi tên + chuỗi chữ ký đứng cạnh nhau, class = chuỗi FindClass gần nhất phía trước."""
        ss = self.func_strings(f)
        out, cls_at = [], []
        for i, x in enumerate(ss):
            if JCLASS.match(x):
                cls_at.append((i, x.strip("L;") if x.startswith("L") and x.endswith(";") else x))
        for i, x in enumerate(ss):
            if not JSIG.match(x):
                continue
            ni = next((j for j in (i - 1, i + 1) if 0 <= j < len(ss) and JNAME.match(ss[j])), None)
            if ni is None:
                continue
            first = min(i, ni)
            cl = next((c for j, c in reversed(cls_at) if j < first), None)
            out.append((cl, ss[ni], x))
        return out

    def jni_summary(self, f: int, depth: int = 3) -> dict:
        """Tóm tắt hàm JNI f (+ hàm nó gọi tới, depth tầng): method Java gọi ngược, import libc gọi tới."""
        seen, q, jc = {f}, deque([(f, 0)]), []
        while q:
            n, d = q.popleft()
            for t in self.jni_calls(n):
                if t not in jc:
                    jc.append(t)
            if d < depth:
                for c in self.callees.get(n, ()):
                    if not isinstance(c, str) and c not in seen:
                        seen.add(c)
                        q.append((c, d + 1))
        return {"jcalls": jc, "imports": self.reach_imports(f, depth)}

    # ------------------------------------------------------------------ snippets
    def _annot(self, a: int, mn: str, op: str) -> str:
        line = f"0x{a:06x}  {mn:<7} {op}"
        if (m := HEX.match(op)) and (mn in CALL_MN or mn.startswith("bl")):
            t = int(m.group(1), 16) & ~1
            if t in self.stubs:
                line += f"   ; <{self.stubs[t]}@plt>"
            elif t in self.fnames:
                line += f"   ; <{self.fname(t)}>"
        return line

    def window(self, addr: int, ctx: int = 5) -> tuple[list[str], int]:
        if not hasattr(self, "_rev"):
            self._rev = {a: v for v, al in self.str_xrefs.items() for a in al}
        i = bisect.bisect_left(self.addrs, addr)
        s, e = max(0, i - ctx), min(len(self.insns), i + ctx + 1)
        rows = []
        for a, _, mn, op in self.insns[s:e]:
            l = self._annot(a, mn, op)
            if (v := self._rev.get(a)) is not None and v in self.va_str:
                l += f'   ; "{self.va_str[v][:50]}"'
            rows.append(l)
        return rows, i - s + 1

    def hook_at(self, f: int | None, imp: str | None = None) -> str:
        if imp:
            return (f"Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('{imp}'), "
                    f"{{ onEnter(a) {{ console.log('{imp}', a[0], a[1]); }}, onLeave(r) {{ console.log('  =>', r); }} }});")
        return (f"Interceptor.attach(Process.getModuleByName('{self.name}').base.add(0x{f:x}), "
                f"{{ onEnter(a) {{ console.log('{self.fname(f)}', a[0], a[1], a[2]); }}, onLeave(r) {{ console.log('  =>', r); }} }});")

    def hit_at(self, addr: int, match: str, ctx: int, conf: str = "code", note: str | None = None,
               imp: str | None = None) -> Hit:
        f = self.func_of(addr)
        rows, hl = self.window(addr, ctx + 2)
        path = self.path_to(f) if f is not None else None
        return Hit(file=self.rel, line=hl, match=match, snippet_start=1, snippet=rows, lang="asm",
                   confidence=conf, engine="native", offset=addr, klass=self.name, method=self.fname(f),
                   hook=self.hook_at(f, imp) if (f is not None or imp) else None,
                   path=path, reachable=path is not None, note=note)

    # ------------------------------------------------------------------ matching
    def match(self, rule: Rule, ctx: int) -> list[Hit]:
        hits: list[Hit] = []
        for p in rule.imports:
            for name in self.imports:
                if not p.search(name):
                    continue
                sites = [a for a, t in self.calls if self.stubs.get(t) == name] if self.ok else []
                if sites:
                    for a in sites:
                        hits.append(self.hit_at(a, f"call {name}", ctx, imp=name))
                else:
                    hits.append(Hit(self.rel, 0, f"import {name}", 1, [f"import: {name}"], "asm",
                                    confidence="text", engine="native", klass=self.name,
                                    note="Có import nhưng không thấy lời gọi trực tiếp (gọi qua con trỏ hàm / dlsym?)"))
        for p in rule.exports:
            for name, a in self.exports.items():
                if p.search(name):
                    note = None
                    if self.ok:
                        imps = self.reach_imports(a)
                        note = "Gọi tới: " + ", ".join(imps[:15]) if imps else None
                    hits.append(self.hit_at(a, name, ctx, note=note) if self.ok else
                                Hit(self.rel, 0, name, 1, [f"export: {name} @ 0x{a:x}"], "asm",
                                    confidence="code", engine="native", offset=a, klass=self.name))
        if "native" in rule.target and rule.any:
            for s, a, how in self.emu_strings():
                if any(p.search(s) for p in rule.any):
                    note = f"Chuỗi khôi phục bằng giả lập ({how}) — không nằm sẵn trong file"
                    hits.append(self.hit_at(a, f'"{s[:80]}"', ctx, conf="behavior", note=note) if a is not None
                                else Hit(self.rel, 0, s[:120], 1, [s[:200]], "asm", confidence="behavior",
                                         engine="native", klass=self.name, note=note))
            for va, s in self.va_str.items():
                if not any(p.search(s) for p in rule.any):
                    continue
                xs = self.str_xrefs.get(va, [])
                if xs:
                    for a in xs:
                        hits.append(self.hit_at(a, f'"{s[:80]}"', ctx, note="Chuỗi được tham chiếu trong code"))
                else:
                    hits.append(Hit(self.rel, 0, s[:120], 1, [f"0x{va:08x}  {s[:200]}"], "asm",
                                    confidence="text", engine="native", offset=va, klass=self.name,
                                    note="Chỉ có trong strings, không tìm thấy xref"))
        return hits

    # ------------------------------------------------------------------ giả lập (unicorn)
    @property
    def emu(self):
        if not hasattr(self, "_emu"):
            self._emu = None
            if self.ok:
                try:
                    from .native_emu import emulate
                    self._emu = emulate(self)
                    if self._emu and self._emu.natives:     # hàm đăng ký qua RegisterNatives thường là static, bị strip
                        self.add_funcs({fn: "JNI(RegisterNatives)" for _, _, fn in self._emu.natives})
                except Exception as e:  # pragma: no cover
                    self.reason = f"giả lập lỗi: {e}"
        return self._emu

    def emu_strings(self) -> list[tuple[str, int | None, str]]:
        """(chuỗi, địa chỉ, nguồn gốc) khôi phục bằng giả lập — không nằm sẵn trong file."""
        r = self.emu
        if not r:
            return []
        known = set(self.va_str.values())
        out = []
        for f, ss in r.stack_strings.items():
            out += [(x, f, "dựng trên stack") for x in ss]
        for f, a, imp, vals in r.cmp_calls + r.str_calls:
            out += [(v, a, f"đối số của {imp}()") for v in vals if v and v not in known]
        out += [(x, a, "giải mã khi nạp thư viện") for a, x in r.init_strings]
        out += [(x, f, "trả về Java qua NewStringUTF") for f, x in r.new_strings if x not in known]
        return out

    def builtin_cmp_const(self, ctx: int) -> list[Hit]:
        r = self.emu
        if not r:
            return []
        known = set(self.va_str.values())
        hits, seen = [], set()
        for f, a, imp, vals in r.cmp_calls:
            consts = [v for v in vals if v]
            if not consts or a is None or (a, tuple(consts)) in seen:
                continue
            seen.add((a, tuple(consts)))
            hidden = [v for v in consts if v not in known]
            shown = ", ".join(repr(v) for v in consts)
            note = (f"{imp}() so sánh với hằng {shown}"
                    + (" — chuỗi này KHÔNG nằm sẵn trong file (dựng trên stack / giải mã lúc chạy)" if hidden else ""))
            h = self.hit_at(a, f"{imp}(…, {shown})", ctx, conf="behavior" if hidden else "code", note=note, imp=imp)
            hits.append(h)
        hits.sort(key=lambda h: h.confidence != "behavior")
        return hits

    def builtin_stack_strings(self, ctx: int) -> list[Hit]:
        r = self.emu
        if not r:
            return []
        hits = []
        for f, ss in r.stack_strings.items():
            note = "Chuỗi được ghép từng byte / từng khối trên stack (không có trong .rodata):\n  " + \
                   "\n  ".join(repr(x) for x in ss[:15])
            hits.append(self.hit_at(f, ", ".join(repr(x) for x in ss[:3])[:150], ctx, conf="behavior", note=note))
        return hits

    def builtin_init_decrypt(self, ctx: int) -> list[Hit]:
        r = self.emu
        if not r or not r.init_strings:
            return []
        roots = [a for a, t in self.roots.items() if t in (".init_array", "JNI_OnLoad")]
        at = roots[0] if roots else self.fstarts[0]
        ss = [x for _, x in r.init_strings]
        note = ("Sau khi chạy .init_array / JNI_OnLoad (giả lập), các chuỗi sau xuất hiện trong .data/.bss:\n  "
                + "\n  ".join(f"0x{a:x}: {x!r}" for a, x in r.init_strings[:20]))
        return [self.hit_at(at, ", ".join(repr(x) for x in ss[:3])[:150], ctx, conf="behavior", note=note)]

    def builtin_register_natives(self, ctx: int) -> list[Hit]:
        r = self.emu
        if not r or not r.natives:
            return []
        hits = []
        for name, sig, fn in r.natives:
            hits.append(self.hit_at(fn, f"{name}{sig} → {self.fname(fn)}", ctx, conf="behavior",
                                    note=f"RegisterNatives (giả lập JNI_OnLoad): method Java '{name}{sig}' được nối "
                                         f"tới {self.name}!{self.fname(fn)} @ 0x{fn:x}"))
        return hits

    # ------------------------------------------------------------------ builtins
    def builtin_init_array(self, ctx: int) -> list[Hit]:
        out = []
        for a, tag in self.roots.items():
            if tag not in (".init_array", "JNI_OnLoad"):
                continue
            imps = self.reach_imports(a) if self.ok else []
            note = (f"Chạy TỰ ĐỘNG khi thư viện được nạp ({tag}), trước mọi hàm JNI. "
                    + ("Gọi tới: " + ", ".join(imps[:20]) if imps else ""))
            h = self.hit_at(a, f"{tag}: {self.fname(a)}", ctx, note=note) if self.ok else \
                Hit(self.rel, 0, f"{tag}: 0x{a:x}", engine="native", confidence="code", note=note, klass=self.name)
            out.append(h)
        return out

    def builtin_entropy(self, ctx: int) -> list[Hit]:
        out = []
        for s in self.sections:
            if s.size <= 1024:
                continue
            execu = bool(s.flags & 0x4)
            if not ((execu and s.entropy > 7.0) or (s.name not in STD_SECTIONS and s.entropy > 7.2)
                    or (s.name in (".rodata", ".data") and s.entropy > 7.6 and s.size > 65536)):
                continue
            out.append(Hit(self.rel, 0, f"{s.name or '<noname>'} entropy={s.entropy:.2f}", 1,
                           [f"section {s.name!r}  va=0x{s.virtual_address:x}  size={s.size}  entropy={s.entropy:.2f}"],
                           "asm", confidence="code", engine="native", klass=self.name,
                           note="Entropy gần 8 → dữ liệu nén / mã hóa (code bị pack, payload ẩn)."))
        return out

    def builtin_stripped(self, ctx: int) -> list[Hit]:
        if len(self.sections) <= 1:
            return [Hit(self.rel, 0, "Không có section header", engine="native", confidence="code",
                        klass=self.name, note="Section header bị xóa để làm hỏng IDA/Ghidra/readelf (anti-analysis).")]
        return []


ABI_PREF = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86")


def load_apk_libs(apk, outdir) -> list:
    """Giải nén lib/<abi>/*.so từ APK (mỗi tên lib lấy 1 ABI, ưu tiên arm64) -> [NativeLib]."""
    import zipfile
    from pathlib import Path
    best: dict = {}
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            parts = n.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so") and parts[1] in ABI_PREF:
                r = ABI_PREF.index(parts[1])
                if parts[2] not in best or r < best[parts[2]][0]:
                    best[parts[2]] = (r, n)
        libs = []
        for _, n in best.values():
            p = Path(z.extract(n, outdir))
            lib = NativeLib(ScanFile(n, "native", p))
            if getattr(lib, "b", None) is not None:
                libs.append(lib)
    return libs
