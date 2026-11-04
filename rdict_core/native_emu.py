"""Giả lập code native (unicorn) để lấy những gì không nằm sẵn trong file.

(A) chạy thật các hàm khởi tạo (.init_array, JNI_OnLoad) với import + JNIEnv giả:
    - so sánh .data/.bss trước/sau -> chuỗi được giải mã lúc nạp thư viện
    - RegisterNatives -> bảng method native đăng ký động (tên Java -> địa chỉ hàm)
(B) chạy TUYẾN TÍNH từng hàm: chạy từng đoạn lệnh, bỏ qua lệnh nhảy / gọi (không phụ thuộc nhánh):
    - đọc đối số chuỗi tại mỗi lời gọi strcmp/strncmp/memcmp/strstr/fopen/open/dlsym/...
    - quét stack sau khi chạy -> chuỗi dựng trên stack (stack string)
Hỗ trợ: arm64, x86_64.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

try:
    import unicorn as U
    from unicorn import arm64_const as A64
    from unicorn import x86_const as X86
    OK = True
except ImportError:  # pragma: no cover
    OK = False

BASE = 0x10000000
IMP_AREA = 0x70000000          # mỗi import 16 byte
JNI_AREA = 0x71000000          # hàm JNIEnv / JavaVM giả
HEAP = 0x60000000
HEAP_SZ = 0x400000
STACK = 0x7F000000
STACK_SZ = 0x100000
ENV = 0x72000000               # JNIEnv*, JavaVM*, bảng hàm, buffer
PAGE = 0x1000

# import có đối số chuỗi đáng ghi lại: tên -> chỉ số đối số là chuỗi
STR_ARGS = {
    "strcmp": (0, 1), "strncmp": (0, 1), "strcasecmp": (0, 1), "strncasecmp": (0, 1), "strstr": (0, 1),
    "strcasestr": (0, 1), "memcmp": (0, 1), "bcmp": (0, 1), "fopen": (0,), "open": (0,), "openat": (1,),
    "access": (0,), "stat": (0,), "lstat": (0,), "opendir": (0,), "readlink": (0,), "dlopen": (0,),
    "dlsym": (1,), "__system_property_get": (0,), "system": (0,), "popen": (0,), "execve": (0,),
    "execl": (0, 1), "execlp": (0, 1), "connect": (), "inet_addr": (0,), "gethostbyname": (0,),
    "getaddrinfo": (0,), "kill": (), "strchr": (0,), "strrchr": (0,), "sscanf": (0, 1), "fgets": (),
}
CMP = {"strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp", "strstr", "strcasestr"}
JNI_NAMES = {6: "FindClass", 33: "GetMethodID", 94: "GetFieldID", 113: "GetStaticMethodID", 144: "GetStaticFieldID",
             167: "NewStringUTF", 169: "GetStringUTFChars", 170: "ReleaseStringUTFChars", 171: "GetArrayLength",
             184: "GetByteArrayElements", 215: "RegisterNatives", 228: "ExceptionCheck"}
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


@dataclass
class EmuResult:
    cmp_calls: list = field(default_factory=list)      # (func, call_addr, import, [chuỗi])
    str_calls: list = field(default_factory=list)      # các import khác có đối số chuỗi
    stack_strings: dict = field(default_factory=dict)  # func -> [chuỗi]
    init_strings: list = field(default_factory=list)   # (địa chỉ, chuỗi) xuất hiện sau khi chạy init
    new_strings: list = field(default_factory=list)    # (func, chuỗi) truyền cho NewStringUTF
    natives: list = field(default_factory=list)        # (tên, chữ ký, địa chỉ hàm)
    errors: list = field(default_factory=list)


class Emu:
    def __init__(self, lib, max_funcs: int = 4000, insn_budget: int = 3_000_000):
        self.lib = lib
        self.b = lib.b
        self.arch = lib.arch
        self.res = EmuResult()
        self.max_funcs = max_funcs
        self.insn_budget = insn_budget
        self.imp_addr: dict[str, int] = {}
        self.imp_name: dict[int, str] = {}
        self.cur_func = None
        self.heap_ptr = HEAP
        if self.arch == "arm64":
            self.uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
            self.ARGS = [A64.UC_ARM64_REG_X0 + i for i in range(8)]
            self.RET = A64.UC_ARM64_REG_X0
            self.SP = A64.UC_ARM64_REG_SP
            self.LR = A64.UC_ARM64_REG_X30
            self.PC = A64.UC_ARM64_REG_PC
        elif self.arch == "x86_64":
            self.uc = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
            self.ARGS = [X86.UC_X86_REG_RDI, X86.UC_X86_REG_RSI, X86.UC_X86_REG_RDX,
                         X86.UC_X86_REG_RCX, X86.UC_X86_REG_R8, X86.UC_X86_REG_R9]
            self.RET = X86.UC_X86_REG_RAX
            self.SP = X86.UC_X86_REG_RSP
            self.PC = X86.UC_X86_REG_RIP
        else:
            raise ValueError(f"chưa hỗ trợ giả lập {self.arch}")
        self._load()

    # ------------------------------------------------------------------ memory
    def _map(self, lo, hi):
        lo &= ~(PAGE - 1)
        hi = (hi + PAGE - 1) & ~(PAGE - 1)
        for a in range(lo, hi, PAGE):
            try:
                self.uc.mem_map(a, PAGE)
            except U.UcError:
                pass

    def _load(self):
        uc, b = self.uc, self.b
        for seg in b.segments:
            if seg.type.name != "LOAD" if hasattr(seg.type, "name") else int(seg.type) != 1:
                continue
            va = seg.virtual_address + BASE
            self._map(va, va + max(seg.virtual_size, 1))
            data = bytes(seg.content)
            if data:
                uc.mem_write(va, data)
        self.writable = [(s.virtual_address + BASE, s.virtual_address + BASE + s.size) for s in b.sections
                         if s.name in (".data", ".bss") and s.size]
        uc.mem_map(IMP_AREA, 0x100000)
        uc.mem_map(JNI_AREA, 0x10000)
        uc.mem_map(HEAP, HEAP_SZ)
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(ENV, 0x20000)
        ret = b"\xc0\x03\x5f\xd6" if self.arch == "arm64" else b"\xc3"
        uc.mem_write(IMP_AREA, ret * (0x100000 // len(ret)))
        uc.mem_write(JNI_AREA, ret * (0x10000 // len(ret)))
        # JNIEnv: *env = bảng hàm; JavaVM tương tự
        tbl = ENV + 0x1000
        uc.mem_write(ENV, struct.pack("<Q", tbl))
        uc.mem_write(tbl, b"".join(struct.pack("<Q", JNI_AREA + i * 16) for i in range(300)))
        vtbl = ENV + 0x3000
        uc.mem_write(ENV + 0x2000, struct.pack("<Q", vtbl))     # JavaVM*
        uc.mem_write(vtbl, b"".join(struct.pack("<Q", JNI_AREA + 0x8000 + i * 16) for i in range(10)))
        # relocation: RELATIVE + import -> vùng import giả
        for i, name in enumerate(sorted({r.symbol.name for r in b.relocations if r.has_symbol and r.symbol.name})):
            self.imp_addr[name] = IMP_AREA + i * 16
            self.imp_name[IMP_AREA + i * 16] = name
        for r in b.relocations:
            try:
                addr = r.address + BASE
                t = r.type.name if hasattr(r.type, "name") else str(r.type)
                if "RELATIVE" in t:
                    uc.mem_write(addr, struct.pack("<Q", (r.addend + BASE) & 0xFFFFFFFFFFFFFFFF))
                elif r.has_symbol and r.symbol.name:
                    sym = r.symbol
                    if sym.value:   # symbol nội bộ
                        uc.mem_write(addr, struct.pack("<Q", sym.value + BASE + r.addend))
                    elif sym.name in self.imp_addr:
                        uc.mem_write(addr, struct.pack("<Q", self.imp_addr[sym.name]))
            except Exception:
                continue
        # PLT stub -> import (lệnh bl tới stub)
        self.stub_name = {a + BASE: n for a, n in self.lib.stubs.items()}
        uc.hook_add(U.UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        uc.hook_add(U.UC_HOOK_CODE, self._on_import, begin=IMP_AREA, end=IMP_AREA + 0x100000)
        uc.hook_add(U.UC_HOOK_CODE, self._on_jni, begin=JNI_AREA, end=JNI_AREA + 0x10000)

    def _on_unmapped(self, uc, access, addr, size, value, _):
        if addr < 0x1000:
            return False
        try:
            uc.mem_map(addr & ~(PAGE - 1), PAGE)
            return True
        except U.UcError:
            return False

    def rd(self, a, n):
        try:
            return bytes(self.uc.mem_read(a, n))
        except U.UcError:
            return b""

    def cstr(self, a, n=256) -> str | None:
        if not a or a < 0x1000:
            return None
        d = self.rd(a, n)
        if not d:
            return None
        d = d.split(b"\0", 1)[0]
        if len(d) < 2 or sum(32 <= c < 127 for c in d) < len(d) * 0.9:
            return None
        return d.decode("latin-1")

    def arg(self, i):
        if i < len(self.ARGS):
            return self.uc.reg_read(self.ARGS[i])
        return 0

    def setret(self, v):
        self.uc.reg_write(self.RET, v & 0xFFFFFFFFFFFFFFFF)

    def alloc(self, n):
        n = (max(n, 16) + 15) & ~15
        if self.heap_ptr + n > HEAP + HEAP_SZ:
            self.heap_ptr = HEAP
        p = self.heap_ptr
        self.heap_ptr += n
        return p

    # ------------------------------------------------------------------ import / JNI giả
    def _import(self, name: str, call_addr: int | None):
        """Thực hiện import (đơn giản) + ghi lại đối số chuỗi. Không đổi PC (caller lo phần trả về)."""
        idx = STR_ARGS.get(name)
        if idx:
            vals = [self.cstr(self.arg(i)) for i in idx]
            if any(vals):
                rec = (self.cur_func, call_addr, name, vals)
                (self.res.cmp_calls if name in CMP else self.res.str_calls).append(rec)
        r = 0
        try:
            if name in ("malloc", "operator new", "_Znwm", "_Znam"):
                r = self.alloc(self.arg(0) & 0xFFFFF)
            elif name == "calloc":
                r = self.alloc((self.arg(0) * self.arg(1)) & 0xFFFFF)
            elif name == "strlen":
                s = self.rd(self.arg(0), 4096)
                r = s.index(b"\0") if b"\0" in s else 0
            elif name in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk"):
                n = self.arg(2) & 0xFFFFF
                self.uc.mem_write(self.arg(0), self.rd(self.arg(1), n))
                r = self.arg(0)
            elif name in ("memset", "__memset_chk"):
                self.uc.mem_write(self.arg(0), bytes([self.arg(1) & 0xFF]) * (self.arg(2) & 0xFFFFF))
                r = self.arg(0)
            elif name in ("strcpy", "__strcpy_chk", "strcat", "__strcat_chk"):
                s = self.rd(self.arg(1), 4096).split(b"\0", 1)[0] + b"\0"
                dst = self.arg(0)
                if name.startswith(("strcat", "__strcat")):
                    d = self.rd(dst, 4096)
                    dst += d.index(b"\0") if b"\0" in d else 0
                self.uc.mem_write(dst, s)
                r = self.arg(0)
            elif name in ("strncpy", "__strncpy_chk"):
                n = self.arg(2) & 0xFFFF
                s = self.rd(self.arg(1), n).split(b"\0", 1)[0]
                self.uc.mem_write(self.arg(0), s + b"\0" * (n - len(s)))
                r = self.arg(0)
            elif name in ("strdup",):
                s = self.rd(self.arg(0), 4096).split(b"\0", 1)[0] + b"\0"
                r = self.alloc(len(s))
                self.uc.mem_write(r, s)
            elif name in ("getpid", "getppid", "gettid"):
                r = 1234
        except U.UcError:
            r = 0
        self.setret(r)

    def _jni(self, idx: int):
        name = JNI_NAMES.get(idx, "")
        r = 1
        if idx >= 0x800:                # JavaVM: GetEnv / AttachCurrentThread -> *penv = env
            vi = idx - 0x800
            if vi in (4, 6, 7):
                try:
                    self.uc.mem_write(self.arg(1), struct.pack("<Q", ENV))
                except U.UcError:
                    pass
                r = 0
        elif name == "NewStringUTF":
            s = self.cstr(self.arg(1), 1024)
            if s:
                self.res.new_strings.append((self.cur_func, s))
        elif name == "GetStringUTFChars" or name == "GetByteArrayElements":
            r = self.alloc(64)
        elif name == "GetArrayLength":
            r = 0
        elif name == "RegisterNatives":
            arr, n = self.arg(2), self.arg(3) & 0xFFFF
            for i in range(min(n, 200)):
                e = self.rd(arr + i * 24, 24)
                if len(e) < 24:
                    break
                pn, ps, fp = struct.unpack("<QQQ", e)
                nm, sg = self.cstr(pn), self.cstr(ps)
                if nm:
                    self.res.natives.append((nm, sg or "", (fp - BASE) & ~1 if fp >= BASE else fp))
            r = 0
        elif name in ("ExceptionCheck",):
            r = 0
        self.setret(r)

    def _ret_from_hook(self):
        if self.arch == "arm64":
            self.uc.reg_write(self.PC, self.uc.reg_read(self.LR))
        else:
            sp = self.uc.reg_read(self.SP)
            ra = struct.unpack("<Q", self.rd(sp, 8) or b"\0" * 8)[0]
            self.uc.reg_write(self.SP, sp + 8)
            self.uc.reg_write(self.PC, ra)

    def _on_import(self, uc, addr, size, _):
        name = self.imp_name.get(addr & ~0xF)
        if name in ("abort", "exit", "_exit", "__stack_chk_fail", "pthread_exit", "raise", "kill") and self.mode == "run":
            uc.emu_stop()
            return
        self._import(name or "?", self._last_call)
        self._ret_from_hook()

    def _on_jni(self, uc, addr, size, _):
        self._jni((addr - JNI_AREA) // 16 if addr < JNI_AREA + 0x8000 else 0x800 + (addr - JNI_AREA - 0x8000) // 16)
        self._ret_from_hook()

    # ------------------------------------------------------------------ (A) chạy init
    def run_init(self):
        self.mode = "run"
        self._last_call = None
        before = {lo: self.rd(lo, hi - lo) for lo, hi in self.writable}
        roots = [(a, t) for a, t in self.lib.roots.items() if t in (".init_array", "JNI_OnLoad")]
        roots.sort(key=lambda x: x[1] != ".init_array")
        for a, tag in roots:
            self.cur_func = a
            self._call(a + BASE, [ENV + 0x2000, 0] if tag == "JNI_OnLoad" else [0, 0, 0])
        known = set(self.lib.va_str.values())
        for lo, hi in self.writable:
            after = self.rd(lo, hi - lo)
            old = before.get(lo, b"")
            for m in PRINTABLE.finditer(after):
                s = m.group().decode()
                if old[m.start():m.end()] != m.group() and s not in known and len(s.strip()) >= 4:
                    self.res.init_strings.append((lo + m.start() - BASE, s))

    def _call(self, addr, args):
        uc = self.uc
        sp = STACK + STACK_SZ - 0x1000
        for i, v in enumerate(args):
            uc.reg_write(self.ARGS[i], v)
        if self.arch == "arm64":
            uc.reg_write(self.LR, IMP_AREA + 0xFFFF0)     # trả về -> dừng
            uc.reg_write(self.SP, sp)
            end = IMP_AREA + 0xFFFF0
        else:
            sp -= 8
            uc.mem_write(sp, struct.pack("<Q", IMP_AREA + 0xFFFF0))
            uc.reg_write(self.SP, sp)
            end = IMP_AREA + 0xFFFF0
        self.imp_name[IMP_AREA + 0xFFFF0] = "abort"
        try:
            uc.emu_start(addr, end, timeout=3_000_000, count=self.insn_budget)
        except U.UcError as e:
            self.res.errors.append(f"{self.lib.fname(addr - BASE)}: {e}")

    # ------------------------------------------------------------------ (B) chạy tuyến tính
    def sweep(self):
        self.mode = "sweep"
        lib = self.lib
        starts = lib.fstarts
        by_func: dict[int, list] = {}
        for ins in lib.insns:
            f = lib.func_of(ins[0])
            if f is not None:
                by_func.setdefault(f, []).append(ins)
        # ưu tiên hàm có gọi import so sánh / JNI / root
        def score(f):
            cs = lib.callees.get(f, ())
            return (-(f in lib.roots), -sum(1 for c in cs if isinstance(c, str) and c[4:] in STR_ARGS))
        funcs = sorted(by_func, key=score)[: self.max_funcs]
        known = set(lib.va_str.values())
        for f in funcs:
            ins = by_func[f]
            if len(ins) > 6000:
                continue
            self.cur_func = f
            self._sweep_func(f, ins, known)

    def _sweep_func(self, f, insns, known):
        uc = self.uc
        top = STACK + STACK_SZ - 0x1000
        uc.mem_write(top - 0x8000, b"\0" * 0x8100)
        for i, r in enumerate(self.ARGS):
            uc.reg_write(r, ENV if i == 0 and f in self.lib.roots else self.alloc(256))
        uc.reg_write(self.SP, top)
        if self.arch == "arm64":
            for r in range(A64.UC_ARM64_REG_X8, A64.UC_ARM64_REG_X28 + 1):
                uc.reg_write(r, 0)
        is_cf = self._is_cf
        seg_start = None
        budget = 20000
        min_sp = top
        for a, s, mn, op in insns:
            if is_cf(mn):
                if seg_start is not None and seg_start < a:
                    budget -= self._run_seg(seg_start + BASE, a + BASE)
                seg_start = None
                self._handle_cf(a, s, mn, op)
                min_sp = min(min_sp, uc.reg_read(self.SP))
                if budget <= 0:
                    break
                continue
            if seg_start is None:
                seg_start = a
        if seg_start is not None:
            self._run_seg(seg_start + BASE, insns[-1][0] + insns[-1][1] + BASE)
        min_sp = min(min_sp, uc.reg_read(self.SP))
        lo = max(STACK, min(min_sp, top) - 0x100)
        data = self.rd(lo, top + 0x100 - lo)
        out = []
        for m in PRINTABLE.finditer(data):
            s = m.group().decode()
            if s not in known and len(s) >= 5 and not re.fullmatch(r"(.)\1+", s):
                out.append(s)
        if out:
            self.res.stack_strings[f] = list(dict.fromkeys(out))

    def _is_cf(self, mn: str) -> bool:
        if self.arch == "arm64":
            return mn in ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "braa", "blraa",
                          "retaa", "eret") or mn.startswith("b.")
        return mn in ("call", "ret", "jmp", "retn") or (mn.startswith("j") and mn != "jmp" and len(mn) <= 5)

    def _run_seg(self, a, b) -> int:
        try:
            self.uc.emu_start(a, b, timeout=200_000, count=5000)
        except U.UcError:
            pass
        return (b - a) // 4 + 1

    def _handle_cf(self, a, s, mn, op):
        """Lệnh điều khiển trong chế độ tuyến tính: gọi import -> giả lập; còn lại bỏ qua."""
        if mn not in ("bl", "blr", "call", "blraa"):
            return
        self._last_call = a
        tgt = None
        if (m := re.match(r"#?(0x[0-9a-f]+)$", op)):
            tgt = int(m.group(1), 16) + BASE
        elif self.arch == "arm64" and re.match(r"x\d+$", op):
            tgt = self.uc.reg_read(A64.UC_ARM64_REG_X0 + int(op[1:])) if int(op[1:]) <= 28 else None
        elif self.arch == "x86_64" and (m := re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", op)):
            p = a + s + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
            tgt = struct.unpack("<Q", self.rd(p + BASE, 8) or b"\0" * 8)[0]
        name = None
        if tgt is not None:
            name = self.stub_name.get(tgt) or self.imp_name.get(tgt & ~0xF)
            if name is None and JNI_AREA <= tgt < JNI_AREA + 0x10000:
                self._jni((tgt - JNI_AREA) // 16)
                return
        if name:
            self._import(name, a)
        else:
            self.setret(0)


def emulate(lib, do_init=True, do_sweep=True) -> EmuResult | None:
    if not OK or lib.arch not in ("arm64", "x86_64") or not getattr(lib, "ok", False):
        return None
    try:
        e = Emu(lib)
    except Exception as ex:  # pragma: no cover
        r = EmuResult()
        r.errors.append(str(ex))
        return r
    if do_init:
        try:
            e.run_init()
        except Exception as ex:
            e.res.errors.append(f"init: {ex}")
    if do_sweep:
        try:
            e.sweep()
        except Exception as ex:
            e.res.errors.append(f"sweep: {ex}")
    return e.res
