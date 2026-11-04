"""Engine phân tích bytecode Dalvik (androguard).

Khác với regex trên source:
  * khớp trên lệnh thật: invoke-*, const-string, sget/iget -> không bị comment / format / tên biến đánh lừa
  * API framework (android.*, java.*) không thể bị obfuscate -> bắt được cả app đã ProGuard
  * có call graph: biết ai gọi, đường gọi từ entry point (Activity/Service/...)
  * combo: nhiều API trong cùng luồng gọi = một hành vi (độ tin cậy cao nhất)
  * theo dõi hằng string trong thanh ghi -> giải được đích của reflection, tìm hàm giải mã string
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

from loguru import logger

logger.remove()
from androguard.misc import AnalyzeAPK, AnalyzeDex  # noqa: E402

from .model import Hit, Rule  # noqa: E402
from .text_engine import LIB_PREFIXES, ScanFile, frida_hook  # noqa: E402

INVOKE_OPS = set(range(0x6E, 0x73)) | set(range(0x74, 0x79)) | {0xFA, 0xFB}
STRING_OPS = {0x1A, 0x1B}
FIELD_GET = set(range(0x52, 0x59)) | set(range(0x60, 0x67))
FIELD_OPS = set(range(0x52, 0x6E))
MOVE_OBJ = {0x07, 0x08, 0x09}
CONST_OPS = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}
MOVE_RESULT_OBJ = 0x0C
STATIC_INVOKE = {0x71, 0x77}
FRAMEWORK = ("Ljava/", "Ljavax/", "Landroid/", "Landroidx/", "Lkotlin/", "Ldalvik/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/")
DEC_PARAMS = {"Ljava/lang/String;", "I", "J", "S", "B", "C"}
NO_WRITE = ({0x00, 0x0E, 0x0F, 0x10, 0x11, 0x1D, 0x1E, 0x1F, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C}
            | set(range(0x32, 0x3E)) | set(range(0x4B, 0x52)) | INVOKE_OPS | (FIELD_OPS - FIELD_GET))

REFLECT_APIS = {
    "Ljava/lang/Class;->forName": "Class.forName",
    "Ljava/lang/ClassLoader;->loadClass": "loadClass",
    "Ljava/lang/Class;->getMethod": "getMethod",
    "Ljava/lang/Class;->getDeclaredMethod": "getDeclaredMethod",
    "Ljava/lang/Class;->getField": "getField",
    "Ljava/lang/Class;->getDeclaredField": "getDeclaredField",
}
SENSITIVE_REFLECT = re.compile(
    r"exec|Runtime|ProcessBuilder|sendTextMessage|SmsManager|getDeviceId|getImei|getSubscriberId|"
    r"DexClassLoader|loadDex|DexFile|InMemoryDexClassLoader|getInstalledPackages|setComponentEnabledSetting|"
    r"ptrace|TelephonyManager|getLine1Number|AccessibilityService|getRunningAppProcesses|"
    r"isDebuggerConnected|ActivityThread|currentApplication|getSignatures|signatures", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    n = len(s)
    return -sum(c / n * log2(c / n) for c in (s.count(ch) for ch in set(s)))


def looks_encoded(s: str) -> bool:
    """Chuỗi trông như ciphertext / dữ liệu mã hóa thay vì chữ đọc được."""
    if len(s) < 4:
        return False
    odd = sum(1 for ch in s if not (ch.isascii() and ch.isprintable()))
    if odd / len(s) > 0.2:
        return True
    words = re.fullmatch(r"[A-Za-z][a-z]*(?:[ _\-.:/][A-Za-z0-9][a-z0-9]*)*[.!?]?", s)
    return not words and len(s) >= 8 and entropy(s) >= 3.5


class DecRef:
    """Giá trị trả về của một lời gọi hàm (có thể là hàm giải mã) với tham số hằng. Giải được sau khi có
    bảng chuỗi đã giải mã (Frida)."""
    __slots__ = ("sig", "args")

    def __init__(self, sig: str, args: tuple):
        self.sig, self.args = sig, args

    def __repr__(self):
        return f"{pretty_sig(self.sig).split('(')[0]}(…)"


def sig_params(sig: str) -> list[str]:
    inner = sig[sig.index("(") + 1: sig.rindex(")")]
    return re.findall(r"\[*(?:L[^;]+;|[ZBSCIJFD])", inner.replace(" ", ""))


_PASS = re.compile(r"^(?=.*[0-9_!@#$%^&*+=-])[^\s/.:]{4,40}$")


def crypto_label(s: str) -> bool:
    """Hằng nào đáng gắn nhãn để engine lần xem nó có đi vào SecretKeySpec / Cipher.doFinal không."""
    if not 4 <= len(s) <= 4096:
        return False
    from . import crypto_solver as cs
    return bool(cs.ct_candidates(s) or cs.key_candidates(s, derive=False) or _PASS.match(s))


def cls_dot(desc: str) -> str:
    return desc[1:-1].replace("/", ".") if desc.startswith("L") and desc.endswith(";") else desc


def pretty_sig(sig: str) -> str:
    """Landroid/os/Debug;->isDebuggerConnected()Z  ->  android.os.Debug.isDebuggerConnected()"""
    m = re.match(r"(L[^;]+;)->([^(\s]+)(\(.*?\))?", sig)
    if not m:
        return sig
    args = ""
    if m.group(3):
        parts = [cls_dot(a).split(".")[-1] if a.startswith("L") else a for a in m.group(3)[1:-1].split()]
        args = ", ".join(parts)
    return f"{cls_dot(m.group(1))}.{m.group(2)}({args})" if m.group(3) is not None else f"{cls_dot(m.group(1))}.{m.group(2)}"


def needle_of(kind: str, key: str) -> str:
    if kind == "api":
        n = key.split("->", 1)[1].split("(", 1)[0]
        return (key.split("->")[0].rsplit("/", 1)[-1].rstrip(";").split("$")[-1] if n == "<init>" else n) + "("
    if kind == "field":
        return key.split("->", 1)[1].split(" ", 1)[0]
    return key[:40]


# hàm libc mà dữ liệu đi vào là "thoát ra ngoài" (mạng / file / log / lệnh hệ thống)
NATIVE_SINK_IMPS = {"send", "sendto", "sendmsg", "write", "writev", "pwrite", "fwrite", "fputs", "fprintf", "dprintf",
                    "__android_log_print", "__android_log_write", "__android_log_vprint", "__android_log_buf_write",
                    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
                    "fopen", "open", "openat", "creat"}


DEX_MAGIC = b"dex\n"
ZIP_MAGIC = b"PK\x03\x04"
MAX_PAYLOAD = 64 * 1024 * 1024


def _xor1(data: bytes, magic: bytes) -> int | None:
    """Key XOR 1 byte nếu data là magic bị XOR (payload mã hóa đơn giản), không thì None."""
    if len(data) < 16:
        return None
    k = data[0] ^ magic[0]
    if k and all(data[i] ^ k == magic[i] for i in range(len(magic))):
        return k
    return None


def find_payloads(files: dict, depth: int = 2) -> list[tuple[str, str, bytes]]:
    """Tìm DEX ẩn: files = {tên: bytes}. -> [(đường dẫn, cách tìm ra, bytes dex)].
    Nhận theo magic (không theo đuôi file): dex trần, zip/jar/apk chứa dex, hoặc dex/zip bị XOR 1 byte."""
    import io
    import zipfile
    out = []
    for name, data in files.items():
        if not data or len(data) > MAX_PAYLOAD:
            continue
        how = None
        k = None
        if data[:4] != DEX_MAGIC and data[:4] != ZIP_MAGIC:
            for mg in (DEX_MAGIC, ZIP_MAGIC):
                if (k := _xor1(data, mg)) is not None:
                    data = bytes(b ^ k for b in data)
                    how = f"giải XOR 1 byte (key 0x{k:02x})"
                    break
        if data[:4] == DEX_MAGIC and data[4:7].isdigit():
            out.append((name, how or "magic DEX", data))
        elif data[:4] == ZIP_MAGIC and depth > 0:
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
                inner = {n: z.read(n) for n in z.namelist()
                         if not n.endswith("/") and z.getinfo(n).file_size <= MAX_PAYLOAD
                         and (n.endswith((".dex", ".jar", ".apk", ".zip")) or z.getinfo(n).file_size > 1024)}
            except Exception:
                continue
            for n2, h2, d2 in find_payloads(inner, depth - 1):
                out.append((f"{name}!{n2}", ", ".join(x for x in (how, "trong zip", h2) if x), d2))
    return out


def jni_mangle(s: str) -> str:
    out = []
    for ch in s:
        if ch == "/":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch.isascii() and ch.isalnum():
            out.append(ch)
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


class DexEngine:
    def __init__(self, path: Path, sources_root: Path | None, include_libs: bool = False):
        self.payloads: list[dict] = []                     # DEX ẩn trong APK (assets/res/...) đã nạp chung
        self.payload_of: dict[str, str] = {}               # class -> payload chứa nó
        if path.suffix.lower() == ".dex":
            _, _, self.dx = AnalyzeDex(str(path))
            self.apk = None
        else:
            self.apk, self.dx = self._load_apk(path)
        self.sources_root = sources_root
        self.include_libs = include_libs
        self.flow_libs = False          # phân tích luồng cả code thư viện (--flow-libs)
        self.flow_budget = 180.0
        self.flow_rounds = 16
        self.inv: dict[str, list] = defaultdict(list)      # sig -> [(ma, off)]
        self.strs: dict[str, list] = defaultdict(list)     # string -> [(ma, off)]
        self.flds: dict[str, list] = defaultdict(list)     # field -> [(ma, off)]
        self.fld_r: dict[str, set] = defaultdict(set)      # "tên kiểu" field -> method đọc (để cắt lát theo field)
        self.fld_w: dict[str, set] = defaultdict(set)      # "tên kiểu" field -> method ghi
        self.reflect: list[tuple] = []                     # (ma, off, api, value|None)
        self.str_arg_calls: dict[str, list] = defaultdict(list)  # callee -> [(ma, off, str)]
        self.static_calls: dict[str, list] = defaultdict(list)   # sig -> [(ma, off, args)] (tham số đều là hằng)
        self.decrypted: dict[tuple, str] = {}                     # (sig, args) -> chuỗi gốc
        self.dec_sites: dict[tuple, tuple] = {}                   # (ma, off) -> (sig, args, chuỗi gốc)
        self._decryptors: list | None = None
        self.native_methods: list = []
        self.internal_classes: set[str] = set()
        self.n_methods = 0
        self._src_cache: dict[str, ScanFile | None] = {}
        self._inits: dict[str, list] = defaultdict(list)
        self.entry_classes = self._entries()
        self._build()

    def _load_apk(self, path: Path):
        """Như AnalyzeAPK, nhưng nạp thêm DEX ẩn (payload dropper / packer) vào cùng Analysis để call graph,
        CHA, reflection và taint đi xuyên qua code được nạp động."""
        from androguard.core import apk as _apk, dex as _dex
        from androguard.core.analysis.analysis import Analysis
        a = _apk.APK(str(path))
        dx = Analysis()
        main = set()
        for b in a.get_all_dex():
            df = _dex.DEX(b, using_api=a.get_target_sdk_version())
            dx.add(df)
            main.update(c.get_name() for c in df.get_classes())
        import zipfile
        root_dex = re.compile(r"^classes\d*\.dex$")
        files = {}
        try:                                     # chỉ đọc 8 byte đầu mỗi file; không xét đuôi (payload hay đội lốt .png)
            with zipfile.ZipFile(str(path)) as z:
                for zi in z.infolist():
                    n = zi.filename
                    if zi.is_dir() or root_dex.match(n) or n.startswith("META-INF/") or zi.file_size < 64 \
                            or zi.file_size > MAX_PAYLOAD or (n.startswith("lib/") and n.endswith(".so")):
                        continue
                    with z.open(zi) as f:
                        head = f.read(8)
                    if head[:4] in (DEX_MAGIC, ZIP_MAGIC) or _xor1(head + b"\0" * 8, DEX_MAGIC) is not None \
                            or _xor1(head + b"\0" * 8, ZIP_MAGIC) is not None:
                        files[n] = z.read(zi)
        except Exception as e:
            logger.debug(f"quét payload: {e}")
        for name, how, data in find_payloads(files):
            try:
                df = _dex.DEX(data, using_api=a.get_target_sdk_version())
            except Exception as e:
                logger.debug(f"payload {name}: {e}")
                continue
            cls = [c.get_name() for c in df.get_classes() if c.get_name() not in main]
            if not cls:
                continue
            dx.add(df)
            for c in cls:
                self.payload_of.setdefault(c, name)
            self.payloads.append({"name": name, "how": how, "size": len(data), "classes": cls})
        dx.create_xref()
        return a, dx

    # ------------------------------------------------------------------ index
    def is_lib(self, cls: str) -> bool:
        return cls[1:].startswith(LIB_PREFIXES)

    def _entries(self) -> set[str]:
        if not self.apk:
            return set()
        names = set()
        a = self.apk
        for getter in (a.get_activities, a.get_services, a.get_receivers, a.get_providers):
            names.update(getter() or [])
        try:   # component bị tắt (android:enabled="false") không bao giờ chạy
            ns = "{http://schemas.android.com/apk/res/android}"
            for el in a.get_android_manifest_xml().iter():
                if el.get(ns + "enabled") == "false" and el.get(ns + "name"):
                    names.discard(el.get(ns + "name"))
        except Exception:
            pass
        app = a.get_attribute_value("application", "name")
        if app:
            names.add(app)
        pkg = a.get_package()
        out = set()
        for n in names:
            if n.startswith("."):
                n = pkg + n
            elif "." not in n:
                n = f"{pkg}.{n}"
            out.add("L" + n.replace(".", "/") + ";")
        return out

    def _build(self) -> None:
        for ma in self.dx.get_methods():
            if ma.is_external():
                continue
            cls = ma.class_name
            self.internal_classes.add(cls)
            if ma.name == "<init>":
                self._inits[cls].append(ma)
            if not self.include_libs and self.is_lib(cls):
                continue
            em = ma.get_method()
            if em.get_access_flags() & 0x100:
                self.native_methods.append(ma)
            if em.get_code() is None:
                continue
            self.n_methods += 1
            regs: dict[str, object] = {}      # thanh ghi -> str | DecRef
            ints: dict[str, int] = {}
            last_class = None
            pending: DecRef | None = None
            off = 0
            for ins in em.get_instructions():
                op = ins.get_op_value()
                res, pending = pending, None
                try:
                    if op in STRING_OPS:
                        s = ins.get_translated_kind()
                        reg = ins.get_output().split(",", 1)[0]
                        regs[reg] = s
                        ints.pop(reg, None)
                        self.strs[s].append((ma, off))
                    elif op in CONST_OPS:
                        reg = ins.get_output().split(",", 1)[0]
                        lit = (ins.get_literals() or [None])[0]
                        regs.pop(reg, None)
                        if lit is None:
                            ints.pop(reg, None)
                        else:
                            ints[reg] = lit << 16 if op == 0x15 and abs(lit) < 0x10000 else lit
                    elif op == MOVE_RESULT_OBJ:
                        reg = ins.get_output().strip()
                        ints.pop(reg, None)
                        if res is not None:
                            regs[reg] = res
                        else:
                            regs.pop(reg, None)
                    elif op in INVOKE_OPS:
                        sig = ins.get_translated_kind()
                        self.inv[sig].append((ma, off))
                        out = ins.get_output()
                        args = self._regs(out)
                        vals = [regs.get(r) for r in args]
                        sargs = [v for v in vals if v is not None]
                        base = sig.split("(", 1)[0]
                        if base in REFLECT_APIS:
                            api = REFLECT_APIS[base]
                            val = sargs[0] if sargs else None
                            if api in ("Class.forName", "loadClass"):
                                last_class = val
                                parts = (val,)
                            else:
                                parts = (last_class, val) if val is not None and last_class is not None else (val,)
                            self.reflect.append((ma, off, api, parts))
                        else:
                            s0 = next((v for v in vals if isinstance(v, str)), None)
                            if s0 is not None:
                                self.str_arg_calls[sig].append((ma, off, s0))
                            if op in STATIC_INVOKE and sig.endswith(")Ljava/lang/String;") and not sig.startswith(FRAMEWORK):
                                cargs = self._const_args(sig, args, regs, ints)
                                if cargs is not None:
                                    self.static_calls[sig].append((ma, off, cargs))
                                    pending = DecRef(sig, cargs)
                    elif op in FIELD_OPS:
                        fk = ins.get_translated_kind()
                        self.flds[fk].append((ma, off))
                        (self.fld_r if op in FIELD_GET else self.fld_w)[fk.split("->", 1)[1]].add(ma)
                        if op in FIELD_GET:
                            reg = ins.get_output().split(",", 1)[0]
                            regs.pop(reg, None)
                            ints.pop(reg, None)
                    elif op in MOVE_OBJ:
                        d, s = [x.strip() for x in ins.get_output().split(",")[:2]]
                        if s in regs:
                            regs[d] = regs[s]
                        else:
                            regs.pop(d, None)
                    elif op not in NO_WRITE:
                        reg = ins.get_output().split(",", 1)[0]
                        regs.pop(reg, None)
                        ints.pop(reg, None)
                except Exception:
                    pass
                off += ins.get_length()

    @staticmethod
    def _const_args(sig: str, regs_used: list[str], regs: dict, ints: dict) -> tuple | None:
        """Giá trị hằng của từng tham số (invoke-static). None nếu có tham số không phải hằng."""
        params = sig_params(sig)
        if not params or any(p not in DEC_PARAMS for p in params):
            return None
        vals, i = [], 0
        for p in params:
            if i >= len(regs_used):
                return None
            r = regs_used[i]
            if p == "Ljava/lang/String;":
                v = regs.get(r)
                if not isinstance(v, str):
                    return None
            else:
                v = ints.get(r)
                if v is None:
                    return None
            vals.append(v)
            i += 2 if p == "J" else 1
        return tuple(vals)

    @staticmethod
    def _regs(out: str) -> list[str]:
        head = re.split(r",\s*(?=[L\[])", out, maxsplit=1)[0]
        if "..." in head:
            a, b = [int(x.strip()[1:]) for x in head.split("...")]
            return [f"v{i}" for i in range(a, b + 1)]
        return [x.strip() for x in head.split(",") if x.strip().startswith(("v", "p"))]

    # ------------------------------------------------------------------ chuỗi đã giải mã
    def resolve(self, v):
        """str -> str; DecRef -> chuỗi đã giải (hoặc None nếu chưa giải)."""
        if isinstance(v, DecRef):
            return self.decrypted.get((v.sig, v.args))
        return v

    def apply_decrypted(self, mapping: dict[tuple, str]) -> int:
        """Nạp bảng (sig, args) -> plaintext: chuỗi gốc được đưa vào index như một const-string tại
        chỗ gọi hàm giải mã, nên mọi rule strings:/str: và reflection đều khớp được."""
        self.decrypted.update(mapping)
        n = 0
        for sig, calls in self.static_calls.items():
            for ma, off, args in calls:
                plain = mapping.get((sig, args))
                if plain is None or (ma, off) in self.dec_sites:
                    continue
                self.strs[plain].append((ma, off))
                self.dec_sites[(ma, off)] = (sig, args, plain)
                n += 1
        return n

    def dec_note(self, ma, off) -> str | None:
        d = self.dec_sites.get((ma, off))
        if not d:
            return None
        sig, args, plain = d
        a = ", ".join(repr(x)[:50] for x in args)
        return f"🔓 Chuỗi đã giải mã: {pretty_sig(sig).split('(')[0]}({a}) → {plain!r}"

    def site_needle(self, kind: str, key: str, ma, off) -> str:
        d = self.dec_sites.get((ma, off)) if kind == "str" else None
        if d:
            s0 = next((a for a in d[1] if isinstance(a, str)), "")
            if len(s0) >= 6 and all(c.isascii() and c.isprintable() and c not in '"\\' for c in s0[:16]):
                return '"' + s0[:16]          # jadx in nguyên ciphertext -> trỏ đúng dòng
            cls, name = d[0].split("(")[0].split("->")
            if cls == ma.class_name:
                return name + "("
            return cls[1:-1].rsplit("/", 1)[-1].split("$")[-1] + "." + name + "("
        return needle_of(kind, key)

    # ------------------------------------------------------------------ call graph
    def _preds(self, ma):
        if self.flow_libs or not self.is_lib(ma.class_name):
            # CHA: gọi qua interface/kế thừa, callback (tạo object), reflection đã giải
            cha = self.cha
            if ma.class_name in cha.internal:
                lab = {"call": "", "new": "new", "reflect": "reflect"}
                res = [(m, lab.get(k, "")) for m, k in cha.preds(ma)]
                seen = {m for m, _ in res}
                res += [(m, "") for _, m, _ in ma.get_xref_from() if not m.is_external() and m not in seen]
                return res
        res = [(m, "") for _, m, _ in ma.get_xref_from() if not m.is_external()]
        em = ma.get_method()
        is_static = em.get_access_flags() & 0x8
        if ma.name not in ("<init>", "<clinit>") and not is_static:
            # callback/override: framework gọi method này trên object -> ai tạo object đó?
            for init in self._inits.get(ma.class_name, []):
                res += [(m, "new") for _, m, _ in init.get_xref_from() if not m.is_external()]
        return res

    def path_to(self, ma, max_depth: int = 12) -> list[str] | None:
        if not self.entry_classes:
            return None
        prev = {ma: None}
        q = deque([(ma, 0)])
        while q:
            n, d = q.popleft()
            if n.class_name in self.entry_classes:
                path, cur, pending = [], n, ""
                while cur is not None:
                    path.append(pending + self.short(cur))
                    nxt = prev[cur]
                    # label 'new' = cur tạo object rồi framework gọi callback ở nxt
                    pending = {"new": "⇢(callback) ", "reflect": "⇢(reflection) "}.get(nxt[1], "") if nxt else ""
                    cur = nxt[0] if nxt else None
                return path
            if d >= max_depth:
                continue
            for p, label in self._preds(n):
                if p not in prev:
                    prev[p] = (n, label)
                    q.append((p, d + 1))
        return None

    def callers(self, ma, limit=5) -> list[str]:
        return [self.short(m) for _, m, _ in list(ma.get_xref_from())[:limit] if not m.is_external()]

    @staticmethod
    def call_needle(ma, callee) -> str:
        """Chuỗi jadx thường dùng khi ma gọi callee: 'c.a(' (khác class) hoặc 'a(' (cùng class)."""
        if callee.name == "<init>":
            return "new " + callee.class_name[1:-1].rsplit("/", 1)[-1].split("$")[-1]
        if callee.class_name == ma.class_name or callee.class_name.startswith(ma.class_name[:-1] + "$"):
            return callee.name + "("
        return callee.class_name[1:-1].rsplit("/", 1)[-1].split("$")[-1] + "." + callee.name + "("

    @staticmethod
    def short(ma) -> str:
        return f"{cls_dot(ma.class_name).split('.')[-1]}.{ma.name}"

    # ------------------------------------------------------------------ snippets
    def _source(self, cls: str) -> ScanFile | None:
        outer = cls[1:-1].split("$")[0]
        if outer in self._src_cache:
            return self._src_cache[outer]
        sf = None
        if self.sources_root:
            p = self.sources_root / (outer + ".java")
            if p.exists():
                sf = ScanFile(p.relative_to(self.sources_root.parent).as_posix(), "code", p)
        self._src_cache[outer] = sf
        return sf

    def _locate(self, sf: ScanFile, ma, needle: str | None) -> tuple[int, int] | None:
        """Tìm (dòng khai báo method, dòng chứa needle) trong source jadx."""
        lines = sf.lines()
        masked = sf.text().split("\n")
        name = ma.name
        simple = ma.class_name[1:-1].rsplit("/", 1)[-1].split("$")[-1]
        if name == "<init>":
            decl = re.compile(rf"^\s*(?:(?:public|private|protected)\s+)?{re.escape(simple)}\s*\(")
        elif name == "<clinit>":
            decl = re.compile(r"^\s*static\s*\{")
        else:
            decl = re.compile(rf"^\s*(?:[\w<>\[\],.?$@]+\s+)+{re.escape(name)}\s*\([^;]*$")
        cands = [i for i, l in enumerate(masked) if decl.match(l)]
        first = None
        if needle and re.fullmatch(r"[\w$]+\(", needle):     # lời gọi: khớp nguyên tên (Log.i( không khớp getApi()
            _rx = re.compile(r"(?<![\w$])" + re.escape(needle))
            hit = lambda l: _rx.search(l) is not None
        else:
            hit = lambda l: bool(needle) and needle in l
        for i in cands:
            depth, opened, j = 0, False, i
            while j < len(masked):
                depth += masked[j].count("{") - masked[j].count("}")
                opened = opened or "{" in masked[j]
                if j > i and hit(lines[j]):
                    return i + 1, j + 1
                if opened and depth <= 0:
                    break
                j += 1
            first = first or (i + 1, i + 1)
        if not first and needle:
            for j, l in enumerate(lines):
                if hit(l):
                    return j + 1, j + 1
        return first

    def _bytecode(self, ma, off: int, ctx: int = 3) -> tuple[list[str], int | None]:
        em = ma.get_method()
        rows, hl, o = [], None, 0
        for ins in em.get_instructions():
            if o == off:
                hl = len(rows)
            rows.append(f"{o:04x}  {ins.get_name()} {ins.get_output()}"[:150])
            o += ins.get_length()
        if hl is None:
            return rows[: ctx * 2 + 1], None
        s = max(0, hl - ctx)
        return rows[s: hl + ctx + 1], hl - s

    def make_hit(self, ma, off: int | None, match: str, needle: str | None, ctx: int,
                 confidence: str = "code", note: str | None = None, with_path: bool = True) -> Hit:
        klass = cls_dot(ma.class_name)
        h = Hit(file=klass, line=0, match=match, confidence=confidence, engine="dex",
                klass=klass, method=ma.name, note=note)
        if off is not None:
            h.bytecode, h.bytecode_hl = self._bytecode(ma, off)
        sf = self._source(ma.class_name)
        if sf:
            loc = self._locate(sf, ma, needle)
            if loc:
                _, line = loc
                lines = sf.lines()
                s, e = max(1, line - ctx), min(len(lines), line + ctx)
                h.file, h.line, h.snippet_start = sf.rel, line, s
                h.snippet = [l[:300] for l in lines[s - 1:e]]
                h.lang = "java"
        h.hook = frida_hook(klass, ma.name)
        if ma.class_name in self.payload_of:
            p = self.payload_of[ma.class_name]
            h.note = f"📦 Code nằm trong payload ẩn {p} (nạp động lúc chạy)" + (f"\n{h.note}" if h.note else "")
        if with_path:
            h.path = self.path_to(ma)
            h.reachable = h.path is not None if self.entry_classes else None
        return h

    # ------------------------------------------------------------------ matching
    def _occ(self, kind: str, pat: re.Pattern):
        index = {"api": self.inv, "str": self.strs, "field": self.flds}[kind]
        for key, occ in index.items():
            if pat.search(key):
                for ma, off in occ:
                    yield key, ma, off

    def match(self, rule: Rule, ctx: int, in_method: re.Pattern | None = None) -> list[Hit]:
        hits, seen = [], set()
        for kind, pats in (("api", rule.api), ("str", rule.strings), ("field", rule.fields)):
            for p in pats:
                for key, ma, off in self._occ(kind, p):
                    if (ma, off) in seen or (in_method and not in_method.search(ma.name)):
                        continue
                    seen.add((ma, off))
                    match = pretty_sig(key) if kind != "str" else repr(key)[:120]
                    note = self.dec_note(ma, off) if kind == "str" else None
                    hits.append(self.make_hit(ma, off, match, self.site_needle(kind, key, ma, off), ctx, note=note))
        return hits

    def combo(self, rule: Rule, ctx: int, limit: int = 30) -> list[Hit]:
        c = rule.combo
        reaches = []
        for grp in c.groups:
            reach: dict = {}
            for item in grp:
                for key, ma, off in self._occ(item.kind, item.pattern):
                    reach.setdefault(ma, (0, key, item.kind, off, ma))
            frontier = list(reach)
            for d in range(1, c.depth + 1):
                nxt = []
                for n in frontier:
                    for p, _ in self._preds(n):
                        if p not in reach and (self.include_libs or not self.is_lib(p.class_name)):
                            reach[p] = (d,) + reach[n][1:]
                            nxt.append(p)
                frontier = nxt
            if not reach:
                return []
            reaches.append(reach)
        common = set(reaches[0]).intersection(*reaches[1:])
        # chỉ giữ method "sâu nhất" của chuỗi gọi (bỏ caller nếu callee của nó cũng đã thỏa)
        ranked = sorted(common, key=lambda m: sum(r[m][0] for r in reaches))
        hits = []
        for ma in ranked[:limit]:
            notes = []
            for i, r in enumerate(reaches):
                d, key, kind, off, origin = r[ma]
                lbl = c.labels[i] or f"nhóm {i + 1}"
                where = "ngay trong method này" if origin is ma else f"qua {self.short(origin)} (cách {d} tầng gọi)"
                show = pretty_sig(key) if kind != "str" else repr(key)[:60]
                if kind == "str" and (origin, off) in self.dec_sites:
                    show += " 🔓(đã giải mã)"
                notes.append(f"{lbl}: {show}  — {where}")
            d0, key0, kind0, off0, origin0 = reaches[0][ma]
            off = off0 if origin0 is ma else None
            if origin0 is ma:
                needle = self.site_needle(kind0, key0, ma, off0)
            else:
                needle = self.call_needle(ma, origin0)
            h = self.make_hit(ma, off, " + ".join(c.labels) or rule.name, needle, ctx,
                              confidence="behavior", note="\n".join(notes))
            hits.append(h)
        return hits

    # ------------------------------------------------------------------ value-flow (taint)
    @property
    def cha(self):
        if getattr(self, "_cha", None) is None:
            from .flow.cha import Hierarchy
            self._cha = Hierarchy(self.dx, self.flow_libs, self.is_lib, self.entry_classes,
                                  onclick=self.layout_onclick())
        return self._cha

    def layout_onclick(self) -> set[str] | None:
        """Tên handler khai báo bằng android:onClick trong layout XML (None nếu không đọc được)."""
        if not self.apk:
            return None
        try:
            from androguard.core.axml import AXMLPrinter
        except ImportError:
            return None
        out = set()
        key = "{http://schemas.android.com/apk/res/android}onClick"
        for f in self.apk.get_files():
            if not (f.startswith("res/layout") and f.endswith(".xml")):
                continue
            try:
                x = AXMLPrinter(self.apk.get_file(f)).get_xml_obj()
                for el in x.iter():
                    v = el.get(key)
                    if v:
                        out.add(v)
            except Exception:
                continue
        return out

    def res_string(self, rid: int) -> str | None:
        """Giải R.string.x (getString(int)) bằng resources.arsc."""
        if not self.apk:
            return None
        if not hasattr(self, "_arsc"):
            try:
                self._arsc = self.apk.get_android_resources()
            except Exception:
                self._arsc = None
        if not self._arsc:
            return None
        try:
            for _, v in self._arsc.get_resolved_res_configs(rid):
                if isinstance(v, str):
                    return v
        except Exception:
            return None
        return None

    def intent_actions(self) -> dict[str, set[str]]:
        """action trong <intent-filter> -> {class component} (để biết Intent ngầm đi tới đâu trong app)."""
        out: dict[str, set[str]] = {}
        if not self.apk:
            return out
        ns = "{http://schemas.android.com/apk/res/android}"
        pkg = self.apk.get_package()
        try:
            root = self.apk.get_android_manifest_xml()
        except Exception:
            return out
        for el in root.iter():
            if el.tag not in ("activity", "activity-alias", "service", "receiver"):
                continue
            n = el.get(ns + "targetActivity") or el.get(ns + "name")
            if not n:
                continue
            n = pkg + n if n.startswith(".") else (n if "." in n else f"{pkg}.{n}")
            cls = "L" + n.replace(".", "/") + ";"
            if cls not in self.entry_classes:
                continue
            for a in el.iter("action"):
                if a.get(ns + "name"):
                    out.setdefault(a.get(ns + "name"), set()).add(cls)
        return out

    def exported_components(self) -> set[str] | None:
        """Component app khác gọi trực tiếp được: exported="true", hoặc có intent-filter mà không ghi exported
        (mặc định trước Android 12). Provider mặc định không exported (targetSdk >= 17)."""
        if not self.apk:
            return None
        ns = "{http://schemas.android.com/apk/res/android}"
        pkg = self.apk.get_package()
        try:
            root = self.apk.get_android_manifest_xml()
        except Exception:
            return None
        out = set()
        for el in root.iter():
            if el.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
                continue
            n = el.get(ns + "targetActivity") or el.get(ns + "name")
            if not n:
                continue
            n = pkg + n if n.startswith(".") else (n if "." in n else f"{pkg}.{n}")
            ex = el.get(ns + "exported")
            if ex == "true" or (ex is None and el.tag != "provider" and el.find("intent-filter") is not None):
                out.add("L" + n.replace(".", "/") + ";")
        return out

    def native_impl(self, ma, natives: list) -> tuple | None:
        """Hàm native hiện thực method Java ma: export Java_* (kể cả bản overload __sig) hoặc RegisterNatives
        (giả lập JNI_OnLoad; chỉ dùng khi lib có JNI_OnLoad). -> (lib, địa chỉ, tên) | None."""
        desc = ma.descriptor.replace(" ", "")          # androguard: "(La; Lb;)V"
        sym = f"Java_{jni_mangle(ma.class_name[1:-1])}_{jni_mangle(ma.name)}"
        long_ = sym + "__" + jni_mangle(desc[1:desc.index(")")])
        for lib in natives:
            if not getattr(lib, "ok", False):
                continue
            for n in (long_, sym):
                if n in lib.exports:
                    return lib, lib.exports[n], n
        for lib in natives:
            if getattr(lib, "ok", False) and "JNI_OnLoad" in lib.exports and lib.emu:
                for n_, sg, fn in lib.emu.natives:
                    if n_ == ma.name and (not sg or sg == desc):
                        return lib, fn, lib.fname(fn)
        return None

    @staticmethod
    def native_hook(nat: dict) -> str:
        if nat["fn"].startswith("Java_") or nat.get("exported"):
            at = f"Process.getModuleByName('{nat['lib']}').getExportByName('{nat['fn']}')"
        else:                                    # hàm static (RegisterNatives) không có symbol: base + offset
            at = f"Process.getModuleByName('{nat['lib']}').base.add({nat['addr']:#x})"
        return f"Interceptor.attach({at}, {{ onEnter(a) {{ console.log('{nat['fn']}', a[2], a[3]); }} }});"

    def jni_summaries(self, natives: list) -> dict:
        """sig method native -> {lib, fn, jsigs (API Java native gọi qua JNI), targets (method app được gọi
        ngược), csinks (hàm libc nguy hiểm gọi tới được, dạng chữ ký giả Lnative/libc;->x()V)}."""
        out = {}
        if not natives:
            return out
        cha = self.cha
        by_nd: dict = defaultdict(list)
        for c, ms in cha.meth.items():
            for k in ms:
                by_nd[k].append(c)
        for ma in self.native_methods:
            impl = self.native_impl(ma, natives)
            if impl is None:
                continue
            lib, a, fn = impl
            js = lib.jni_summary(a)
            jsigs, targets = [], []
            for cl, n, sg in js["jcalls"]:
                # class lấy từ FindClass gần nhất có thể sai (GetObjectClass không để lại chuỗi): nếu app có method
                # trùng tên + chữ ký thì coi đó cũng là đích
                app = by_nd.get(n + sg, [])[:4]
                cands = ([f"L{cl};"] if cl else []) + [c for c in app if c != f"L{cl};"]
                for c in cands:
                    jsig = f"{c}->{n}{sg}"
                    if jsig not in jsigs:
                        jsigs.append(jsig)
                    if c in cha.internal:
                        for t in cha.resolve(0x6E, jsig) or cha.resolve(0x71, jsig):
                            if t not in targets and t is not ma:
                                targets.append(t)
            csinks = [f"Lnative/libc;->{i}()V" for i in js["imports"] if i in NATIVE_SINK_IMPS]
            if jsigs or csinks:
                out[f"{ma.class_name}->{ma.name}{ma.descriptor}"] = {
                    "lib": lib.name, "fn": fn, "addr": a, "exported": fn in lib.exports, "jname": ma.name, "jsigs": jsigs, "targets": targets,
                    "csinks": csinks}
        return out

    def run_flows(self, rules: list[Rule], natives: list | None = None):
        """Chạy engine taint một lần cho mọi rule flow: (nguồn ∪, đích ∪)."""
        from .flow.engine import FlowEngine, Spec
        src, sinks, seen = [], [], set()
        for r in rules:
            if not r.flow:
                continue
            for k, p in r.flow[0]:
                if (k, p.pattern) not in seen:
                    seen.add((k, p.pattern))
                    src.append((k, p))
            for p in r.flow[1]:
                if ("sink", p.pattern) not in seen:
                    seen.add(("sink", p.pattern))
                    sinks.append(p)
        dec_sigs = {d["sig"] for d in self.find_decryptors()}
        crypto = re.compile(r"^Ljavax/crypto/|^Ljava/security/MessageDigest;|^Ljava/lang/(?:Class|ClassLoader);->"
                            r"(?:forName|loadClass|getMethod|getDeclaredMethod|getField|getDeclaredField)|"
                            r"^Ljava/lang/reflect/Method;->invoke|^Ldalvik/system/\w+ClassLoader;-><init>")
        fe = FlowEngine(self.dx, self.cha, Spec(src, sinks), self.is_lib, self.flow_libs,
                        decrypted=self.decrypted, res_string=self.res_string, max_rounds=self.flow_rounds, inv=self.inv,
                        interesting=lambda sg: sg in dec_sigs or bool(crypto.search(sg)), budget=self.flow_budget,
                        fields=(self.fld_r, self.fld_w))
        fe.label_str = crypto_label
        fe.components = set(self.entry_classes)
        fe.actions = self.intent_actions()
        fe.exported = self.exported_components()
        fe.package = self.apk.get_package() if self.apk else None
        if natives is not None:
            self.natives = natives
        fe.natives = self.jni_summaries(getattr(self, "natives", None) or [])
        self.flow = fe.run()
        return self.flow

    def flow_hits(self, rule: Rule, ctx: int) -> list[Hit]:
        fe = getattr(self, "flow", None)
        if fe is None:
            return []
        reach = self.cha.reachable if self.entry_classes else None
        groups: dict = {}
        for f in fe.flows_for(*rule.flow):         # gộp theo chỗ dữ liệu thoát ra (sink)
            groups.setdefault((f.sink_ma, f.sink_off), []).append(f)
        hits = []
        for (sm, so), fl in groups.items():
            def sdesc(f):
                s = fe.sources[f.src]
                if s.kind == "param":
                    return f"tham số của callback {pretty_sig(s.sig).split('(')[0]}"
                d = pretty_sig(s.sig).split("(")[0] + (f" @ {self.short(s.ma)}+{s.off:#x}" if s.off >= 0 else "")
                if (nat := fe.native_sites.get((s.ma, s.off))) and s.sig in nat["jsigs"]:
                    d += f" (gọi trong mã native {nat['lib']}!{nat['fn']} qua JNI)"
                return d
            # nguồn cụ thể nhất trước (getStringExtra hơn getIntent)
            fl.sort(key=lambda f: ("getIntent()" in fe.sources[f.src].sig, len(f.chain)))
            f0 = fl[0]
            s0 = fe.sources[f0.src]
            jni_via = {}                         # (a, b): a gọi method native, mã native gọi ngược b
            for (nm, _), nat in fe.native_sites.items():
                for t in nat["targets"]:
                    jni_via[(nm, t)] = f"{nat['lib']}!{nat['fn']}"
            chain = self.short(f0.chain[0])
            for a_, b_ in zip(f0.chain, f0.chain[1:]):
                chain += (f" ⇢(JNI: {jni_via[(a_, b_)]} gọi ngược) → " if (a_, b_) in jni_via else " → ") + self.short(b_)
            if f0.chain[0] is s0.ma:
                path = chain
            else:
                via = "field/heap"
                sink_comp = fe._comp_of(f0.chain[0].class_name)
                for (lm, lo), tg in fe.icc_links.items():
                    if tg & sink_comp:
                        via = f"Intent: {self.short(lm)}+{lo:#x} → {cls_dot(sorted(tg & sink_comp)[0]).split('.')[-1]}"
                    elif "*" in tg and sink_comp and via == "field/heap":
                        via = f"Intent không rõ đích: {self.short(lm)}+{lo:#x} → ?"
                    else:
                        continue
                    if lm is s0.ma:
                        break
                nat = fe.native_sites.get((s0.ma, s0.off))
                if via == "field/heap" and nat and f0.chain[0] in nat["targets"]:
                    via = f"JNI: {nat['lib']}!{nat['fn']} gọi ngược {self.short(f0.chain[0])}"
                if via == "field/heap" and f0.chain[0].name == "onActivityResult":
                    via = "setResult → onActivityResult"
                path = f"{self.short(s0.ma)} ⇢({via}) → {chain}"
            srcs = list(dict.fromkeys(sdesc(f) for f in fl))
            note = ("Nguồn: " + srcs[0] + (f"  (+{len(srcs) - 1} nguồn khác trên cùng đường: " + "; ".join(srcs[1:4]) + ")"
                                           if len(srcs) > 1 else "") + "\n"
                    f"Đường dữ liệu: {path}\n"
                    f"Đích: {pretty_sig(f0.sink_sig)} trong {self.short(sm)}")
            match = f"{pretty_sig(s0.sig).split('(')[0].split('.')[-1]}() ⟶ {pretty_sig(f0.sink_sig).split('(')[0]}"
            needle = needle_of("api", f0.sink_sig)
            if (nat := fe.native_sites.get((sm, so))) and (f0.sink_sig in nat["jsigs"] or f0.sink_sig in nat["csinks"]):
                how = "qua JNI" if f0.sink_sig in nat["jsigs"] else "hàm libc"
                note += (f"\nĐích nằm trong mã native: {nat['lib']}!{nat['fn']} gọi {pretty_sig(f0.sink_sig).split('(')[0]}"
                         f" ({how}). Bên trong native chỉ xấp xỉ: mọi đối số của method native coi như tới được đích."
                         f"\nHook: {self.native_hook(nat)}")
                needle = nat["jname"] + "("
            h = self.make_hit(sm, so, match, needle, ctx, confidence="behavior", note=note)
            if reach is not None:
                h.reachable = any(f.chain[0] in reach and fe.sources[f.src].ma in reach for f in fl)
            hits.append(h)
        hits.sort(key=lambda h: not h.reachable)
        return hits

    # ------------------------------------------------------------------ builtins
    def builtin_payload_dex(self, ctx: int) -> list[Hit]:
        """DEX ẩn trong APK: nơi chứa, cách tìm ra, số class, chỗ code chính nạp nó."""
        hits = []
        loaders = [(ma, off) for sg, occ in self.inv.items()
                   if re.match(r"Ldalvik/system/\w*(?:DexClassLoader|DexFile|PathClassLoader);-><init>|Ldalvik/system/DexFile;->loadDex", sg)
                   for ma, off in occ if ma.class_name not in self.payload_of]
        for p in self.payloads:
            base = p["name"].split("!")[0].rsplit("/", 1)[-1]
            refs = [(ma, off) for s_, occ in self.strs.items() if base and base in s_ for ma, off in occ]
            at = refs[0] if refs else (loaders[0] if loaders else None)
            pk = sorted({c[1:].rsplit("/", 1)[0].replace("/", ".") for c in p["classes"]})
            note = (f"Payload: {p['name']} ({p['size']} byte, {p['how']}), {len(p['classes'])} class"
                    f" — gói: {', '.join(pk[:6])}{' …' if len(pk) > 6 else ''}\n"
                    f"Đã nạp chung với code chính: các finding khác trong payload được đánh dấu 📦."
                    + (f"\nCode chính nhắc tới file: {', '.join(sorted({self.short(m) for m, _ in refs})[:5])}" if refs else "")
                    + (f"\nNạp bằng: {', '.join(sorted({self.short(m) for m, _ in loaders})[:5])}" if loaders else ""))
            match = f"{p['name']} → {len(p['classes'])} class"
            if at:
                h = self.make_hit(at[0], at[1], match, base if refs else None, ctx, confidence="behavior", note=note)
            else:
                h = Hit(file=p["name"], line=0, match=match, confidence="code", engine="dex", note=note)
            hits.append(h)
        return hits

    def _flow_reflect(self, ma, off) -> str | None:
        fe = getattr(self, "flow", None)
        if fe is None:
            return None
        r = fe.reflect.get((ma, off))
        if not r:
            return None
        names = []
        for c, m in sorted(r[1], key=str):
            if c is None and m is None:
                continue
            cd = cls_dot(c) if c and c.startswith("L") else c
            names.append(".".join(x for x in (cd, m) if x))
        return " | ".join(names[:4]) or None

    def builtin_reflection(self, ctx: int) -> list[Hit]:
        hits = []
        for ma, off, api, parts in self.reflect:
            res = [self.resolve(p) for p in parts]
            val = None if any(r is None for r in res) else ".".join(res)
            fv = self._flow_reflect(ma, off)
            if fv and (val is None or len(fv) > len(val)):
                val = fv          # engine luồng giá trị giải được xuyên method / qua field / nối chuỗi / resource
            encs = [p for p in parts if isinstance(p, DecRef)]
            if val is None:
                if encs:
                    note = (f"Tên được trả về từ {encs[0]!r} (nghi là hàm giải mã string) nên chưa biết đích. "
                            "Chạy lại với --frida-decrypt để giải.")
                    match = f"{api}({encs[0]!r})"
                else:
                    note = "Tên class/method KHÔNG phải hằng số: được tính lúc chạy (có thể đã bị mã hóa)."
                    match = f"{api}(<dynamic>)"
            else:
                match = f'{api}("{val}")'
                note = "Đích reflection: " + val + ("  ⚠ API nhạy cảm bị giấu qua reflection!" if SENSITIVE_REFLECT.search(val) else "")
                if encs:
                    note += f"\n🔓 Tên đã được giải mã từ {encs[0]!r}"
            h = self.make_hit(ma, off, match, api.split(".")[-1], ctx, note=note)
            h.confidence = "behavior" if val and SENSITIVE_REFLECT.search(val) else "code"
            hits.append(h)
        hits.sort(key=lambda h: (h.confidence != "behavior", "<dynamic>" in h.match or "…" in h.match))
        return hits

    def find_decryptors(self) -> list[dict]:
        """Hàm giải mã string: static, tham số chỉ là String/byte[]/char[]/số, trả về String,
        thân hàm có XOR / thao tác ký tự / Base64 / Cipher, được gọi nhiều lần với hằng số
        trông như đã mã hóa (entropy cao / ký tự lạ)."""
        if self._decryptors is not None:
            return self._decryptors
        allowed = {"Ljava/lang/String;", "[B", "[C", "I", "J", "S", "B", "C", "[I"}
        by_sig = {}
        for ma in self.dx.get_methods():
            if not ma.is_external():
                by_sig[f"{ma.class_name}->{ma.name}{ma.descriptor}".replace(" ", "")] = ma
        found = []
        for sig, calls in self.str_arg_calls.items():
            cls = sig.split("->")[0]
            if cls not in self.internal_classes or self.is_lib(cls) or not sig.endswith(")Ljava/lang/String;"):
                continue
            params = sig_params(sig)
            if not params or any(p not in allowed for p in params):
                continue
            callers = {id(c[0]) for c in calls}
            if len(calls) < 3 or len(callers) < 2:
                continue
            target = by_sig.get(sig.replace(" ", ""))
            if target is None or not (target.get_method().get_access_flags() & 0x8):
                continue
            em = target.get_method()
            if em.get_code() is None:
                continue
            ops, outs = set(), []
            for ins in em.get_instructions():
                ops.add(ins.get_op_value())
                if ins.get_op_value() in INVOKE_OPS:
                    outs.append(ins.get_output())
            has_xor = bool(ops & {0x97, 0xA2, 0xB7, 0xC2, 0xD7, 0xDF})
            has_ops = any(re.search(r"charAt|toCharArray|Base64;->decode|Cipher;->doFinal|String;-><init>\(\[[BC]", o) for o in outs)
            if not (has_xor or has_ops):
                continue
            vals = [c[2] for c in calls]
            enc = sum(1 for v in vals if looks_encoded(v)) / len(vals)
            if enc < 0.5:
                continue
            found.append({
                "sig": sig, "cls": cls, "name": sig.split("->")[1].split("(")[0], "params": params,
                "target": target, "calls": calls, "const_calls": self.static_calls.get(sig, []),
                "n_callers": len(callers), "enc": enc,
                "why": ", ".join(x for x, ok in (("XOR", has_xor), ("thao tác ký tự/Base64/Cipher", has_ops)) if ok),
            })
        self._decryptors = found
        return found

    def builtin_string_decryptor(self, ctx: int) -> list[Hit]:
        hits = []
        for d in self.find_decryptors():
            sig, fname, calls, cc = d["sig"], d["name"], d["calls"], d["const_calls"]
            solved = [(m, a, self.decrypted[(sig, a)]) for m, _, a in cc if (sig, a) in self.decrypted]
            note = (f"{len(calls)} lần gọi từ {d['n_callers']} method; {d['enc']:.0%} tham số trông như đã mã hóa; "
                    f"thân hàm có {d['why']}.\n")
            if solved:
                note += f"🔓 Đã giải mã {len(solved)}/{len(cc)} lời gọi (tham số hằng). Ví dụ:\n  " + "\n  ".join(
                    f"{self.short(m)}: {fname}({', '.join(repr(x)[:30] for x in a)}) → {p!r}" for m, a, p in solved[:8])
            else:
                samples = [f"{self.short(m)} → {fname}({v[:40]!r})" for m, _, v in calls[:6]]
                note += (f"{len(cc)}/{len(calls)} lời gọi có tham số hằng (giải được). "
                         "Chạy --frida-decrypt để giải tự động. Ví dụ:\n  " + "\n  ".join(samples))
            h = self.make_hit(d["target"], 0, pretty_sig(sig), None, ctx, note=note, with_path=False)
            h.confidence = "behavior"
            h.hook = (f"Java.perform(() => {{ const C = Java.use('{cls_dot(d['cls'])}'); "
                      f"C['{fname}'].overloads.forEach(o => o.implementation = function (...a) {{ "
                      f"const r = o.apply(this, a); console.log(JSON.stringify(a), '=>', r); return r; }}); }});")
            hits.append(h)
        return hits

    def builtin_crypto_autodecrypt(self, ctx: int, max_ct: int = 300) -> list[Hit]:
        """Ghép ciphertext hardcode với key/IV hardcode trong cùng vùng code rồi thử giải thật."""
        from . import crypto_solver as cs
        if not cs.OK:
            return []
        # method dùng javax.crypto, mở rộng ra caller 2 tầng (key/ciphertext thường nằm ở caller)
        crypto_m = {ma for sig, occ in self.inv.items() if sig.startswith("Ljavax/crypto/") for ma, _ in occ}
        frontier = set(crypto_m)
        for _ in range(2):
            frontier = {p for m in frontier for p, lbl in self._preds(m) if not lbl} - crypto_m
            crypto_m |= frontier
        if not crypto_m:
            return []
        by_m: dict = defaultdict(list)
        by_cls: dict = defaultdict(set)
        for st, occ in self.strs.items():
            for ma, off in occ:
                by_m[ma].append(st)
        for ma in by_m:
            by_cls[ma.class_name].add(ma)

        def hood(ma):
            ms = {ma} | by_cls[ma.class_name] | {p for p, _ in self._preds(ma)}
            ms |= {m for _, m, _ in ma.get_xref_to() if not m.is_external()}
            return ms

        hits, done = [], set()
        solved_ct: set = set()
        fe = getattr(self, "flow", None)
        for ma, off, sig, objl, argl in (fe.crypto_sites if fe else []):
            keys, ivs = [], []
            for x in sorted(objl, key=len):
                for k in cs.key_candidates(x, derive=True):
                    keys.append(k)
                    if len(k.raw) in (8, 16) and k.how in ("hex", "base64", "utf-8"):
                        ivs.append((k.raw, f"IV = {x!r} ({k.how})"))
            for st in sorted(argl, key=len):
                if st in solved_ct:
                    continue
                for ct, enc in cs.ct_candidates(st):
                    r = cs.solve(ct, keys, ivs) if keys else None
                    if not r:
                        continue
                    txt, algo, k, ivd = r
                    solved_ct.add(st)
                    keyd = f"{k.src!r}" + ("" if k.how == "utf-8" else f" ({k.how})") + f" = {k.raw.hex()}"
                    note = (f"🔑 Đã giải mã thành công bằng hằng số trong app (key và ciphertext được ghép theo "
                            f"luồng dữ liệu tới Cipher.doFinal):\n"
                            f"  thuật toán: {algo}\n  key: {keyd}\n" + (f"  {ivd}\n" if ivd else "") +
                            f"  ciphertext ({enc}): {st[:60]!r}\n  plaintext: {txt[:300]!r}")
                    hits.append(self.make_hit(ma, off, repr(txt)[:120], "doFinal", ctx, confidence="behavior", note=note))
                    break
        n_ct = 0
        for st, occ in self.strs.items():
            if st in solved_ct:
                continue
            cts = cs.ct_candidates(st)
            if not cts:
                continue
            for ma, off in occ:
                if (st, ma) in done:
                    continue
                done.add((st, ma))
                hm = hood(ma)
                if not (hm & crypto_m):
                    continue
                n_ct += 1
                if n_ct > max_ct:
                    break
                near = {x for m in hm for x in by_m.get(m, ()) if x != st}
                keys, ivs = [], []
                for x in sorted(near, key=len):
                    for k in cs.key_candidates(x, derive=not cs.ct_candidates(x)):
                        keys.append(k)
                        if len(k.raw) in (8, 16) and k.how in ("hex", "base64", "utf-8"):
                            ivs.append((k.raw, f"IV = {x!r} ({k.how})"))
                if not keys:
                    continue
                for ct, enc in cts:
                    r = cs.solve(ct, keys, ivs)
                    if not r:
                        continue
                    txt, algo, k, ivd = r
                    keyd = f"{k.src!r}" + ("" if k.how == "utf-8" else f" ({k.how})") + f" = {k.raw.hex()}"
                    note = (f"🔑 Đã giải mã thành công bằng hằng số trong app:\n"
                            f"  thuật toán: {algo}\n  key: {keyd}\n" + (f"  {ivd}\n" if ivd else "") +
                            f"  ciphertext ({enc}): {st[:60]!r}\n  plaintext: {txt[:300]!r}")
                    h = self.make_hit(ma, off, repr(txt)[:120], self.site_needle("str", st, ma, off), ctx,
                                      confidence="behavior", note=note)
                    hits.append(h)
                    break
        return hits

    def builtin_insecure_tls(self, ctx: int) -> list[Hit]:
        """checkServerTrusted rỗng / verify() luôn true / getAcceptedIssuers null — kiểm tra trên bytecode."""
        hits = []
        for ma in self.dx.get_methods():
            if ma.is_external() or ma.name not in ("checkServerTrusted", "verify", "getAcceptedIssuers"):
                continue
            if not self.include_libs and self.is_lib(ma.class_name):
                continue
            em = ma.get_method()
            if em.get_code() is None:
                continue
            ops = [i.get_name() for i in em.get_instructions()]
            outs = [i.get_output() for i in em.get_instructions()]
            bad = None
            if ma.name == "checkServerTrusted" and ops == ["return-void"]:
                bad = "checkServerTrusted() rỗng → chấp nhận MỌI chứng chỉ"
            elif ma.name == "verify" and "SSLSession" in ma.descriptor and ops[:2] == ["const/4", "return"] and outs[0].endswith(", 1"):
                bad = "HostnameVerifier.verify() luôn trả về true"
            elif ma.name == "getAcceptedIssuers" and ops[:2] == ["const/4", "return-object"] and outs[0].endswith(", 0"):
                bad = "getAcceptedIssuers() trả về null"
            if bad:
                hits.append(self.make_hit(ma, 0, bad, None, ctx, note=bad))
        return hits
