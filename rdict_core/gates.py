"""Cổng chặn (gate): các điều kiện `if` phải đúng thì mới chạy tới một lệnh.

- gates_at(ma, off): điều kiện trong method chặn trước lệnh tại off (phụ thuộc điều khiển: chỉ 1 nhánh của if
  tới được lệnh đó).
- Dựng lại biểu thức của thanh ghi trong điều kiện bằng cách lùi ngược trong block/predecessor duy nhất
  (lời gọi + hằng + field + phép so sánh), phân loại: time / secret / geo / env / other.
- force: cách ép điều kiện bằng Frida (xem gate_script.py).
"""
from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass

from .flow.ir import INVOKE, MOVE_RESULT, lift, split_desc

WRITES_R0 = (set(range(0x01, 0x0A)) | {0x0D} | set(range(0x12, 0x1D)) | {0x1F, 0x20, 0x21, 0x22, 0x23}
             | set(range(0x2D, 0x32)) | set(range(0x44, 0x4B)) | set(range(0x52, 0x59)) | set(range(0x60, 0x67))
             | set(range(0x7B, 0xE3)))
STATIC_INV = {0x71, 0x77}
IF_Z = {0x38: "==", 0x39: "!=", 0x3A: "<", 0x3B: ">=", 0x3C: ">", 0x3D: "<="}
IF_2 = {0x32: "==", 0x33: "!=", 0x34: "<", 0x35: ">=", 0x36: ">", 0x37: "<="}
NEG = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">", "is": "not", "not": "is"}
SWAP = {"==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<="}
BIN = ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"]
LIT_OPS = ["+", "r-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"]

TIME_RX = re.compile(r"System;->currentTimeMillis|Date;->(?:getTime|after|before|compareTo)|"
                     r"Calendar;->(?:get\(|getTimeInMillis|after|before)|SystemClock;->(?:elapsedRealtime|uptimeMillis)|"
                     r"java/time/|PackageInfo;->(?:firstInstallTime|lastUpdateTime)")
INSTALL_RX = re.compile(r"PackageInfo;->(?:firstInstallTime|lastUpdateTime)")
GEO_RX = re.compile(r"TelephonyManager;->(?:getSimCountryIso|getNetworkCountryIso|getSimOperator|getNetworkOperator)|"
                    r"Locale;->(?:getCountry|getLanguage|getISO3\w*|getDisplay\w*|toString|toLanguageTag)|"
                    r"TimeZone;->(?:getID|getDisplayName)|LocaleList;->|Configuration;->locale")
EQ_RX = re.compile(r"Ljava/lang/String;->(?:equals|equalsIgnoreCase|contentEquals|startsWith|endsWith|contains|matches)\(|"
                   r"Landroid/text/TextUtils;->equals\(|Ljava/util/Objects;->equals\(")
INPUT_RX = re.compile(r"(?:EditText|TextView);->getText|SmsMessage;->get\w*(?:Body|Address)|JSONObject;->(?:get|opt)String|"
                      r"BufferedReader;->readLine|Intent;->get\w*Extra|Uri;->(?:getQueryParameter|getHost|getPath|"
                      r"getLastPathSegment)|Scanner;->next|RemoteMessage;->getData|Bundle;->get(?:String|CharSequence)\b|"
                      r"SharedPreferences;->getString|ClipData|InputStream;->read|ByteArrayOutputStream;->toString|"
                      r"Response\w*;->body|ResponseBody;->string|MessageDigest;->digest|getClipboard|"
                      r"DataSnapshot;->getValue|RemoteConfig;->getString")
ENV_RX = re.compile(r"(?i)root|emulat|debugg|isDebug|frida|xposed|magisk|hook|tamper|substrate|goldfish|qemu|vbox|"
                    r"genymotion|Build;->(?:FINGERPRINT|MODEL|MANUFACTURER|BRAND|DEVICE|PRODUCT|HARDWARE|BOARD|HOST|TAGS)|"
                    r"getInstallerPackageName|getInstallSourceInfo|adb_enabled|development_settings|Debug;->")
ENV_STR_RX = re.compile(r"(?i)^/(?:system|sbin|data/local)\S*/su$|^su$|test-keys|superuser|supersu|magisk|frida|xposed|"
                        r"substrate|goldfish|ranchu|qemu|genymotion|vbox|/proc/self/(?:maps|status)|TracerPid|27042|"
                        r"ro\.(?:kernel\.qemu|debuggable|secure|hardware)|^generic|^google_sdk$|^sdk_gphone|emulator|busybox|daemonsu")
NOISE_RX = re.compile(r"Build\$VERSION;->SDK_INT|;->(?:isEmpty|size|length|hasNext|isFinishing|isDestroyed)\(")
# method framework được ép kết quả boolean (method của app thì luôn được)
FW_FORCE_RX = re.compile(r"Landroid/os/Debug;->isDebuggerConnected|Landroid/os/Debug;->waitingForDebugger")

KIND_ICON = {"time": "⏰", "secret": "🔑", "geo": "🌍", "env": "🛡", "other": "⚙"}
KIND_ORDER = ["env", "time", "geo", "secret", "other"]


@dataclass
class Expr:
    text: str
    kind: str                    # const | str | call | field | param | cmp | inst | arith | obj | unk
    val: object = None           # hằng / (sig, recv, args) / field sig / (a, b)
    typ: str = ""
    sigs: frozenset = frozenset()

    @property
    def is_const(self):
        return self.kind in ("const", "str")


UNK = Expr("?", "unk")


def simple(cls: str) -> str:
    return cls.strip("L;").rsplit("/", 1)[-1]


def date_of(v) -> str | None:
    """Hằng trông như thời điểm epoch (ms hoặc s) trong 2014..2040 -> ngày UTC."""
    if not isinstance(v, int):
        return None
    for div in (1000, 1):
        s = v / div
        if 1.39e9 <= s <= 2.21e9:
            return datetime.datetime.fromtimestamp(s, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return None


def dur_of(v) -> str | None:
    if not isinstance(v, int) or v < 3_600_000 or v > 400 * 86_400_000:
        return None
    h = v / 3_600_000
    return f"{h / 24:g} ngày" if h >= 24 else f"{h:g} giờ"


def _fmt_const(v, typ=""):
    if isinstance(v, int):
        d = date_of(v)
        return f"{v}" + (f" ({d})" if d else "")
    return str(v)


@dataclass
class Gate:
    where: str           # Class.method chứa if
    off: int
    text: str            # điều kiện cần thỏa (đã đúng chiều)
    kind: str
    force: list | None = None    # cách ép: ["ret", sig, bool] | ["eq", const, bool] | ["time", rel, T]
    #                                       | ["ret_str", sig, s] | ["shift", ms]

    def as_dict(self):
        return {"where": self.where, "off": self.off, "cond": self.text, "kind": self.kind, "force": self.force}


class Cond:
    """rel in == != < <= > >= (a rel b) hoặc is/not (a là boolean)."""
    __slots__ = ("rel", "a", "b")

    def __init__(self, rel, a, b=None):
        self.rel, self.a, self.b = rel, a, b

    def neg(self):
        return Cond(NEG[self.rel], self.a, self.b)

    @property
    def sigs(self):
        return self.a.sigs | (self.b.sigs if self.b else frozenset())

    @property
    def text(self):
        if self.rel == "is":
            return self.a.text
        if self.rel == "not":
            t = self.a.text
            return "!" + (t if re.fullmatch(r"[\w.$]+(\(.*\))?", t) else f"({t})")
        b = self.b
        return f"{self.a.text} {self.rel} {_fmt_const(b.val) if b.kind == 'const' else b.text}"


class GateAnalyzer:
    def __init__(self, internal: set, method_of=None):
        self.internal = internal
        self.method_of = method_of          # sig -> MethodAnalysis (để xem thân method boolean bị obfuscate)
        self._body_env: dict = {}
        self._ir: dict = {}
        self._aux: dict = {}
        self._at: dict = {}

    # ------------------------------------------------------------------ IR + CFG
    def ir(self, ma):
        if ma not in self._ir:
            try:
                self._ir[ma] = lift(ma)
            except Exception:
                self._ir[ma] = None
        return self._ir[ma]

    def aux(self, ma):
        """(pos: off -> (block, idx), preds, by_start, reach)"""
        if ma in self._aux:
            return self._aux[ma]
        m = self.ir(ma)
        if m is None or len(m.blocks) > 3000:
            self._aux[ma] = None
            return None
        pos, preds, by_start = {}, [[] for _ in m.blocks], {}
        for b in m.blocks:
            by_start[b.start] = b.idx
            for i, ins in enumerate(b.insns):
                pos[ins.off] = (b.idx, i)
            for s in b.succs + b.handlers:
                preds[s].append(b.idx)
        succ = [b.succs + b.handlers for b in m.blocks]
        reach = []
        for b in m.blocks:            # tập block tới được từ b (kể cả b)
            seen, st = {b.idx}, [b.idx]
            while st:
                for s in succ[st.pop()]:
                    if s not in seen:
                        seen.add(s)
                        st.append(s)
            reach.append(seen)
        r = (pos, preds, by_start, reach)
        self._aux[ma] = r
        return r

    # ------------------------------------------------------------------ biểu thức
    def expr(self, ma, bi, ii, reg, depth=0, seen=None) -> Expr:
        """Giá trị của thanh ghi reg ngay trước lệnh thứ ii của block bi."""
        m, ax = self.ir(ma), self.aux(ma)
        if depth > 6 or ax is None:
            return UNK
        seen = seen or set()
        if (bi, ii, reg) in seen:
            return UNK
        seen.add((bi, ii, reg))
        b = m.blocks[bi]
        for j in range(ii - 1, -1, -1):
            ins = b.insns[j]
            if ins.res == reg and (ins.op in INVOKE or ins.op in (0x24, 0x25)):
                return self._call(ma, bi, j, ins, depth) if ins.op in INVOKE else Expr("{...}", "obj")
            if ins.op in MOVE_RESULT:
                continue
            if ins.op in WRITES_R0 and ins.regs and ins.regs[0] == reg:
                return self._mk(ma, bi, j, ins, depth, seen)
        preds = ax[1][bi]
        if not preds:
            if reg in m.param_regs:
                i = m.param_regs.index(reg)
                t = m.param_types[i]
                return Expr("this" if i == 0 and not m.is_static else f"p{i}", "param", i, t)
            return UNK
        outs = [self.expr(ma, p, len(m.blocks[p].insns), reg, depth + 1, seen) for p in preds[:4]]
        if len(preds) <= 4 and outs and all(o.text == outs[0].text for o in outs) and outs[0].kind != "unk":
            return outs[0]
        return UNK

    def _call(self, ma, bi, j, ins, depth) -> Expr:
        sig = ins.ref.replace(" ", "") if isinstance(ins.ref, str) else str(ins.ref)
        try:
            cls, rest = sig.split("->", 1)
            name = rest.split("(", 1)[0]
            params, ret = split_desc(rest[rest.index("("):])
        except ValueError:
            return Expr("call?", "unk")
        regs = list(ins.regs)
        static = ins.op in STATIC_INV
        recv = None
        if not static and regs:
            recv = self.expr(ma, bi, j, regs[0], depth + 1)
            regs = regs[1:]
        args, k = [], 0
        for p in params:
            args.append(self.expr(ma, bi, j, regs[k], depth + 1) if k < len(regs) else UNK)
            k += 2 if p in ("J", "D") else 1
        at = ", ".join(a.text if len(a.text) <= 40 else a.text[:37] + "..." for a in args)
        if recv is None or recv.kind == "unk":
            head = simple(cls)
        elif recv.text == "this":
            head = "this"
        else:
            head = recv.text if len(recv.text) <= 60 else "..." + recv.text[-57:]
        if name == "<init>":
            text = f"new {simple(cls)}({at})"
        else:
            text = f"{head}.{name}({at})"
        sigs = frozenset((sig,))
        for e in [recv] + args if recv else args:
            sigs |= e.sigs
        return Expr(text, "call", (sig, recv, args), ret, sigs)

    def _mk(self, ma, bi, j, ins, depth, seen) -> Expr:
        op, r = ins.op, ins.regs
        sub = lambda reg: self.expr(ma, bi, j, reg, depth + 1, seen)   # noqa: E731
        if 0x01 <= op <= 0x09 or op == 0x1F:
            return sub(r[1] if op != 0x1F else r[0])
        if 0x12 <= op <= 0x19:
            lit = ins.lit
            if lit is not None and op == 0x15 and abs(lit) < 0x10000:
                lit <<= 16
            if lit is not None and op == 0x19 and abs(lit) < 0x10000:
                lit <<= 48
            return Expr(str(lit), "const", lit, "J" if op >= 0x16 else "I")
        if op in (0x1A, 0x1B):
            s = str(ins.ref)
            return Expr(json.dumps(s[:60], ensure_ascii=False), "str", s, "Ljava/lang/String;")
        if op == 0x1C:
            return Expr(simple(str(ins.ref)) + ".class", "const", str(ins.ref), "Ljava/lang/Class;")
        if op == 0x20:
            x = sub(r[1])
            return Expr(f"{x.text} instanceof {simple(str(ins.ref))}", "inst", None, "Z", x.sigs)
        if op == 0x21:
            x = sub(r[1])
            return Expr(f"{x.text}.length", "arith", None, "I", x.sigs)
        if op == 0x22:
            return Expr(f"new {simple(str(ins.ref))}", "obj", str(ins.ref), str(ins.ref))
        if op == 0x23:
            return Expr(f"new {simple(str(ins.ref))}", "obj", None, str(ins.ref))
        if 0x2D <= op <= 0x31:
            a, b = sub(r[1]), sub(r[2])
            return Expr(f"cmp({a.text}, {b.text})", "cmp", (a, b), "I", a.sigs | b.sigs)
        if 0x44 <= op <= 0x4A:
            a, i = sub(r[1]), sub(r[2])
            return Expr(f"{a.text}[{i.text}]", "arith", None, "", a.sigs | i.sigs)
        if 0x52 <= op <= 0x58 or 0x60 <= op <= 0x66:
            f = str(ins.ref)
            fs = f.split(" ")[0]
            cls, fname = fs.split("->", 1) if "->" in fs else ("", fs)
            typ = f.split(" ")[1] if " " in f else ""
            if op <= 0x58:
                o = sub(r[1])
                head = "this" if o.text == "this" else (o.text if o.kind != "unk" else simple(cls))
            else:
                head = simple(cls)
                o = Expr("", "unk")
            return Expr(f"{head}.{fname}", "field", fs, typ, o.sigs | {fs})
        if 0x7B <= op <= 0x8F:
            x = sub(r[1])
            if op in (0x7B, 0x7D, 0x7F, 0x80):
                return Expr(f"-{x.text}", "arith", None, x.typ, x.sigs)
            if op in (0x7C, 0x7E):
                return Expr(f"~{x.text}", "arith", None, x.typ, x.sigs)
            return x                                           # đổi kiểu
        if 0x90 <= op <= 0xCF:
            two = op >= 0xB0
            base = op - (0xB0 if two else 0x90)
            a, b = (sub(r[0]), sub(r[1])) if two else (sub(r[1]), sub(r[2]))
            sym = BIN[base % 11] if base < 22 else BIN[(base - 22) % 5]
            return Expr(f"({a.text} {sym} {b.text})", "arith", (sym, a, b), a.typ, a.sigs | b.sigs)
        if 0xD0 <= op <= 0xE2:
            a = sub(r[1])
            sym = LIT_OPS[op - 0xD0] if op <= 0xD7 else LIT_OPS[op - 0xD8]
            if sym == "r-":
                return Expr(f"({ins.lit} - {a.text})", "arith", None, "I", a.sigs)
            return Expr(f"({a.text} {sym} {ins.lit})", "arith", None, "I", a.sigs)
        return UNK

    # ------------------------------------------------------------------ điều kiện
    def cond_of(self, ma, bi) -> Cond | None:
        """Điều kiện để if ở cuối block bi nhảy (nhánh 'taken')."""
        m = self.ir(ma)
        b = m.blocks[bi]
        ins = b.insns[-1]
        j = len(b.insns) - 1
        if ins.op in IF_Z:
            rel = IF_Z[ins.op]
            e = self.expr(ma, bi, j, ins.regs[0])
            if e.kind == "cmp":
                return Cond(rel, *e.val)
            if e.typ == "Z" or e.kind == "inst":
                if rel in ("==", "!="):
                    return Cond("not" if rel == "==" else "is", e)
            if e.typ.startswith(("L", "[")) or e.kind in ("obj", "str"):
                return Cond(rel, e, Expr("null", "const", None))       # kiểm tra null
            return Cond(rel, e, Expr("0", "const", 0, "I"))
        if ins.op in IF_2:
            return Cond(IF_2[ins.op], self.expr(ma, bi, j, ins.regs[0]), self.expr(ma, bi, j, ins.regs[1]))
        return None

    def body_env(self, sig: str, depth: int = 2) -> bool:
        """Method của app (tên bị obfuscate) mà thân có dấu hiệu kiểm tra môi trường: chuỗi su/test-keys/frida,
        Build.TAGS, isDebuggerConnected... (xét thêm method nó gọi, sâu depth tầng)."""
        if sig in self._body_env:
            return self._body_env[sig]
        self._body_env[sig] = False
        ma = self.method_of(sig) if self.method_of else None
        m = self.ir(ma) if ma is not None else None
        hit = False
        if m is not None:
            calls = []
            for b in m.blocks:
                for ins in b.insns:
                    r = ins.ref
                    if not isinstance(r, str):
                        continue
                    if ins.op in (0x1A, 0x1B) and ENV_STR_RX.search(r) or ins.op not in (0x1A, 0x1B) and ENV_RX.search(r):
                        hit = True
                        break
                    if ins.op in INVOKE and r.split("->")[0] in self.internal:
                        calls.append(r.replace(" ", ""))
                if hit:
                    break
            if not hit and depth > 0:
                hit = any(self.body_env(c, depth - 1) for c in dict.fromkeys(calls) if c != sig)
        self._body_env[sig] = hit
        return hit

    def classify(self, c: Cond) -> str | None:
        """None = điều kiện không đáng báo (không rõ / chỉ null-check / SDK_INT...)."""
        sigs = c.sigs
        if c.b is not None and c.b.kind == "const" and c.b.val is None:
            return None                              # null-check
        if not sigs or any(NOISE_RX.search(s) for s in sigs):
            return None
        if c.a.kind == "unk" and (c.b is None or c.b.kind == "unk"):
            return None
        txt = " ".join(sigs) + " " + c.text
        if any(TIME_RX.search(s) for s in sigs):
            return "time"
        if any(GEO_RX.search(s) for s in sigs):
            return "geo"
        if ENV_RX.search(txt):
            return "env"
        e = c.a
        if e.kind == "call" and e.val[0].endswith(")Z") and e.val[0].split("->")[0] in self.internal \
                and self.body_env(e.val[0]):
            return "env"
        if e.kind == "call" and EQ_RX.search(e.val[0]):
            parts = [x for x in [e.val[1]] + e.val[2] if x]
            if any(x.kind == "str" and x.val for x in parts) and \
                    any(INPUT_RX.search(s) for x in parts if x.kind != "str" for s in x.sigs):
                return "secret"
        return "other"

    def force_of(self, c: Cond, kind: str):
        e = c.a
        if c.rel in ("is", "not") and e.kind == "call":
            sig, recv, args = e.val
            want = c.rel == "is"
            if EQ_RX.search(sig):
                consts = [x for x in [recv] + args if x and x.kind == "str" and x.val]
                others = [x for x in [recv] + args if x and x.kind == "call"]
                if consts:
                    getter = next((o.val[0] for o in others if GEO_RX.search(o.val[0])), None)
                    if getter and sig.split("->")[1].startswith(("equals", "equalsIgnoreCase")):
                        return ["ret_str", getter, consts[0].val if want else "us"]
                    if want and kind == "secret" and \
                            sig.split("->")[1].startswith(("equals", "equalsIgnoreCase", "contentEquals")):
                        return ["eq", consts[0].val, True]
                return None
            cls = sig.split("->")[0]
            if sig.endswith(")Z") and (cls in self.internal or FW_FORCE_RX.search(sig)):
                return ["ret", sig, want]
            return None
        if c.rel in SWAP and c.b is not None:
            a, b, rel = c.a, c.b, c.rel
            if a.kind == "const" and b.kind != "const":
                a, b, rel = b, a, SWAP[rel]
            if b.kind == "const" and isinstance(b.val, int) and a.kind == "call" \
                    and a.val[0] == "Ljava/lang/System;->currentTimeMillis()J" and rel != "!=":
                return ["time", rel, b.val]
            # (now - mốc) > N: đẩy đồng hồ lên N ms (+1 phút)
            if b.kind == "const" and isinstance(b.val, int) and b.val > 0 and rel in (">", ">=") and \
                    a.kind == "arith" and a.val and a.val[0] == "-" and a.val[1].kind == "call" and \
                    a.val[1].val[0] == "Ljava/lang/System;->currentTimeMillis()J":
                return ["shift", b.val + 60_000]
        return None

    def gates_at(self, ma, off, where: str) -> list[Gate]:
        key = (ma, off)
        if key in self._at:
            return self._at[key]
        out = []
        ax = self.aux(ma)
        if ax is not None and off in ax[0]:
            pos, preds, by_start, reach = ax
            m = self.ir(ma)
            sb = pos[off][0]
            for b in m.blocks:
                if not b.insns or b.idx == sb or b.idx in reach[sb]:
                    continue              # cùng block, hoặc trong vòng lặp chung với lệnh đích
                last = b.insns[-1]
                if last.op not in IF_Z and last.op not in IF_2 or len(set(b.succs)) != 2:
                    continue
                t = by_start.get(last.lit)
                if t is None or t not in b.succs:
                    continue
                f = next(s for s in b.succs if s != t)
                rt, rf = sb in reach[t], sb in reach[f]
                if rt == rf:
                    continue
                c = self.cond_of(ma, b.idx)
                if c is None:
                    continue
                if not rt:
                    c = c.neg()
                kind = self.classify(c)
                if kind is None:
                    continue
                out.append(Gate(where, last.off, c.text[:200], kind, self.force_of(c, kind)))
        self._at[key] = out
        return out

    def ifs(self, ma):
        """Mọi (off, Cond nhánh taken) trong method — dùng cho rule BHV-*-GATE."""
        m = self.ir(ma)
        if m is None or self.aux(ma) is None:
            return
        for b in m.blocks:
            if b.insns and (b.insns[-1].op in IF_Z or b.insns[-1].op in IF_2):
                c = self.cond_of(ma, b.idx)
                if c is not None:
                    yield b.insns[-1].off, c
