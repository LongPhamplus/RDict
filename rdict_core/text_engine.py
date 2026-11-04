"""Engine regex trên text (source jadx, manifest, resource, strings của .so).
Ở bản mới đây là lớp *fallback*: khi có engine bytecode/native thì các rule tương ứng
sẽ dùng engine đó trước, regex chỉ bổ sung."""
from __future__ import annotations

import bisect
import re
from pathlib import Path

from .model import Hit, Rule

CODE_EXT = {".java", ".kt", ".smali"}
RES_EXT = {".xml", ".json", ".properties", ".txt", ".js", ".html", ".htm", ".cfg", ".conf", ".yaml", ".yml", ".ini"}
MAX_FILE_SIZE = 4 * 1024 * 1024
ABI_PREF = ["arm64-v8a", "x86_64", "armeabi-v7a", "armeabi", "x86", "mips64", "mips"]

LIB_PREFIXES = (
    "android/", "androidx/", "kotlin/", "kotlinx/", "com/google/", "com/android/",
    "okhttp3/", "okio/", "retrofit2/", "com/squareup/", "org/apache/", "org/json/",
    "io/reactivex/", "com/facebook/", "com/fasterxml/", "org/intellij/", "org/jetbrains/",
    "javax/", "j$/", "dagger/", "butterknife/", "com/bumptech/", "org/bouncycastle/",
    "org/slf4j/", "com/airbnb/", "io/grpc/", "com/crashlytics/", "io/fabric/",
    # React Native / Expo / Flutter ecosystem
    "expo/modules/", "host/exp/", "com/swmansion/", "com/horcrux/", "com/th3rdwave/", "com/reactnativecommunity/",
    "com/oblador/", "com/BV/", "com/zoontek/", "com/learnium/", "com/reactcommunity/", "io/invertase/",
    "versioned/host/", "io/flutter/", "dev/fluttercommunity/",
    # SDK / thư viện phổ biến
    "org/brotli/", "io/sentry/", "com/onesignal/", "com/appsflyer/", "com/adjust/", "com/amplitude/",
    "com/mixpanel/", "io/branch/", "org/greenrobot/", "com/jakewharton/", "org/reactivestreams/",
    "com/microsoft/", "com/amazonaws/", "com/stripe/", "com/bugsnag/", "zendesk/", "org/koin/", "coil/",
    "io/ktor/", "io/realm/", "net/sqlcipher/", "com/tencent/mmkv/", "org/chromium/", "com/unity3d/",
    "com/huawei/hms/", "com/yandex/", "com/applovin/", "com/ironsource/", "com/vungle/", "com/mopub/",
    "com/startapp/", "com/chartboost/", "com/inmobi/", "org/conscrypt/", "org/joda/", "org/threeten/",
    "com/caverock/", "com/nimbusds/", "net/zetetic/", "org/spongycastle/", "com/scottyab/rootbeer/",
)

# Thư viện native bên thứ ba phổ biến: bỏ qua mặc định (dùng -a để quét)
KNOWN_NATIVE = re.compile(
    r"^lib(?:c\+\+_shared|reactnative\w*|react_\w+|hermes\w*|jsi|jsc\w*|fbjni|folly\w*|yoga|glog\w*|flipper\w*"
    r"|fb\w*|imagepipeline|gifimage|static-webp|native-imagetranscoder|native-filters|reanimated|worklets|rnscreens"
    r"|gesturehandler|appmodules|expo-[\w-]+|turbomodule\w*|fabricjni|jscexecutor|androidx\.[\w.]+|zstd-kmp"
    r"|flutter|sentry\w*|crashlytics\w*|tensorflowlite\w*|opencv\w*|sqlcipher|mmkv|realm-jni|conceal\w*|unity"
    r"|main|monosgen\w*|monodroid|xamarin\w*|mapbox\w*|vlc\w*|ffmpeg\w*|av(?:codec|format|util|filter|device)\w*"
    r"|swscale|swresample|x264|ijk\w*|webp\w*|png\w*|jpeg\w*|turbojpeg|crypto|ssl|curl|z|sqlite\w*|bugsnag\w*"
    r"|pl_droidsonroids_gif|datastore_shared_counter|graphics-core|barhopper\w*|face_detector\w*|mlkit\w*"
    r"|firebase\w*|image_processing_util_jni|tflite\w*|rive-android|lottie\w*|skia\w*|v8\w*|j2v8|node)\.so$")


_TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?(?:\*/|\Z)', re.S)


def mask_comments(src: str) -> str:
    """Thay comment Java/Kotlin bằng khoảng trắng (giữ nguyên độ dài + newline) để regex
    không khớp vào comment, nhưng offset/số dòng không đổi. String literal được giữ nguyên."""
    def repl(m: re.Match) -> str:
        t = m.group()
        return t if t[0] in "\"'" else re.sub(r"[^\n]", " ", t)
    return _TOKEN.sub(repl, src)


def native_strings(p: Path, minlen: int = 5) -> tuple[str, list[int]]:
    data = p.read_bytes()
    lines, offs = [], []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        lines.append(m.group().decode("ascii"))
        offs.append(m.start())
    return "\n".join(lines), offs


class ScanFile:
    def __init__(self, rel: str, kind: str, path: Path, is_lib: bool = False, text: str | None = None):
        self.rel, self.kind, self.path, self.is_lib = rel, kind, path, is_lib
        self._raw = text
        self._masked: str | None = None
        self._nl: list[int] | None = None
        self.offsets: list[int] | None = None
        self._lines: list[str] | None = None

    def raw(self) -> str:
        if self._raw is None:
            if self.kind == "native":
                self._raw, self.offsets = native_strings(self.path)
            else:
                try:
                    self._raw = self.path.read_text(errors="ignore")
                except OSError:
                    self._raw = ""
        return self._raw

    def text(self) -> str:
        """Text dùng để match (code thì đã bỏ comment)."""
        if self._masked is None:
            self._masked = mask_comments(self.raw()) if self.kind == "code" and not self.rel.endswith(".smali") else self.raw()
        return self._masked

    def line_of(self, pos: int) -> int:
        if self._nl is None:
            self._nl = [m.start() for m in re.finditer("\n", self.raw())]
        return bisect.bisect_left(self._nl, pos) + 1

    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = self.raw().split("\n")
        return self._lines


def is_elf(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def collect(root: Path) -> list[ScanFile]:
    files: list[ScanFile] = []
    natives: dict[str, list[tuple[int, Path, str]]] = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.name == ".done":
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        suf = p.suffix.lower()
        if suf == ".so" or (not suf and is_elf(p)):
            abi = p.parent.name
            rank = ABI_PREF.index(abi) if abi in ABI_PREF else len(ABI_PREF)
            natives.setdefault(p.name, []).append((rank, p, rel))
            continue
        if size > MAX_FILE_SIZE:
            continue
        if p.name == "AndroidManifest.xml":
            kind = "manifest"
        elif suf in CODE_EXT:
            kind = "code"
        elif suf in RES_EXT:
            kind = "resource"
        else:
            continue
        pkg_path = rel.split("sources/", 1)[1] if "sources/" in rel else rel
        files.append(ScanFile(rel, kind, p, is_lib=kind == "code" and pkg_path.startswith(LIB_PREFIXES)))
    # mỗi thư viện native chỉ lấy 1 ABI (ưu tiên arm64) để tránh trùng kết quả
    for name, cands in natives.items():
        _, p, rel = sorted(cands)[0]
        files.append(ScanFile(rel, "native", p))
    return files


# --------------------------------------------------------------------------- context helpers
METHOD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)*"
    r"(?:<[^>]+>\s+)?[\w.$<>\[\], ?]+\s+(\w+)\s*\([^;]*$"
)
CLASS_RE = re.compile(r"^\s*(?:[\w ]*\s)?(?:class|interface|enum)\s+(\w+)")
KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new"}


def code_context(sf: ScanFile, line: int) -> tuple[str | None, str | None]:
    lines = sf.lines()
    pkg = None
    for l in lines[:30]:
        if m := re.match(r"\s*package\s+([\w.]+);", l):
            pkg = m.group(1)
            break
    method = klass = None
    for i in range(min(line - 1, len(lines) - 1), -1, -1):
        l = lines[i]
        if method is None and (m := METHOD_RE.match(l)) and m.group(1) not in KEYWORDS:
            method = m.group(1)
        if m := CLASS_RE.match(l):
            klass = m.group(1)
            break
    klass = klass or Path(sf.rel).stem
    return (f"{pkg}.{klass}" if pkg else klass), method


def frida_hook(klass: str | None, method: str | None) -> str | None:
    if not klass or not method or method in ("<init>", "<clinit>"):
        return None
    return (f"Java.perform(() => {{ const C = Java.use('{klass}'); "
            f"C['{method}'].overloads.forEach(o => o.implementation = function (...a) {{ "
            f"console.log('[{klass.split('.')[-1]}.{method}]', JSON.stringify(a)); "
            f"const r = o.apply(this, a); console.log('  =>', r); return r; }}); }});")


def make_hit(sf: ScanFile, pos: int, end: int, ctx: int) -> Hit:
    text = sf.raw()
    line = sf.line_of(pos)
    lines = sf.lines()
    s = max(1, line - ctx)
    e = min(len(lines), sf.line_of(end) + ctx)
    match = re.sub(r"\s+", " ", text[pos:end].strip())[:200]
    if sf.kind == "native":
        offs = sf.offsets or []
        snippet = [f"0x{offs[i - 1]:08x}  {lines[i - 1][:200]}" for i in range(s, e + 1)]
        return Hit(sf.rel, line, match, s, snippet, "text",
                   offset=offs[line - 1] if line - 1 < len(offs) else None)
    lang = {"code": "smali" if sf.rel.endswith(".smali") else "java",
            "manifest": "xml", "resource": "xml"}.get(sf.kind, "text")
    hit = Hit(sf.rel, line, match, s, [l[:300] for l in lines[s - 1:e]], lang)
    if sf.kind == "code":
        hit.klass, hit.method = code_context(sf, line)
        hit.hook = frida_hook(hit.klass, hit.method)
    return hit


def match_rule(rule: Rule, pool: list[ScanFile], ctx: int) -> list[Hit]:
    hits: list[Hit] = []
    for sf in pool:
        t = sf.text()
        if not t or any(not p.search(t) for p in rule.all):
            continue
        seen = set()
        for pat in rule.any:
            for m in pat.finditer(t):
                ln = sf.line_of(m.start())
                if ln in seen:
                    continue
                seen.add(ln)
                if sf.kind == "filelist":
                    h = Hit("<danh sách file>", ln, m.group(), ln, [sf.lines()[ln - 1]])
                else:
                    h = make_hit(sf, m.start(), m.end(), ctx)
                if sf.kind in ("manifest", "filelist"):
                    h.confidence = "code"   # cấu hình / file có thật, không phải text tự do
                hits.append(h)
    return hits


# --------------------------------------------------------------------------- builtin: manifest
def builtin_exported(files: list[ScanFile], ctx: int) -> list[Hit]:
    """Component export (exported=true hoặc có intent-filter mà không khai báo) và không có permission."""
    hits = []
    for sf in files:
        if sf.kind != "manifest":
            continue
        t = sf.raw()
        for m in re.finditer(r"<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(/?)>", t, re.S):
            tag, attrs, selfclose = m.groups()
            body = ""
            if not selfclose:
                close = t.find(f"</{tag}>", m.end())
                body = t[m.end():close] if close != -1 else ""
            exported = re.search(r'android:exported="(\w+)"', attrs)
            is_exp = (exported and exported.group(1) == "true") or (not exported and "<intent-filter" in body)
            if not is_exp or "android:permission=" in attrs or "android.intent.category.LAUNCHER" in body:
                continue
            h = make_hit(sf, m.start(), m.end(), ctx)
            h.confidence = "code"   # manifest là cấu hình thật, không phải text tự do
            hits.append(h)
    return hits
