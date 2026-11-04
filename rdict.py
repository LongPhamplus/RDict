#!/usr/bin/env python3
"""
rdict - Reverse Dictionary
Quét APK / DEX / JAR / .so / thư mục source, đối chiếu với "từ điển" kỹ thuật (rules/*.yaml)
và in ra các kỹ thuật nghi ngờ kèm bằng chứng (source, bytecode, asm, đường gọi).

Engine:
  dex     : bytecode Dalvik (androguard) — invoke/const-string/field, call graph, reflection, combo
  native  : ELF (lief + capstone)        — call site thật qua PLT, xref string, call graph native
  text    : regex trên source jadx / manifest / resource (fallback)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"

# Tự chạy lại bằng python trong .venv nếu thiếu thư viện phân tích
try:
    import androguard  # noqa: F401
    import lief  # noqa: F401
except ImportError:
    if (VENV / "bin/python").exists() and not os.environ.get("RDICT_REEXEC"):
        os.environ["RDICT_REEXEC"] = "1"
        os.execv(str(VENV / "bin/python"), [str(VENV / "bin/python"), str(Path(__file__).resolve()), *sys.argv[1:]])

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import zipfile  # noqa: E402

sys.path.insert(0, str(ROOT))
from rdict_core import report, text_engine as te  # noqa: E402
from rdict_core.model import CONFIDENCE, SEVERITIES, Finding, Hit, Rule  # noqa: E402
from rdict_core.report import console  # noqa: E402
from rdict_core.rules import load_rules  # noqa: E402

try:
    from rdict_core.dex_engine import DexEngine, jni_mangle, pretty_sig
    DEX_OK = True
except ImportError as e:
    DEX_OK, DEX_ERR = False, str(e)
try:
    from rdict_core.native_engine import NativeLib
    NATIVE_OK = True
except ImportError as e:
    NATIVE_OK, NATIVE_ERR = False, str(e)

VERSION = "0.3.0"
DEFAULT_RULES = ROOT / "rules"
CACHE_DIR = Path(os.environ.get("RDICT_CACHE", Path.home() / ".cache" / "rdict"))
DEX_BUILTINS = {"reflection", "string_decryptor", "insecure_tls", "jni_bridge", "crypto_autodecrypt", "payload_dex",
                "gate_time", "gate_secret", "gate_geo"}
NATIVE_BUILTINS = {"native_init_array", "native_entropy", "native_stripped", "native_cmp_const",
                   "native_stack_strings", "native_init_decrypt", "native_register_natives"}


# --------------------------------------------------------------------------- input prep
def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def decompile(inp: Path, fresh: bool, threads: int) -> tuple[Path, list[str]]:
    if not shutil.which("jadx"):
        raise SystemExit("Không tìm thấy jadx trong PATH.")
    out = CACHE_DIR / sha256(inp)[:16]
    filelist: list[str] = []
    if zipfile.is_zipfile(inp):
        with zipfile.ZipFile(inp) as z:
            filelist = z.namelist()
    if fresh and out.exists():
        shutil.rmtree(out)
    if not (out / ".done").exists():
        out.mkdir(parents=True, exist_ok=True)
        with console.status(f"[cyan]Đang decompile {inp.name} bằng jadx..."):
            subprocess.run(["jadx", "-d", str(out), "-j", str(threads), "--show-bad-code", "-q", str(inp)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if filelist and not any(out.rglob("*.so")):
            with zipfile.ZipFile(inp) as z:
                for n in filelist:
                    if n.endswith(".so"):
                        z.extract(n, out / "_native")
        if not any(out.iterdir()):
            shutil.rmtree(out, ignore_errors=True)
            raise SystemExit(f"jadx không decompile được {inp} (file hỏng hoặc không đúng định dạng).")
        (out / ".done").write_text(str(inp))
    else:
        console.print(f"[dim]Dùng cache jadx: {out}[/]")
    return out, filelist


def app_info(files: list[te.ScanFile], filelist: list[str]) -> dict:
    info: dict = {}
    man = next((f for f in files if f.kind == "manifest"), None)
    if man:
        t = man.raw()

        def g(rx):
            m = re.search(rx, t)
            return m.group(1) if m else None
        info["package"] = g(r'<manifest[^>]*\bpackage="([^"]+)"')
        info["version"] = g(r'android:versionName="([^"]+)"')
        info["minSdk"] = g(r'android:minSdkVersion="([^"]+)"')
        info["targetSdk"] = g(r'android:targetSdkVersion="([^"]+)"')
        info["application"] = g(r'<application[^>]*android:name="([^"]+)"')
        info["permissions"] = sorted(set(re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', t)))
        info["components"] = {k: len(re.findall(rf"<{k}\b", t)) for k in ("activity", "service", "receiver", "provider")}
    names = filelist or [f.rel for f in files]
    info["native_libs"] = sorted({Path(n).name for n in names if n.endswith(".so")})
    info["dex"] = sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n))
    return info


# --------------------------------------------------------------------------- string decryption
def handle_decrypt(args, dex, target: Path) -> list[dict]:
    from rdict_core import frida_decrypt as fd

    decs = dex.find_decryptors()
    want = args.frida_decrypt or args.frida_script or args.strings
    if not decs and not args.strings:
        if want:
            console.print("[yellow]! Không tìm thấy hàm giải mã string nào → không có gì để giải[/]")
        return []
    fe = getattr(dex, "flow", None)
    if fe is not None:                 # tham số hằng tìm được xuyên method / qua field / nối chuỗi
        for d in decs:
            have = {(id(m), o) for m, o, _ in d["const_calls"]}
            extra = [(m, o, a) for (m, o), a in fe.const_calls.get(d["sig"], {}).items() if (id(m), o) not in have]
            if extra:
                d["const_calls"] = list(d["const_calls"]) + extra
    jobs = fd.build_jobs(decs)
    n_args = sum(len(j["args"]) for j in jobs)
    pkg = dex.apk.get_package() if dex.apk else None
    cache = CACHE_DIR / f"{sha256(target)[:16]}.strings.json"   # ngoài thư mục jadx (không bị engine text quét)
    mapping: dict = {}

    if args.frida_script:
        if not pkg:
            raise SystemExit("--frida-script cần APK (để biết package)")
        args.frida_script.write_text(fd.make_script(jobs, args.frida_delay))
        console.print(f"[green]✓ Script Frida ({len(jobs)} hàm, {n_args} chuỗi): {args.frida_script}[/]\n"
                      f"  Chạy: [bold]frida -U -f {pkg} -l {args.frida_script} -q -t 30 > rdict.log[/]\n"
                      f"  Rồi:  [bold]rdict {target.name} --strings rdict.log[/]")
    if args.strings:
        mapping = fd.load(args.strings, jobs)
        console.print(f"[dim]Nạp {len(mapping)} chuỗi đã giải từ {args.strings}[/]")
    elif args.frida_decrypt:
        if not pkg:
            raise SystemExit("--frida-decrypt cần APK (để biết package)")
        if not jobs:
            console.print("[yellow]! Có hàm giải mã nhưng không lời gọi nào có tham số hằng → không gọi được[/]")
        else:
            with console.status(f"[cyan]Frida: gọi {len(jobs)} hàm giải mã với {n_args} bộ tham số trong {pkg}..."):
                try:
                    data = fd.run(pkg, jobs, args.device, args.attach, args.frida_delay)
                except ImportError:
                    raise SystemExit("Thiếu frida: .venv/bin/pip install frida frida-tools (cùng phiên bản frida-server)")
                except Exception as e:
                    raise SystemExit(f"Frida lỗi: {e}")
            fd.save(cache, pkg, jobs, data)
            mapping = fd.to_mapping(jobs, data)
            for err in data.get("errors", [])[:5]:
                console.print(f"[yellow]  ! {err}[/]")
            console.print(f"[green]✓ Frida giải được {len(mapping)}/{n_args} chuỗi[/] [dim](lưu ở {cache})[/]")
    elif cache.exists() and not args.fresh:
        mapping = fd.load(cache)
        console.print(f"[dim]Dùng {len(mapping)} chuỗi đã giải mã trong cache ({cache}) — --fresh để bỏ qua[/]")
    elif not args.frida_script:
        console.print(f"[yellow]ℹ Có {len(decs)} hàm giải mã string ({n_args} chuỗi giải được). "
                      f"Thêm --frida-decrypt để giải và quét lại trên chuỗi gốc.[/]")

    if not mapping:
        return []
    n = dex.apply_decrypted(mapping)
    rows = []
    for (ma, off), (sig, a, plain) in dex.dec_sites.items():
        rows.append({"where": f"{pretty_sig(ma.class_name + '->' + ma.name + ma.descriptor).split('(')[0]}+{off:#x}",
                     "decryptor": pretty_sig(sig).split("(")[0], "args": list(a), "plain": plain})
    rows.sort(key=lambda r: r["where"])
    console.print(f"[dim]  → {n} chỗ gọi được thay bằng chuỗi gốc[/]")
    if args.dump_strings:
        from rich.table import Table
        t = Table(title=f"Chuỗi đã giải mã ({len(rows)})", show_lines=False)
        t.add_column("Vị trí", style="cyan")
        t.add_column("Chuỗi gốc", style="bold")
        for r in rows:
            t.add_row(r["where"], repr(r["plain"])[:160])
        console.print(t)
    return rows


# --------------------------------------------------------------------------- scanning
class Scanner:
    def __init__(self, files, filelist, dex, natives, include_libs, ctx):
        self.files, self.dex, self.natives = files, dex, natives
        self.include_libs, self.ctx = include_libs, ctx
        self.native_rels = {lib.rel for lib in natives}
        fl = "\n".join(filelist) if filelist else "\n".join(f.rel for f in files)
        self.fl_file = te.ScanFile("<filelist>", "filelist", Path("."), text=fl)

    def builtin(self, rule: Rule) -> list[Hit]:
        b, ctx = rule.builtin, self.ctx
        if b == "exported_components":
            return te.builtin_exported(self.files, ctx)
        if b in DEX_BUILTINS and not self.dex:
            return []
        if b == "reflection":
            return self.dex.builtin_reflection(ctx)
        if b == "string_decryptor":
            return self.dex.builtin_string_decryptor(ctx)
        if b == "crypto_autodecrypt":
            return self.dex.builtin_crypto_autodecrypt(ctx)
        if b == "insecure_tls":
            return self.dex.builtin_insecure_tls(ctx)
        if b == "payload_dex":
            return self.dex.builtin_payload_dex(ctx)
        if b.startswith("gate_"):
            return self.dex.builtin_gate(b[5:], ctx)
        if b == "jni_bridge":
            return self.jni_bridge()
        out = []
        for lib in self.natives:
            fn = {"native_init_array": lib.builtin_init_array, "native_entropy": lib.builtin_entropy,
                  "native_stripped": lib.builtin_stripped, "native_cmp_const": lib.builtin_cmp_const,
                  "native_stack_strings": lib.builtin_stack_strings, "native_init_decrypt": lib.builtin_init_decrypt,
                  "native_register_natives": lib.builtin_register_natives}[b]
            out += fn(ctx)
        return out

    def jni_bridge(self) -> list[Hit]:
        exports = {n: (lib, a) for lib in self.natives for n, a in lib.exports.items()}
        onload = [lib.name for lib in self.natives if "JNI_OnLoad" in lib.exports]
        hits = []
        for ma in self.dex.native_methods:
            sym = f"Java_{jni_mangle(ma.class_name[1:-1])}_{jni_mangle(ma.name)}"
            found = exports.get(sym) or next((v for k, v in exports.items() if k.startswith(sym + "__")), None)
            if found:
                lib, a = found
                imps = lib.reach_imports(a) if lib.ok else []
                note = f"Hiện thực tại {lib.name}!{sym} @ 0x{a:x}" + (f"\nhàm native gọi tới: {', '.join(imps[:15])}" if imps else "")
            elif (dyn := next(((lib, fn, sg) for lib in self.natives if lib.emu for n_, sg, fn in lib.emu.natives
                               if n_ == ma.name), None)):
                lib, fn, sg = dyn
                note = (f"Đăng ký động (RegisterNatives trong JNI_OnLoad, tìm bằng giả lập) → {lib.name}!{lib.fname(fn)} "
                        f"@ 0x{fn:x}  {sg}")
            else:
                note = ("Không có export Java_* tương ứng → đăng ký động qua RegisterNatives"
                        + (f" trong JNI_OnLoad của {', '.join(onload)}" if onload else "")
                        + "\nHook RegisterNatives để lấy địa chỉ thật.")
            hits.append(self.dex.make_hit(ma, None, f"native {pretty_sig(f'{ma.class_name}->{ma.name}{ma.descriptor}')}",
                                          ma.name, self.ctx, note=note))
        return hits

    def run(self, rule: Rule) -> list[Hit]:
        hits: list[Hit] = []
        if rule.builtin:
            hits += self.builtin(rule)
        dex_used = bool(self.dex) and (rule.has_dex or rule.builtin in DEX_BUILTINS)
        if self.dex and (rule.api or rule.strings or rule.fields):
            hits += self.dex.match(rule, self.ctx, rule.in_method)
        if self.dex and rule.combo:
            hits += self.dex.combo(rule, self.ctx)
        if self.dex and rule.flow:
            hits += self.dex.flow_hits(rule, self.ctx)
        if rule.has_native or ("native" in rule.target and rule.any):
            for lib in self.natives:
                hits += lib.match(rule, self.ctx)
        # regex fallback
        tt = set(rule.target)
        if dex_used:
            tt.discard("code")
        if rule.any and tt:
            pool = [self.fl_file] if "filelist" in tt else []
            pool += [f for f in self.files if f.kind in tt and f.kind != "filelist"
                     and f.rel not in self.native_rels
                     and (self.include_libs or rule.include_libs or not f.is_lib)]
            hits += te.match_rule(rule, pool, self.ctx)
        if rule.exclude:
            hits = [h for h in hits if not any(p.search(h.file) or (h.klass and p.search(h.klass)) for p in rule.exclude)]
        # dedupe + sắp xếp: tin cậy cao, reachable trước
        uniq, seen, by_line = [], set(), {}
        for h in hits:
            if h.key() in seen:
                continue
            seen.add(h.key())
            # gộp nhiều match trên cùng một dòng source (vd. mảng path su) thành 1 bằng chứng
            lk = (h.file, h.line, h.method, h.confidence) if h.line and h.lang != "asm" else None
            if lk and lk in by_line:
                prev = by_line[lk]
                if h.match not in prev.match and len(prev.match) < 300:
                    prev.match += " | " + h.match
                continue
            if lk:
                by_line[lk] = h
            uniq.append(h)
        uniq.sort(key=lambda h: (-CONFIDENCE.index(h.confidence), not h.reachable))
        return uniq


# --------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(prog="rdict", description="Reverse Dictionary — phát hiện kỹ thuật trong APK/DEX/JAR/.so")
    ap.add_argument("target", nargs="?", help="APK/DEX/JAR/AAR, file .so/ELF, hoặc thư mục source đã decompile")
    ap.add_argument("-r", "--rules", action="append", type=Path, help="Thêm thư mục/file rule (lặp được)")
    ap.add_argument("-s", "--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("-t", "--min-conf", choices=CONFIDENCE, default="text",
                    help="Độ tin cậy tối thiểu: text | code | behavior (mặc định text)")
    ap.add_argument("-c", "--category", action="append", help="Chỉ hiện nhóm này (lặp được)")
    ap.add_argument("-i", "--id", action="append", help="Chỉ chạy rule có ID (hoặc prefix) này")
    ap.add_argument("-a", "--all", action="store_true", help="Quét cả code thư viện (androidx, okhttp, ...)")
    ap.add_argument("-C", "--context", type=int, default=3, help="Số dòng ngữ cảnh (mặc định 3)")
    ap.add_argument("-m", "--max-hits", type=int, default=5, help="Số bằng chứng tối đa mỗi kỹ thuật (mặc định 5)")
    ap.add_argument("--reachable", action="store_true", help="Chỉ giữ bằng chứng gọi tới được từ entry point")
    ap.add_argument("--hook", action="store_true", help="In Frida hook cho từng bằng chứng")
    ap.add_argument("-b", "--bytecode", action="store_true", help="Luôn in bytecode Dalvik cạnh source")
    ap.add_argument("--no-dex", action="store_true", help="Tắt engine bytecode")
    ap.add_argument("--no-native", action="store_true", help="Tắt engine ELF")
    ap.add_argument("--no-flow", action="store_true", help="Tắt phân tích luồng dữ liệu (taint)")
    ap.add_argument("--no-emu", action="store_true", help="Tắt giả lập code native (unicorn)")
    ap.add_argument("--flow-libs", action="store_true", help="Phân tích luồng cả code thư viện (chậm, tốn RAM)")
    ap.add_argument("--flow-budget", type=float, default=180, metavar="S", help="Giới hạn thời gian phân tích luồng (giây)")
    ap.add_argument("--json", type=Path, help="Xuất JSON")
    ap.add_argument("--md", type=Path, help="Xuất báo cáo Markdown")
    ap.add_argument("--fresh", action="store_true", help="Bỏ cache, decompile lại")
    ap.add_argument("-j", "--threads", type=int, default=os.cpu_count() or 4)
    ap.add_argument("-l", "--list-rules", action="store_true", help="Liệt kê từ điển")
    ap.add_argument("-e", "--explain", metavar="ID", help="Xem chi tiết một rule")
    g = ap.add_argument_group("giải mã string (cần Frida + thiết bị)")
    g.add_argument("--frida-decrypt", action="store_true",
                   help="Khởi động app qua Frida, gọi hàm giải mã với mọi tham số tìm được, rồi quét lại trên chuỗi gốc")
    g.add_argument("--attach", action="store_true", help="Attach vào app đang chạy thay vì spawn (khi app có anti-Frida)")
    g.add_argument("-D", "--device", help="ID thiết bị Frida (mặc định: USB)")
    g.add_argument("--frida-delay", type=int, default=1000, metavar="MS",
                   help="Chờ sau khi app khởi tạo rồi mới gọi (mặc định 1000ms; 0 = gọi ngay, trước anti-Frida)")
    g.add_argument("--frida-script", type=Path, metavar="FILE", help="Chỉ sinh script Frida để tự chạy tay")
    g.add_argument("--strings", type=Path, metavar="FILE", help="Nạp chuỗi đã giải (JSON của rdict, hoặc log của frida -l)")
    g.add_argument("--dump-strings", action="store_true", help="In toàn bộ chuỗi đã giải mã")
    ap.add_argument("--gate-script", type=Path, metavar="FILE",
                    help="Sinh script Frida ép các điều kiện chặn (🔒) về phía mở khóa: frida -U -f <pkg> -l FILE")
    ap.add_argument("-q", "--quiet", action="store_true", help="Không in chi tiết (dùng với --json/--md)")
    args = ap.parse_args()

    rules = load_rules([DEFAULT_RULES] + (args.rules or []), warn=lambda m: console.print(f"[yellow]{m}[/]"))
    if args.list_rules:
        return report.list_rules(rules)
    if args.explain:
        return report.explain(rules, args.explain)
    if not args.target:
        ap.error("cần chỉ định target (hoặc dùng --list-rules)")

    rules = [r for r in rules if SEVERITIES.index(r.severity) >= SEVERITIES.index(args.min_severity)]
    if args.category:
        cats = {c.lower() for c in args.category}
        rules = [r for r in rules if r.category.lower() in cats]
    if args.id:
        rules = [r for r in rules if any(r.id.lower().startswith(i.lower()) for i in args.id)]

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"Không tồn tại: {target}")
    if target.is_file() and target.stat().st_size == 0:
        raise SystemExit(f"File rỗng (0 byte): {target}")

    t0 = time.time()
    filelist: list[str] = []
    sources_root = None
    is_elf = target.is_file() and (target.suffix == ".so" or te.is_elf(target))
    if target.is_dir():
        files = te.collect(target)
        sources_root = next((p for p in [target / "sources", target] if p.is_dir()), None)
    elif is_elf:
        files = [te.ScanFile(target.name, "native", target)]
    else:
        out, filelist = decompile(target, args.fresh, args.threads)
        files = te.collect(out)
        sources_root = out / "sources"

    if not args.all:
        third = [f for f in files if f.kind == "native" and te.KNOWN_NATIVE.match(f.path.name)]
        if third:
            files = [f for f in files if f not in third]
            console.print(f"[dim]Bỏ qua {len(third)} thư viện native bên thứ ba ({', '.join(f.path.name for f in third[:6])}"
                          f"{'...' if len(third) > 6 else ''}) — dùng -a để quét cả[/]")

    engines = ["text"]
    dex = None
    if not args.no_dex and not target.is_dir() and not is_elf:
        if not DEX_OK:
            console.print(f"[yellow]! Engine dex tắt (thiếu androguard: {DEX_ERR})[/]")
        else:
            with console.status("[cyan]Đang phân tích bytecode (androguard)..."):
                try:
                    dex = DexEngine(target, sources_root, include_libs=args.all)
                    engines.insert(0, f"dex({dex.n_methods} methods)")
                except Exception as e:
                    console.print(f"[yellow]! Không phân tích được bytecode: {e}[/]")

    natives = []
    if not args.no_native:
        if not NATIVE_OK:
            console.print(f"[yellow]! Engine native tắt (thiếu lief/capstone: {NATIVE_ERR})[/]")
        else:
            with console.status("[cyan]Đang phân tích thư viện native (lief + capstone)..."):
                for sf in files:
                    if sf.kind != "native":
                        continue
                    lib = NativeLib(sf)
                    if getattr(lib, "b", None) is None:
                        continue
                    if not lib.ok:
                        console.print(f"[dim]  {lib.name}: {lib.reason}[/]")
                    natives.append(lib)
            if natives:
                engines.insert(1 if dex else 0, "native(" + ", ".join(f"{l.name}/{l.arch}" for l in natives) + ")")

    if args.no_emu:
        for lib in natives:
            lib._emu = None
    want_flow = dex is not None and not args.no_flow
    flow_rules = rules if any(r.flow for r in rules) else []

    def do_flow():
        t1 = time.time()
        with console.status("[cyan]Đang phân tích luồng giá trị (hằng số + taint)..."):
            try:
                dex.flow_libs, dex.flow_budget = args.flow_libs, args.flow_budget
                fe = dex.run_flows(flow_rules, natives)
                if fe.truncated:
                    console.print(f"[yellow]! Phân tích luồng dừng sau {args.flow_budget:.0f}s (--flow-budget): "
                                  f"kết quả có thể thiếu[/]")
                jni = f", JNI {len(fe.natives)} method native" if fe.natives else ""
                return f"flow({len(fe.irs)}/{fe.n_total} methods, {fe.rounds} vòng{jni}, {time.time() - t1:.0f}s)"
            except Exception as e:
                console.print(f"[yellow]! Phân tích luồng dữ liệu lỗi: {e}[/]")
                return None

    flow_desc = do_flow() if want_flow else None
    decrypted_rows = handle_decrypt(args, dex, target) if dex else []
    if want_flow and decrypted_rows:
        flow_desc = do_flow()          # chạy lại: chuỗi đã giải mã giúp giải reflection / crypto
    if flow_desc:
        engines[0] += " + " + flow_desc

    scanner = Scanner(files, filelist, dex, natives, args.all, args.context)
    findings: list[Finding] = []
    min_conf = CONFIDENCE.index(args.min_conf)
    with console.status("[cyan]Đang đối chiếu từ điển...") as st:
        for rule in rules:
            st.update(f"[cyan]Đang đối chiếu[/] {rule.id}")
            hits = [h for h in scanner.run(rule) if CONFIDENCE.index(h.confidence) >= min_conf]
            if args.reachable:
                hits = [h for h in hits if h.reachable or h.reachable is None and h.engine == "text"]
            if hits:
                findings.append(Finding(rule, hits[: args.max_hits], len(hits)))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.rule.severity), -CONFIDENCE.index(f.confidence), f.rule.id))

    info = app_info(files, filelist)
    data = report.to_dict(info, findings, str(target), VERSION)
    if decrypted_rows:
        data["decrypted_strings"] = decrypted_rows
    if not args.quiet:
        report.print_report(info, findings, str(target), args.hook, engines, VERSION, args.bytecode)
    console.print(f"[dim]Hoàn tất trong {time.time() - t0:.1f}s[/]")
    if args.json:
        args.json.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        console.print(f"[green]✓ JSON: {args.json}[/]")
    if args.md:
        report.write_markdown(args.md, data)
        console.print(f"[green]✓ Markdown: {args.md}[/]")
    if args.gate_script:
        from rdict_core import gate_script
        gs = gate_script.collect(findings)
        pkg = dex.apk.get_package() if dex and dex.apk else "<package>"
        args.gate_script.write_text(gate_script.make(gs, pkg, args.gate_script.name))
        console.print(f"[green]✓ Script ép {len(gs)} điều kiện chặn: {args.gate_script}[/]\n"
                      f"  Chạy: [bold]frida -U -f {pkg} -l {args.gate_script}[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
