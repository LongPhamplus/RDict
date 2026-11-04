from __future__ import annotations

import re
from pathlib import Path

import yaml

from .model import Combo, ComboItem, Rule, SEVERITIES, TARGETS

BUILTINS = {
    "exported_components", "reflection", "string_decryptor", "jni_bridge",
    "native_init_array", "native_entropy", "native_stripped", "insecure_tls", "crypto_autodecrypt",
    "native_cmp_const", "native_stack_strings", "native_init_decrypt", "native_register_natives", "payload_dex",
}


def _compile(rid: str, pats, flags) -> list[re.Pattern]:
    out = []
    for p in pats or []:
        try:
            out.append(re.compile(p, flags))
        except re.error as e:
            raise SystemExit(f"Rule {rid}: regex lỗi '{p}': {e}")
    return out


def _combo(rid: str, c: dict, flags) -> Combo:
    groups, labels = [], []
    for g in c["groups"]:
        if isinstance(g, dict):
            labels.append(g.get("label", ""))
            items = g["items"]
        else:
            labels.append("")
            items = g
        grp = []
        for it in items:
            kind, _, pat = it.partition(":") if it.split(":", 1)[0] in ("api", "str", "field") else ("api", "", it)
            grp.append(ComboItem(kind, _compile(rid, [pat], flags)[0]))
        groups.append(grp)
    return Combo(depth=int(c.get("depth", 0)), groups=groups, labels=labels)


def _flow(rid: str, f: dict, flags):
    src = []
    for it in f.get("source", []):
        kind, _, pat = it.partition(":") if it.split(":", 1)[0] in ("api", "cb", "field") else ("api", "", it)
        src.append((kind, _compile(rid, [pat], flags)[0]))
    sinks = _compile(rid, [it.split(":", 1)[1] if it.startswith("api:") else it for it in f.get("sink", [])], flags)
    if not src or not sinks:
        raise SystemExit(f"Rule {rid}: flow cần cả source và sink")
    return src, sinks


def load_rules(paths: list[Path], warn=print) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for d in paths:
        files = sorted(d.glob("*.y*ml")) if d.is_dir() else [d]
        for f in files:
            data = yaml.safe_load(f.read_text()) or {}
            for r in data.get("rules", []):
                rid = r["id"]
                if rid in seen:
                    warn(f"! Rule trùng id {rid} trong {f.name}, bỏ qua")
                    continue
                seen.add(rid)
                flags = re.MULTILINE | (re.IGNORECASE if r.get("ignore_case") else 0)
                tgt = r.get("target", ["code"])
                tgt = [tgt] if isinstance(tgt, str) else tgt
                if bad := set(tgt) - TARGETS:
                    raise SystemExit(f"Rule {rid}: target không hợp lệ {bad}")
                sev = r.get("severity", "info")
                if sev not in SEVERITIES:
                    raise SystemExit(f"Rule {rid}: severity không hợp lệ {sev}")
                b = r.get("builtin")
                if b and b not in BUILTINS:
                    raise SystemExit(f"Rule {rid}: builtin không tồn tại {b}")
                rules.append(Rule(
                    id=rid, name=r["name"], category=r.get("category", "Misc"), severity=sev,
                    description=(r.get("description") or "").strip(), target=tgt,
                    any=_compile(rid, r.get("any"), flags),
                    all=_compile(rid, r.get("all"), flags),
                    api=_compile(rid, r.get("api"), flags),
                    strings=_compile(rid, r.get("strings"), flags),
                    fields=_compile(rid, r.get("fields"), flags),
                    combo=_combo(rid, r["combo"], flags) if r.get("combo") else None,
                    flow=_flow(rid, r["flow"], flags) if r.get("flow") else None,
                    in_method=re.compile(r["in_method"]) if r.get("in_method") else None,
                    exclude=_compile(rid, r.get("exclude"), 0),
                    imports=_compile(rid, r.get("imports"), flags),
                    exports=_compile(rid, r.get("exports"), flags),
                    builtin=b, hint=(r.get("hint") or "").strip(),
                    mitre=r.get("mitre", []), refs=r.get("refs", []),
                    include_libs=r.get("include_libs", False), source=f.name,
                ))
    return rules
