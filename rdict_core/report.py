from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .gates import KIND_ICON

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .model import CONF_ICON, SEVERITIES, Finding, Rule

SEV_STYLE = {"high": "bold red", "medium": "bold yellow", "low": "cyan", "info": "dim"}
CONF_STYLE = {"text": "dim", "code": "yellow", "behavior": "bold green"}
CONF_DESC = {"text": "khớp text", "code": "khớp cấu trúc", "behavior": "hành vi"}

console = Console()


def _app_panel(info: dict, target: str, engines: list[str], version: str) -> None:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold cyan")
    t.add_column()
    t.add_row("File", target)
    for k in ("package", "version", "minSdk", "targetSdk", "application"):
        if info.get(k):
            t.add_row(k, str(info[k]))
    if info.get("components"):
        t.add_row("components", ", ".join(f"{k}={v}" for k, v in info["components"].items()))
    if info.get("dex"):
        t.add_row("dex", ", ".join(info["dex"]))
    if info.get("native_libs"):
        t.add_row("native libs", ", ".join(info["native_libs"]))
    if info.get("permissions"):
        t.add_row("permissions", "\n".join(p.replace("android.permission.", "") for p in info["permissions"]))
    t.add_row("engines", ", ".join(engines))
    console.print(Panel(t, title=f"[bold]rdict {version}[/] — Thông tin ứng dụng", border_style="cyan"))


def print_report(info: dict, findings: list[Finding], target: str, show_hook: bool,
                 engines: list[str], version: str, show_bytecode: bool = False) -> None:
    _app_panel(info, target, engines, version)
    if not findings:
        console.print("[green]Không phát hiện kỹ thuật nào trong từ điển.[/]")
        return

    s = Table(title="Tổng quan kỹ thuật phát hiện", caption="Tin cậy: ●○○ khớp text · ●●○ khớp cấu trúc (bytecode/asm/manifest) · ●●● hành vi (nhiều API trong 1 luồng gọi)   |   ✓ = gọi tới được từ entry point")
    for col, kw in (("Mức", {"justify": "center"}), ("Tin cậy", {"justify": "center"}), ("✓", {"justify": "center"}),
                    ("ID", {}), ("Kỹ thuật", {}), ("Nhóm", {"style": "magenta"}), ("Hits", {"justify": "right"})):
        s.add_column(col, **kw)
    for f in findings:
        r = f.rule
        s.add_row(Text(r.severity.upper(), style=SEV_STYLE[r.severity]),
                  Text(CONF_ICON[f.confidence], style=CONF_STYLE[f.confidence]),
                  "✓" if f.reachable else "", r.id, r.name, r.category, str(f.total))
    console.print(s)

    for f in findings:
        r = f.rule
        head = Text()
        head.append(f"[{r.severity.upper()}] ", style=SEV_STYLE[r.severity])
        head.append(f"{r.id} — {r.name}", style="bold")
        head.append(f"   ({r.category}" + (" | MITRE " + ", ".join(r.mitre) if r.mitre else "") + ")", style="magenta")
        console.rule(head, align="left", style=SEV_STYLE[r.severity])
        if r.description:
            console.print(r.description)
        if r.hint:
            console.print(f"[green]💡 {r.hint}[/]")
        for h in f.hits:
            conf = Text(f" {CONF_ICON[h.confidence]} {CONF_DESC[h.confidence]} ", style=CONF_STYLE[h.confidence])
            if h.lang == "asm" and h.offset is not None:
                loc = f"{h.file} @ 0x{h.offset:x}"
            elif h.line:
                loc = f"{h.file}:{h.line}"
            else:
                loc = h.file
            line = Text("\n  📄 ")
            line.append(loc, style="bold blue")
            if h.method:
                line.append(f"  → {h.klass}{'!' if h.engine == 'native' else '.'}{h.method}" + ("" if h.engine == "native" else "()"), style="dim")
            line.append("  ")
            line.append_text(conf)
            console.print(line)
            console.print(Text(f"     match: {h.match}", style="bold"))
            if h.path:
                arrow = " → ".join(h.path)
                console.print(Text(f"     ↳ đường gọi: {arrow}", style="green"))
            elif h.reachable is False:
                console.print(Text("     ↳ không tìm thấy đường từ entry point (dead code? gọi qua reflection/native?)", style="dim red"))
            for g in h.gates or []:
                console.print(Text(f"     🔒 cần {KIND_ICON.get(g['kind'], '')} {g['cond']}   [{g['where']}]",
                                   style="yellow"))
            if h.note:
                for nl in h.note.split("\n"):
                    console.print(Text(f"     ℹ {nl}", style="cyan"))
            if h.bytecode and (show_bytecode or not h.snippet):
                for i, bl in enumerate(h.bytecode):
                    console.print(Text(("   ❱ " if i == h.bytecode_hl else "     ") + bl,
                                       style="bold yellow" if i == h.bytecode_hl else "dim"))
            if h.snippet:
                if h.lang in ("text", "asm"):
                    for i, l in enumerate(h.snippet):
                        hit = h.snippet_start + i == h.line
                        console.print(Text(("   ❱ " if hit else "     ") + l, style="bold yellow" if hit else "dim"))
                else:
                    console.print(Syntax("\n".join(h.snippet), h.lang, line_numbers=True,
                                         start_line=h.snippet_start, highlight_lines={h.line},
                                         theme="monokai", word_wrap=True, padding=(0, 2)))
            if show_hook and h.hook:
                console.print(Text("     frida: " + h.hook, style="dim green"))
        if f.total > len(f.hits):
            console.print(f"  [dim]... và {f.total - len(f.hits)} vị trí khác (tăng --max-hits để xem)[/]")
        console.print()

    counts = {s: sum(1 for f in findings if f.rule.severity == s) for s in reversed(SEVERITIES)}
    console.print(Panel(" ".join(f"[{SEV_STYLE[k]}]{k.upper()}: {v}[/]" for k, v in counts.items()),
                        title="Tổng kết", border_style="cyan"))


def to_dict(info: dict, findings: list[Finding], target: str, version: str) -> dict:
    out = []
    for f in findings:
        r = f.rule
        out.append({
            "id": r.id, "name": r.name, "category": r.category, "severity": r.severity,
            "confidence": f.confidence, "reachable": f.reachable,
            "mitre": r.mitre, "description": r.description, "hint": r.hint, "refs": r.refs,
            "total_hits": f.total, "hits": [asdict(h) for h in f.hits],
        })
    return {"tool": f"rdict {version}", "target": target, "app": info, "findings": out}


def write_markdown(path: Path, data: dict) -> None:
    L = [f"# Báo cáo rdict — `{Path(data['target']).name}`", ""]
    app = data["app"]
    L += ["## Thông tin ứng dụng", "", "| Trường | Giá trị |", "|---|---|"]
    for k in ("package", "version", "minSdk", "targetSdk", "application"):
        if app.get(k):
            L.append(f"| {k} | `{app[k]}` |")
    if app.get("native_libs"):
        L.append(f"| native libs | {', '.join(app['native_libs'])} |")
    if app.get("permissions"):
        L.append("| permissions | " + "<br>".join(app["permissions"]) + " |")
    L += ["", "## Tổng quan", "", "Tin cậy: ●○○ khớp text · ●●○ khớp cấu trúc (bytecode/asm/manifest) · ●●● hành vi", "",
          "| Mức | Tin cậy | Reach | ID | Kỹ thuật | Nhóm | Hits |", "|---|---|---|---|---|---|---|"]
    for f in data["findings"]:
        L.append(f"| {f['severity'].upper()} | {CONF_ICON[f['confidence']]} | {'✓' if f['reachable'] else ''} | "
                 f"{f['id']} | {f['name']} | {f['category']} | {f['total_hits']} |")
    L += ["", "## Chi tiết", ""]
    for f in data["findings"]:
        L.append(f"### [{f['severity'].upper()}] {f['id']} — {f['name']}")
        meta = f"**Nhóm:** {f['category']} · **Tin cậy:** {CONF_ICON[f['confidence']]}"
        if f["mitre"]:
            meta += f" · **MITRE:** {', '.join(f['mitre'])}"
        L += [meta, "", f["description"], ""]
        if f["hint"]:
            L += [f"> 💡 {f['hint']}", ""]
        for h in f["hits"]:
            where = f"`{h['file']}" + (f":{h['line']}" if h["line"] and h["lang"] != "asm" else "") + "`"
            if h.get("offset") is not None and h["lang"] == "asm":
                where += f" @ `0x{h['offset']:x}`"
            if h.get("method"):
                where += f" → `{h['klass']}.{h['method']}`"
            where += f" — {CONF_ICON[h['confidence']]}"
            L += [where, "", f"- match: `{h['match']}`"]
            if h.get("path"):
                L.append(f"- đường gọi: `{' → '.join(h['path'])}`")
            for g in h.get("gates") or []:
                L.append(f"- 🔒 cần {KIND_ICON.get(g['kind'], '')} `{g['cond']}` ({g['where']})")
            if h.get("note"):
                L += [f"- {n}" for n in h["note"].split("\n")]
            L.append("")
            if h.get("bytecode"):
                L += ["```smali"] + h["bytecode"] + ["```", ""]
            if h.get("snippet"):
                lang = {"asm": "asm", "text": ""}.get(h["lang"], h["lang"])
                L += [f"```{lang}"] + h["snippet"] + ["```", ""]
        if f["total_hits"] > len(f["hits"]):
            L += [f"_... và {f['total_hits'] - len(f['hits'])} vị trí khác_", ""]
        L += [f"- {ref}" for ref in f.get("refs", [])] + [""]
    path.write_text("\n".join(L))


def list_rules(rules: list[Rule]) -> None:
    t = Table(title=f"Từ điển kỹ thuật ({len(rules)} rule)")
    for c in ("ID", "Mức", "Kỹ thuật", "Nhóm", "Engine"):
        t.add_column(c)
    for r in sorted(rules, key=lambda r: (r.category, r.id)):
        eng = []
        if r.builtin:
            eng.append(f"builtin:{r.builtin}")
        if r.combo:
            eng.append("combo")
        if r.api or r.strings or r.fields:
            eng.append("dex")
        if r.has_native:
            eng.append("elf")
        if r.any:
            eng.append("regex")
        t.add_row(r.id, Text(r.severity, style=SEV_STYLE[r.severity]), r.name, r.category, ",".join(eng))
    console.print(t)


def explain(rules: list[Rule], rid: str) -> None:
    r = next((r for r in rules if r.id.lower() == rid.lower()), None)
    if not r:
        raise SystemExit(f"Không có rule {rid}")
    b = Text()
    b.append(f"{r.name}\n", style="bold")
    b.append(f"Nhóm: {r.category} | Mức: {r.severity} | Target: {', '.join(r.target)} | File: {r.source}\n")
    if r.mitre:
        b.append(f"MITRE: {', '.join(r.mitre)}\n")
    b.append(f"\n{r.description}\n")
    if r.hint:
        b.append(f"\n💡 {r.hint}\n", style="green")
    if r.builtin:
        b.append(f"\n[builtin] {r.builtin}", style="cyan")
    for label, pats in (("api", r.api), ("str", r.strings), ("field", r.fields), ("import", r.imports),
                        ("export", r.exports), ("all", r.all), ("regex", r.any)):
        for p in pats:
            b.append(f"\n[{label}] {p.pattern}", style="cyan")
    if r.in_method:
        b.append(f"\n[in_method] {r.in_method.pattern}", style="cyan")
    if r.combo:
        b.append(f"\n[combo depth={r.combo.depth}]", style="yellow")
        for lbl, g in zip(r.combo.labels, r.combo.groups):
            b.append(f"\n   {lbl or 'nhóm'}: " + " | ".join(map(str, g)), style="yellow")
    for ref in r.refs:
        b.append(f"\n🔗 {ref}", style="blue")
    console.print(Panel(b, title=r.id))
