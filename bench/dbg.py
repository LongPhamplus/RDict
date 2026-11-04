"""Debug 1 app DroidBench: dbg.py <tên app> [lọc summary theo tên method]"""
import json, sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from loguru import logger; logger.remove()
from pathlib import Path
from rdict_core.rules import load_rules
from rdict_core.dex_engine import DexEngine
rows = {r["name"]: r for r in json.load(open(os.path.join(ROOT, "bench/truth.json")))}
for r in rows.values():
    r["apk"] = os.path.expanduser(r["apk"])
R = [r for r in load_rules([Path(ROOT, "rules/flows.yaml")]) if r.id == "FLOW-PRIVACY-LEAK"]
d = DexEngine(Path(rows[sys.argv[1]]["apk"]), None)
import tempfile
from rdict_core.native_engine import load_apk_libs
with tempfile.TemporaryDirectory() as td:
    nat = load_apk_libs(rows[sys.argv[1]]["apk"], td)
fe = d.run_flows(R, nat)
for k, v in fe.natives.items():
    print("NATIVE", k, {x: y for x, y in v.items() if x != "targets"}, [t.name for t in v["targets"]])
sh = d.short
print("components", fe.components, "actions", fe.actions)
print("icc_links", {(sh(m), o): t for (m, o), t in fe.icc_links.items()})
print("analyzed", sorted(sh(m) for m in fe.irs))
for s in fe.sources: print("SRC", s.id, s.kind, s.sig[:80], sh(s.ma), s.off)
for f in fe.flows.values(): print("FLOW", f.src, "->", f.sink_sig[:70], [sh(m) for m in f.chain])
if len(sys.argv) > 2:
    for m, s in fe.summ.items():
        if sys.argv[2] in sh(m): print("SUMM", sh(m), m.descriptor, "p2ret", s.p2ret, "ret_src", s.ret_src, "p2sink", dict(s.p2sink), "p2field", dict(s.p2field))
print("fields", {k: v for k, v in fe.f_taint.items() if v})
for h in d.flow_hits(R[0], 0): print("NOTE", h.note)
