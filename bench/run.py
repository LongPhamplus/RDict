"""Chấm FLOW-PRIVACY-LEAK trên DroidBench (mức app). Dùng: run.py OUT.json [regex tên app]
Cần DroidBench ở ~/.cache/rdict/bench/DroidBench (xem bench/README)."""
import json, sys, time, os, re
from multiprocessing import Pool
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from loguru import logger; logger.remove()
from pathlib import Path
from rdict_core.rules import load_rules
from rdict_core.model import Combo, ComboItem, Rule

RULES = [r for r in load_rules([Path(ROOT, "rules/flows.yaml")]) if r.id == "FLOW-PRIVACY-LEAK"]
R = RULES[0]
BASE = Rule(id="BASE", name="b", category="b", severity="high", description="", target=["code"],
            combo=Combo(depth=2, groups=[[ComboItem("api", p) for k, p in R.flow[0] if k == "api"],
                                          [ComboItem("api", p) for p in R.flow[1]]], labels=["s", "k"]))

def one(row):
    from rdict_core.dex_engine import DexEngine
    t0 = time.time()
    out = {"name": row["name"], "cat": row["cat"], "truth": row["leaks"]}
    try:
        d = DexEngine(Path(row["apk"]), None)
        out["base"] = len(d.combo(BASE, 0)) > 0
        natives = []
        if not os.environ.get("NO_NATIVE"):
            import tempfile
            from rdict_core.native_engine import load_apk_libs
            with tempfile.TemporaryDirectory(prefix="rdict_nat_") as td:
                natives = load_apk_libs(row["apk"], td)
        fe = d.run_flows(RULES, natives)
        fl = fe.flows_for(*R.flow)
        reach = d.cha.reachable
        out["taint_all"] = len(fl)
        out["taint_reach"] = sum(1 for f in fl if f.chain[0] in reach and fe.sources[f.src].ma in reach)
        out["sinks"] = sorted({f.sink_sig.split("(")[0] for f in fl})
    except Exception:
        import traceback
        out["err"] = traceback.format_exc()[-600:]
    out["t"] = round(time.time() - t0, 2)
    return out

def score(res, key, pred):
    tp = sum(1 for r in res if r["truth"] > 0 and pred(r)); fn = sum(1 for r in res if r["truth"] > 0 and not pred(r))
    fp = sum(1 for r in res if r["truth"] == 0 and pred(r)); tn = sum(1 for r in res if r["truth"] == 0 and not pred(r))
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    print(f"{key:12s} TP={tp:3d} FN={fn:3d} FP={fp:3d} TN={tn:3d}  precision={prec:.2f} recall={rec:.2f} F1={f1:.2f}")

if __name__ == "__main__":
    rows = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "truth.json")))
    for r in rows:
        r["apk"] = os.path.expanduser(r["apk"])
    if len(sys.argv) > 2:
        rows = [r for r in rows if re.search(sys.argv[2], r["name"] + " " + r["cat"])]
    with Pool(8) as p:
        res = p.map(one, rows, chunksize=1)
    json.dump(res, open(sys.argv[1], "w"), indent=1)
    ok = [r for r in res if "err" not in r]
    errs = [r for r in res if "err" in r]
    print(f"{len(ok)} app ok, {len(errs)} lỗi, tổng {sum(r['t'] for r in res):.0f}s CPU")
    for r in errs[:3]: print(r["name"], r["err"])
    score(ok, "combo(cũ)", lambda r: r["base"])
    score(ok, "taint-all", lambda r: r["taint_all"] > 0)
    score(ok, "taint-reach", lambda r: r["taint_reach"] > 0)
    icc = [r for r in ok if r["cat"] in ("InterComponentCommunication", "InterAppCommunication", "Reflection_ICC")
           and r["truth"] > 0]
    send = re.compile(r"->(?:startActivit|startService|bindService|sendBroadcast|sendOrdered|setResult)")
    e2e = sum(1 for r in icc if any(not send.search(x) for x in r.get("sinks", [])))
    print(f"ICC: {e2e}/{len(icc)} app có luồng tới đích thật bên component nhận (không dừng ở startActivity/sendBroadcast)")
