"""In các luồng của FLOW-PRIVACY-LEAK theo tag của lời gọi sink (const-string gần nhất trước sink).
Dùng cho app test có tag dạng X_..._LEAK / X_..._SAFE: tests/flowtags.py <apk>"""
import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from loguru import logger; logger.remove()
from pathlib import Path
from rdict_core.dex_engine import DexEngine
from rdict_core.rules import load_rules
d = DexEngine(Path(sys.argv[1]), None)
R = [r for r in load_rules([Path(ROOT, "rules/flows.yaml")]) if r.id == "FLOW-PRIVACY-LEAK"]
import tempfile
from rdict_core.native_engine import load_apk_libs
with tempfile.TemporaryDirectory() as td:
    natives = load_apk_libs(sys.argv[1], td)
fe = d.run_flows(R, natives)
if "-v" in sys.argv:
    for k, v in fe.natives.items():
        print("JNI", k.split("->")[1], v["fn"], v["jsigs"], v["csinks"], [t.name for t in v["targets"]])
def tag(ma, off):
    last, o = None, 0
    for ins in ma.get_method().get_instructions():
        if o >= off:
            break
        if ins.get_name().startswith("const-string"):
            last = ins.get_output().split(", ", 1)[1].strip('"')
        o += ins.get_length()
    return last
got = sorted({tag(f.sink_ma, f.sink_off) or f.sink_sig for f in fe.flows_for(*R[0].flow)}, key=str)
print(" ".join(map(str, got)))
