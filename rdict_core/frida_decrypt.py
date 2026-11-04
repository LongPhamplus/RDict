"""Giải mã string bằng Frida: gọi thẳng hàm giải mã trong process thật.

Engine dex đã biết tĩnh hàm giải mã và mọi tham số hằng truyền vào nó (kể cả ở nhánh code
không bao giờ chạy tới). Script Frida chỉ việc gọi lại hàm đó với từng bộ tham số, nên:
  * đúng với mọi thuật toán (XOR, AES, key lấy từ stack trace...), không cần giả lập;
  * không cần app tự chạy tới đoạn code đó.

Kết quả là bảng {(sig, args): plaintext}, lưu dạng JSON để dùng lại (--strings).
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

BEGIN, END = "RDICT_JSON_BEGIN", "RDICT_JSON_END"
JTYPE = {"Ljava/lang/String;": "java.lang.String", "I": "int", "J": "long", "S": "short",
         "B": "byte", "C": "char"}


def build_jobs(decryptors: list[dict]) -> list[dict]:
    jobs = []
    for d in decryptors:
        if any(p not in JTYPE for p in d["params"]):
            continue
        uniq = list(dict.fromkeys(a for _, _, a in d["const_calls"]))
        if not uniq:
            continue
        args = [[chr(x) if p == "C" else x for p, x in zip(d["params"], a)] for a in uniq]
        jobs.append({"sig": d["sig"], "cls": d["cls"][1:-1].replace("/", "."), "name": d["name"],
                     "types": [JTYPE[p] for p in d["params"]], "params": d["params"], "args": args})
    return jobs


AGENT = r"""
// Frida 17: Java bridge không còn nhúng sẵn -> xin host gửi source (giống frida CLI)
if (!('Java' in globalThis)) {
  Object.defineProperty(globalThis, 'Java', { configurable: true, get() {
    let b;
    send({ type: 'frida:load-bridge', name: 'Java' });
    recv('frida:bridge-loaded', m => {
      b = Script.evaluate('/frida/bridges/' + m.filename,
        '(function () { ' + m.source + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\nreturn bridge; })();");
    }).wait();
    return b;
  }});
}

const JOBS = __JOBS__;
const DELAY = __DELAY__;

function findClass(name) {
  try { return Java.use(name); } catch (e) {}
  for (const l of Java.enumerateClassLoadersSync()) {
    try { l.findClass(name); return Java.ClassFactory.get(l).use(name); } catch (e) {}
  }
  return null;
}

function work() {
  const results = [], errors = [];
  for (const j of JOBS) {
    let C = null;
    for (let i = 0; i < 20 && C === null; i++) { C = findClass(j.cls); if (C === null) Thread.sleep(0.25); }
    if (C === null) { errors.push(j.sig + ': không tìm thấy class ' + j.cls); continue; }
    let m;
    try { m = C[j.name].overload(...j.types); } catch (e) { errors.push(j.sig + ': ' + e); continue; }
    for (const a of j.args) {
      try {
        const r = m.call(C, ...a);
        results.push([j.sig, a, r === null ? null : r.toString()]);
      } catch (e) { errors.push(j.sig + JSON.stringify(a) + ': ' + e); }
    }
  }
  const out = { results: results, errors: errors };
  console.log('__BEGIN__' + JSON.stringify(out) + '__END__');
  send({ type: 'rdict:result', data: out });
}

Java.perform(() => { if (DELAY > 0) setTimeout(() => Java.perform(work), DELAY); else work(); });
"""


def make_script(jobs: list[dict], delay_ms: int = 0) -> str:
    return (AGENT.replace("__JOBS__", json.dumps(jobs, ensure_ascii=False))
            .replace("__DELAY__", str(int(delay_ms)))
            .replace("__BEGIN__", BEGIN).replace("__END__", END))


def to_mapping(jobs: list[dict], data: dict) -> dict[tuple, str]:
    params = {j["sig"]: j["params"] for j in jobs}
    out = {}
    for sig, args, plain in data.get("results", []):
        if plain is None:
            continue
        ps = params.get(sig, [])
        key = tuple(ord(x) if p == "C" and isinstance(x, str) else x for p, x in zip(ps, args)) if ps else tuple(args)
        out[(sig, key)] = plain
    return out


def save(path: Path, package: str | None, jobs: list[dict], data: dict) -> None:
    path.write_text(json.dumps({"version": 1, "package": package, "jobs": jobs, **data},
                               ensure_ascii=False, indent=1))


def load(path: Path, jobs: list[dict] | None = None) -> dict[tuple, str]:
    """Đọc JSON do rdict lưu, hoặc log của `frida -l script.js` (lấy đoạn giữa 2 marker)."""
    text = path.read_text(errors="surrogatepass")
    m = re.search(re.escape(BEGIN) + r"(.*?)" + re.escape(END), text, re.S)
    data = json.loads(m.group(1) if m else text)
    return to_mapping(data.get("jobs") or jobs or [], data)


def _bridge_handler(script):
    """Frida 17 không còn nhúng sẵn Java bridge khi dùng qua API: nạp từ frida_tools như CLI làm."""
    try:
        import frida_tools
        bridges = Path(frida_tools.__file__).parent / "bridges"
    except ImportError:
        bridges = None

    def handle(payload) -> bool:
        if not (isinstance(payload, dict) and payload.get("type") == "frida:load-bridge"):
            return False
        if bridges is None:
            raise RuntimeError("Frida 17 cần frida-tools để nạp Java bridge: pip install frida-tools")
        stem = payload["name"].lower()
        src = next(p for p in bridges.glob("*.js") if p.stem == stem)
        script.post({"type": "frida:bridge-loaded", "filename": src.name, "source": src.read_text(encoding="utf-8")})
        return True
    return handle


def run(package: str, jobs: list[dict], device_id: str | None = None, attach: bool = False,
        delay_ms: int = 0, timeout: float = 60.0, log=print) -> dict:
    import frida

    dev = frida.get_device(device_id, timeout=5) if device_id else frida.get_usb_device(timeout=5)
    pid = None
    if attach:
        procs = [a for a in dev.enumerate_applications() if a.identifier == package and a.pid]
        if not procs:
            raise RuntimeError(f"{package} chưa chạy trên {dev.name} (bỏ --attach để rdict tự khởi động app)")
        session = dev.attach(procs[0].pid)
    else:
        pid = dev.spawn([package])
        session = dev.attach(pid)

    done, box = threading.Event(), {}
    script = session.create_script(make_script(jobs, delay_ms))
    bridge = _bridge_handler(script)

    def on_message(msg, _data):
        if msg["type"] == "send":
            p = msg["payload"]
            if bridge(p):
                return
            if isinstance(p, dict) and p.get("type") == "rdict:result":
                box["data"] = p["data"]
                done.set()
        elif msg["type"] == "error":
            box.setdefault("errors", []).append(msg.get("description", str(msg)))

    def on_detached(reason, *_):
        box["detached"] = str(reason)
        done.set()

    script.set_log_handler(lambda *_: None)
    script.on("message", on_message)
    session.on("detached", on_detached)
    script.load()
    if pid is not None:
        dev.resume(pid)
    t0 = time.time()
    done.wait(timeout)
    if "data" not in box:
        why = box.get("detached") or (f"quá {timeout:.0f}s" if time.time() - t0 >= timeout else "không rõ")
        errs = "; ".join(box.get("errors", [])[:3])
        raise RuntimeError(f"Không nhận được kết quả ({why}). {errs}".strip()
                           + ("\nApp có thể có anti-Frida: thử --attach sau khi đã bypass, hoặc --frida-delay 0."
                              if box.get("detached") else ""))
    try:
        session.detach()
    except Exception:
        pass
    data = box["data"]
    data["errors"] = data.get("errors", []) + box.get("errors", [])
    return data
