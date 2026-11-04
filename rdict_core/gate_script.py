"""Sinh script Frida ép các cổng chặn (gates.py) về phía "mở khóa" để hành vi bị giấu chạy ngay trên thiết bị.

Chạy: frida -U -f <pkg> -l gates.js
  - ret     : method boolean (isRooted, isEmulator, checkLicense...) -> trả về giá trị cần
  - eq      : String.equals / equalsIgnoreCase / contentEquals so với chuỗi hằng -> true
  - ret_str : getter quốc gia/ngôn ngữ (getSimCountryIso, Locale.getCountry...) -> trả về chuỗi cần
  - time    : System.currentTimeMillis -> kẹp vào khoảng thỏa mọi mốc thời gian
"""
from __future__ import annotations

import json

from .flow.ir import split_desc

PRIM = {"Z": "boolean", "B": "byte", "C": "char", "S": "short", "I": "int", "J": "long", "F": "float", "D": "double"}


def jtype(t: str) -> str:
    if t in PRIM:
        return PRIM[t]
    if t.startswith("["):
        return t.replace("/", ".")
    return t[1:-1].replace("/", ".")


def collect(findings) -> list[dict]:
    """Gom gate có cách ép từ các finding đang báo cáo (bỏ trùng, gộp nơi xuất hiện)."""
    out: dict = {}
    for f in findings:
        for h in f.hits:
            for g in h.gates or []:
                if not g.get("force"):
                    continue
                k = json.dumps(g["force"], ensure_ascii=False)
                if k not in out:
                    out[k] = {"force": g["force"], "cond": g["cond"], "kind": g["kind"], "where": set(), "rules": set()}
                out[k]["where"].add(g["where"])
                out[k]["rules"].add(f.rule.id)
    return list(out.values())


HEAD = r"""// rdict --gate-script: ép các điều kiện chặn về phía "mở khóa".
// Chạy: frida -U -f %PKG% -l %FILE%
'use strict';
function rlog(m) { console.log('[rdict] ' + m); }
function findClass(name) {
  try { return Java.use(name); } catch (e) {}
  for (const l of Java.enumerateClassLoadersSync()) {
    try { l.findClass(name); return Java.ClassFactory.get(l).use(name); } catch (e) {}
  }
  return null;
}
const PENDING = [];
function hookRet(cls, name, types, val, why) {
  const C = findClass(cls);
  if (!C) { PENDING.push(() => hookRet(cls, name, types, val, why)); return false; }
  try {
    C[name].overload.apply(C[name], types).implementation = function () {
      rlog('ép ' + cls + '.' + name + ' -> ' + val + '   (' + why + ')');
      return val;
    };
    rlog('đã hook ' + cls + '.' + name);
  } catch (e) { rlog('không hook được ' + cls + '.' + name + ': ' + e); }
  return true;
}
"""

TAIL = r"""
  // class nạp muộn (payload, multidex): thử lại vài lần
  let tries = 0;
  const t = setInterval(() => {
    if (!PENDING.length || ++tries > 20) { clearInterval(t); if (PENDING.length) rlog(PENDING.length + ' hook chưa gắn được (class chưa nạp)'); return; }
    Java.perform(() => { const p = PENDING.splice(0); p.forEach(f => f()); });
  }, 1500);
});
"""


def make(gates: list[dict], pkg: str = "<package>", fname: str = "gates.js") -> str:
    L = [HEAD.replace("%PKG%", pkg).replace("%FILE%", fname), "Java.perform(function () {"]
    eqs, lo, hi, shift = {}, None, None, 0
    for g in gates:
        kind, *a = g["force"]
        why = f"{g['cond']} @ {', '.join(sorted(g['where']))}"[:160]
        L.append(f"  // [{g['kind']}] cần: {g['cond']}  — {', '.join(sorted(g['where']))}  ({', '.join(sorted(g['rules']))})")
        if kind in ("ret", "ret_str"):
            sig, val = a
            cls, rest = sig.split("->", 1)
            name = rest.split("(", 1)[0]
            params, _ = split_desc(rest[rest.index("("):])
            off = "// " if g["kind"] == "other" else ""      # cổng không rõ mục đích: bỏ comment nếu muốn ép
            L.append(f"  {off}hookRet({json.dumps(jtype(cls))}, {json.dumps(name)}, {json.dumps([jtype(p) for p in params])}, "
                     f"{json.dumps(val, ensure_ascii=False)}, {json.dumps(why, ensure_ascii=False)});")
        elif kind == "eq":
            eqs[a[0]] = why
        elif kind == "shift":
            shift = max(shift, a[0])
        elif kind == "time":
            rel, T = a
            if rel in (">", ">="):
                v = T + 1 if rel == ">" else T
                lo = v if lo is None else max(lo, v)
            else:
                v = T - 1 if rel == "<" else T
                hi = v if hi is None else min(hi, v)
    if eqs:
        L.append(f"  const EQ = {json.dumps(eqs, ensure_ascii=False, indent=None)};")
        L.append(r"""  const S = Java.use('java.lang.String');
  ['equals', 'equalsIgnoreCase', 'contentEquals'].forEach(n => {
    S[n].overloads.forEach(o => {
      o.implementation = function (x) {
        const r = o.call(this, x);
        if (r || x === null) return r;
        const a = this.toString(), b = x.toString();
        const k = Object.prototype.hasOwnProperty.call(EQ, b) ? b : (Object.prototype.hasOwnProperty.call(EQ, a) ? a : null);
        if (k !== null) { rlog('ép "' + a + '".' + n + '("' + b + '") -> true   (' + EQ[k] + ')'); return true; }
        return r;
      };
    });
  });""")
    if lo is not None or hi is not None or shift:
        if lo is not None and hi is not None and lo > hi:
            L.append(f"  // các mốc thời gian mâu thuẫn ({lo} > {hi}): chỉ ép mốc dưới")
            hi = None
        L.append(f"""  const Sys = Java.use('java.lang.System');
  Sys.currentTimeMillis.implementation = function () {{
    let t = this.currentTimeMillis(){f" + {shift}" if shift else ""};
    {f"if (t < {lo}) {{ rlog('ép currentTimeMillis ' + t + ' -> {lo}'); t = {lo}; }}" if lo is not None else ""}
    {f"if (t > {hi}) {{ rlog('ép currentTimeMillis ' + t + ' -> {hi}'); t = {hi}; }}" if hi is not None else ""}
    return t;
  }};""")
    L.append(TAIL)
    return "\n".join(L)
