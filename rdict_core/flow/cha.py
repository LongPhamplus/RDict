"""Cây kế thừa (Class Hierarchy Analysis), giải lời gọi ảo/interface, entry point Android, callback.

- resolve(op, sig): lời gọi `Runnable.run()` / `Listener.onX()` -> mọi hiện thực nội bộ có thể nhận lời gọi đó.
- overrides(ma): method này override method framework nào (onCreate, onClick, run, onLocationChanged...).
- entries / reachable: điểm vào = method vòng đời của component trong manifest + mọi callback override
  framework thuộc class có được khởi tạo + handler onClick khai báo trong XML + <clinit>.
- callers(ma): ai gọi ma (kể cả qua dispatch ảo) + "đăng ký callback" (ai tạo object chứa callback).
"""
from __future__ import annotations

import re
from collections import defaultdict, deque

from .ir import INVOKE, STATIC_LIKE

# Callback nhiều khả năng do framework gọi khi object được truyền vào API (Thread, Handler, listener...)
LIFECYCLE_ROOTS = ("Landroid/app/Activity;", "Landroid/app/Service;", "Landroid/content/BroadcastReceiver;",
                   "Landroid/content/ContentProvider;", "Landroid/app/Application;")


CALLBACK_RX = re.compile(r"^(?:on[A-Z]\w*|run|call|handleMessage|doInBackground|getView|getItem\w*|getCount|"
                         r"compare|accept|apply|uncaughtException|shouldOverrideUrlLoading|shouldInterceptRequest|"
                         r"after\w+|before\w+|surface\w+|newThread|get|update|query|insert|delete|getType|openFile)$")


# Được framework tạo từ XML / FragmentManager -> không có "new" trong code nhưng vẫn sống
INFLATED = ("Landroid/view/View;", "Landroid/app/Fragment;", "Landroidx/fragment/app/Fragment;",
            "Landroid/support/v4/app/Fragment;", "Landroid/preference/Preference;")


class Hierarchy:
    def __init__(self, dx, include_libs: bool, is_lib, entry_classes: set[str], onclick: set[str] | None = None):
        self.dx = dx
        self.is_lib = is_lib
        self.include_libs = include_libs
        self.sup: dict[str, str | None] = {}
        self.ifaces: dict[str, list[str]] = {}
        self.internal: set[str] = set()
        self.subs: dict[str, set[str]] = defaultdict(set)
        self.meth: dict[str, dict[str, object]] = defaultdict(dict)   # cls -> {name+desc: ma}
        self.instantiated: set[str] = set()
        self.onclick = onclick
        self.fdecl: dict[str, set[str]] = defaultdict(set)     # cls -> {tên field khai báo}
        self._fc: dict[str, str] = {}
        for ca in dx.get_classes():
            n = ca.name
            if ca.is_external():
                continue
            self.internal.add(n)
            try:
                self.sup[n] = ca.extends
                self.ifaces[n] = list(ca.implements or [])
            except Exception:
                self.sup[n], self.ifaces[n] = None, []
            try:
                for f in ca.get_vm_class().get_fields():
                    self.fdecl[n].add(f.get_name())
            except Exception:
                pass
            if self.sup[n]:
                self.subs[self.sup[n]].add(n)
            for i in self.ifaces[n]:
                self.subs[i].add(n)
        for ma in dx.get_methods():
            if not ma.is_external():
                self.meth[ma.class_name][ma.name + ma.descriptor] = ma
        self._subt: dict[str, set[str]] = {}
        self._anc: dict[str, list[str]] = {}
        self._res: dict[tuple, list] = {}
        self.entry_classes = entry_classes
        self.callees: dict = defaultdict(set)   # ma -> {ma}
        self.callers: dict = defaultdict(set)   # ma -> {(caller, kind)}
        self._build_edges()
        self.entries = self._entries()
        self.reachable = self._reach()

    # ------------------------------------------------------------------ hierarchy
    def subtypes(self, cls: str) -> set[str]:
        r = self._subt.get(cls)
        if r is None:
            r, q = set(), [cls]
            while q:
                c = q.pop()
                for s in self.subs.get(c, ()):
                    if s not in r:
                        r.add(s)
                        q.append(s)
            self._subt[cls] = r
        return r

    def ancestors(self, cls: str) -> list[str]:
        """Mọi supertype (class cha + interface), theo thứ tự gần -> xa."""
        r = self._anc.get(cls)
        if r is None:
            r, seen, q = [], {cls}, deque([cls])
            while q:
                c = q.popleft()
                for p in ([self.sup.get(c)] if self.sup.get(c) else []) + self.ifaces.get(c, []):
                    if p not in seen:
                        seen.add(p)
                        r.append(p)
                        q.append(p)
            self._anc[cls] = r
        return r

    def is_subtype(self, cls: str, parent: str) -> bool:
        return cls == parent or parent in self.ancestors(cls)

    def canon_field(self, ref: str) -> str:
        """'LSub;->imei Ljava/lang/String;' -> 'LBase;->imei ...' (class thật sự khai báo field)."""
        r = self._fc.get(ref)
        if r is None:
            r = ref
            try:
                cls, rest = ref.split("->", 1)
                name = rest.split(" ", 1)[0]
                c = cls
                while c in self.internal and name not in self.fdecl.get(c, ()):
                    c = self.sup.get(c)
                if c and c != cls and c in self.internal:
                    r = c + "->" + rest
            except ValueError:
                pass
            self._fc[ref] = r
        return r

    def _ext_methods(self) -> set[str]:
        if getattr(self, "_extm", None) is None:
            self._extm = set()
            for m in self.dx.get_methods():
                if m.is_external():
                    self._extm.add(f"{m.class_name}->{m.name}{m.descriptor}")
        return self._extm

    def overrides(self, ma) -> list[str]:
        """Chữ ký framework mà method nội bộ này override: ['Landroid/view/View$OnClickListener;->onClick(...)V'].
        Chỉ tính method không private/static, và framework thật sự có method đó (được tham chiếu trong dex)
        hoặc tên có dạng callback."""
        r = self._ov.get(ma) if hasattr(self, "_ov") else None
        if r is not None:
            return r
        if not hasattr(self, "_ov"):
            self._ov = {}
        r = []
        if ma.name not in ("<init>", "<clinit>") and not (ma.get_method().get_access_flags() & 0xA):
            key = ma.name + ma.descriptor
            ext = [a for a in self.ancestors(ma.class_name) if a not in self.internal and a != "Ljava/lang/Object;"]
            if ext:
                known = [f"{a}->{key}" for a in ext if f"{a}->{key}" in self._ext_methods()]
                r = known or ([f"{a}->{key}" for a in ext] if CALLBACK_RX.match(ma.name) else [])
        self._ov[ma] = r
        return r

    def resolve(self, op: int, sig: str) -> list:
        k = (op in STATIC_LIKE, sig)
        r = self._res.get(k)
        if r is not None:
            return r
        cls, rest = sig.split("->", 1)
        r = []
        if op in STATIC_LIKE:
            c = cls
            while c and c in self.internal:
                m = self.meth[c].get(rest)
                if m is not None:
                    r = [m]
                    break
                c = self.sup.get(c)
        else:
            seen = set()
            for c in [cls] + sorted(self.subtypes(cls)):
                m = self.meth.get(c, {}).get(rest)
                if m is not None and id(m) not in seen:
                    seen.add(id(m))
                    r.append(m)
            if not r:   # kế thừa hiện thực từ class cha nội bộ
                c = self.sup.get(cls)
                while c and c in self.internal:
                    m = self.meth[c].get(rest)
                    if m is not None:
                        r = [m]
                        break
                    c = self.sup.get(c)
        if not self.include_libs:
            r = [m for m in r if not self.is_lib(m.class_name)]
        self._res[k] = r
        return r

    # ------------------------------------------------------------------ call graph
    def _build_edges(self):
        for cls in self.internal:
            if not self.include_libs and self.is_lib(cls):
                continue
            for ma in self.meth[cls].values():
                em = ma.get_method()
                if em.get_code() is None:
                    continue
                for ins in em.get_instructions():
                    op = ins.get_op_value()
                    if op == 0x22:
                        try:
                            self.instantiated.add(ins.get_translated_kind())
                        except Exception:
                            pass
                    elif op in INVOKE:
                        try:
                            sig = ins.get_translated_kind()
                        except Exception:
                            continue
                        for t in self.resolve(op, sig):
                            if t is not ma:
                                self.callees[ma].add(t)
                                self.callers[t].add((ma, "call"))

    def _entries(self) -> set:
        out = set()
        for cls in self.internal:
            if not self.include_libs and self.is_lib(cls):
                continue
            comp = cls in self.entry_classes or any(sc in self.entry_classes for sc in self.subtypes(cls))
            act = self.is_subtype(cls, "Landroid/app/Activity;")
            live = comp or cls in self.instantiated or any(sc in self.instantiated for sc in self.subtypes(cls)) \
                or any(self.is_subtype(cls, v) for v in INFLATED)
            for ma in self.meth[cls].values():
                if ma.name == "<clinit>":
                    out.add(ma)
                elif comp and ma.name == "<init>":
                    out.add(ma)
                elif live and self.overrides(ma):
                    out.add(ma)
                elif act and ma.descriptor.replace(" ", "") == "(Landroid/view/View;)V" \
                        and ma.get_method().get_access_flags() & 0x1 and (self.onclick is None or ma.name in self.onclick):
                    out.add(ma)          # android:onClick trong layout XML
        return out

    def _reach(self) -> set:
        seen, q = set(self.entries), deque(self.entries)
        while q:
            m = q.popleft()
            for c in self.callees.get(m, ()):
                if c not in seen:
                    seen.add(c)
                    q.append(c)
        return seen

    def extend(self, edges):
        """Thêm cạnh gọi phát hiện được sau (reflection, AsyncTask...) rồi tính lại khả năng gọi tới."""
        for a, b in edges:
            self.callees[a].add(b)
            self.callers[b].add((a, "reflect"))
        self.reachable = self._reach()

    def preds(self, ma) -> list[tuple]:
        """Ai dẫn tới ma: lời gọi (kể cả qua dispatch ảo) và — với callback — nơi tạo object chứa nó."""
        res = list(self.callers.get(ma, ()))
        if self.overrides(ma) and not (ma.get_method().get_access_flags() & 0x8):
            for key, init in self.meth[ma.class_name].items():
                if key.startswith("<init>"):
                    res += [(c, "new") for c, _ in self.callers.get(init, ())]
        return res
