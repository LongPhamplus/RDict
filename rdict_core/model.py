from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ["info", "low", "medium", "high"]

# Độ tin cậy của bằng chứng
#   text     : chỉ khớp chữ (regex trên source / strings) -> có thể là comment, dead code
#   code     : khớp ở mức bytecode / mã máy (lệnh invoke, const-string, call ptrace thật)
#   behavior : nhiều API cấu thành một hành vi trong cùng luồng gọi
CONFIDENCE = ["text", "code", "behavior"]
CONF_ICON = {"text": "●○○", "code": "●●○", "behavior": "●●●"}

TARGETS = {"code", "manifest", "resource", "native", "filelist"}


@dataclass
class ComboItem:
    kind: str            # api | str | field
    pattern: re.Pattern

    def __str__(self) -> str:
        return f"{self.kind}:{self.pattern.pattern}"


@dataclass
class Combo:
    depth: int
    groups: list[list[ComboItem]]
    labels: list[str]


@dataclass
class Rule:
    id: str
    name: str
    category: str
    severity: str
    description: str
    target: list[str]
    any: list[re.Pattern] = field(default_factory=list)
    all: list[re.Pattern] = field(default_factory=list)
    # bytecode (DEX)
    api: list[re.Pattern] = field(default_factory=list)
    strings: list[re.Pattern] = field(default_factory=list)
    fields: list[re.Pattern] = field(default_factory=list)
    combo: Combo | None = None
    # luồng dữ liệu: ([(kind, pattern)], [sink pattern]) — kind: api | cb | field
    flow: tuple[list[tuple[str, re.Pattern]], list[re.Pattern]] | None = None
    in_method: re.Pattern | None = None   # chỉ tính hit nằm trong method có tên khớp
    exclude: list[re.Pattern] = field(default_factory=list)  # bỏ hit có file/class khớp
    # native (ELF)
    imports: list[re.Pattern] = field(default_factory=list)
    exports: list[re.Pattern] = field(default_factory=list)

    builtin: str | None = None
    hint: str = ""
    mitre: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    include_libs: bool = False
    source: str = ""

    @property
    def has_dex(self) -> bool:
        return bool(self.api or self.strings or self.fields or self.combo or self.flow)

    @property
    def has_native(self) -> bool:
        return bool(self.imports or self.exports)


@dataclass
class Hit:
    file: str
    line: int
    match: str
    snippet_start: int = 0
    snippet: list[str] = field(default_factory=list)
    lang: str = "text"
    confidence: str = "text"
    engine: str = "text"
    offset: int | None = None
    klass: str | None = None
    method: str | None = None
    hook: str | None = None
    bytecode: list[str] = field(default_factory=list)
    bytecode_hl: int | None = None          # index dòng cần highlight trong bytecode
    path: list[str] | None = None           # đường gọi từ entry point
    reachable: bool | None = None
    note: str | None = None

    def key(self) -> tuple:
        return (self.file, self.klass, self.method, self.line, self.offset, self.match[:60])


@dataclass
class Finding:
    rule: Rule
    hits: list[Hit] = field(default_factory=list)
    total: int = 0

    @property
    def confidence(self) -> str:
        return max((h.confidence for h in self.hits), key=CONFIDENCE.index, default="text")

    @property
    def reachable(self) -> bool:
        return any(h.reachable for h in self.hits)
