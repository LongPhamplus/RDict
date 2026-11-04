"""Tự giải ciphertext hardcode bằng key hardcode tìm được trong cùng vùng code.

Thử AES-128/192/256 và DES/3DES, các mode ECB / CBC (IV = hằng 16 byte gần đó, IV toàn 0,
IV = key, hoặc IV nằm ở đầu ciphertext). Kết quả chỉ được nhận khi padding PKCS#5/7 hợp lệ và
plaintext là văn bản đọc được, nên tỉ lệ báo nhầm rất thấp.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # cryptography < 43
        TripleDES = algorithms.TripleDES
    OK = True
except ImportError:  # pragma: no cover
    OK = False

HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
B64URL = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")


@dataclass
class KeyCand:
    raw: bytes
    src: str        # chuỗi gốc trong code
    how: str        # "hex", "base64", "utf-8", "md5(...)", ...


@dataclass
class Solved:
    plaintext: str
    algo: str
    key: KeyCand
    iv: str
    ct_src: str


def _b64(s: str) -> bytes | None:
    t = s.strip()
    if len(t) < 8:
        return None
    try:
        if B64.match(t):
            return base64.b64decode(t)
        if B64URL.match(t) and ("-" in t or "_" in t):
            return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except (binascii.Error, ValueError):
        return None
    return None


def key_candidates(s: str, derive: bool = True) -> list[KeyCand]:
    out = []
    if HEX.match(s) and len(s) in (16, 32, 48, 64):
        out.append(KeyCand(bytes.fromhex(s), s, "hex"))
    b = _b64(s)
    if b is not None and len(b) in (8, 16, 24, 32):
        out.append(KeyCand(b, s, "base64"))
    raw = s.encode("utf-8", "surrogatepass")
    if len(raw) in (8, 16, 24, 32) and " " not in s:
        out.append(KeyCand(raw, s, "utf-8"))
    if derive and 4 <= len(s) <= 64 and " " not in s and s.isprintable():
        out.append(KeyCand(hashlib.md5(raw).digest(), s, "md5"))
        out.append(KeyCand(hashlib.sha256(raw).digest(), s, "sha256"))
        out.append(KeyCand(hashlib.sha1(raw).digest()[:16], s, "sha1[:16]"))
    return out


def ct_candidates(s: str) -> list[tuple[bytes, str]]:
    out = []
    b = _b64(s)
    if b is not None and len(b) >= 8 and len(b) % 8 == 0:
        out.append((b, "base64"))
    if HEX.match(s) and len(s) >= 32 and (len(s) // 2) % 8 == 0:
        out.append((bytes.fromhex(s), "hex"))
    return out


def _unpad(p: bytes, bs: int) -> bytes | None:
    if not p or len(p) % bs:
        return None
    n = p[-1]
    if not 1 <= n <= bs or p[-n:] != bytes([n]) * n:
        return None
    return p[:-n]


def _readable(p: bytes) -> str | None:
    if len(p) < 2:
        return None
    try:
        t = p.decode("utf-8")
    except UnicodeDecodeError:
        return None
    good = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return t if good / len(t) >= 0.95 else None


def _dec(algo, mode, ct: bytes) -> bytes | None:
    try:
        d = Cipher(algo, mode).decryptor()
        return d.update(ct) + d.finalize()
    except Exception:
        return None


def solve(ct: bytes, keys: list[KeyCand], ivs: list[tuple[bytes, str]]) -> tuple[str, str, KeyCand, str] | None:
    """Trả về (plaintext, algo, key, mô tả IV) cho tổ hợp đầu tiên giải ra văn bản hợp lệ."""
    if not OK:
        return None
    for k in keys:
        if len(k.raw) in (16, 24, 32):
            fams = [("AES", lambda kk=k.raw: algorithms.AES(kk), 16)]
            if len(k.raw) in (16, 24):
                fams.append(("3DES", lambda kk=k.raw: TripleDES(kk), 8))
        elif len(k.raw) == 8:
            fams = [("DES", lambda kk=k.raw: TripleDES(kk * 3), 8)]
        else:
            continue
        for name, mk, bs in fams:
            if len(ct) % bs:
                continue
            bits = f"-{len(k.raw) * 8}" if name == "AES" else ""
            tries = [("ECB", None, "")]
            for iv, desc in ivs + [(bytes(bs), "IV = 0"), (k.raw[:bs], "IV = key")]:
                if len(iv) == bs:
                    tries.append(("CBC", iv, desc))
            if len(ct) >= 2 * bs:
                tries.append(("CBC*", ct[:bs], "IV = 16 byte đầu ciphertext"))
            for m, iv, desc in tries:
                body = ct[bs:] if m == "CBC*" else ct
                mode = modes.ECB() if m == "ECB" else modes.CBC(iv)
                p = _dec(mk(), mode, body)
                if p is None:
                    continue
                u = _unpad(p, bs)
                txt = _readable(u) if u is not None else None
                if txt:
                    return txt, f"{name}{bits}/{m.rstrip('*')}/PKCS5Padding", k, desc
    return None
