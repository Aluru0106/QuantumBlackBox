"""Forward-secure hash-chain logger (Schneier-Kelsey style).

Entry i stores:
    hash_i = SHA256(hash_{i-1} || seq || ts || payload)
    mac_i  = HMAC(K_i, hash_i)
and the MAC key is ratcheted one-way after every entry: K_{i+1} = HMAC(K_i, b"evolve").
Old keys are discarded, so an attacker who steals the *current* key cannot re-forge
MACs for entries already written. A verifier holding K_0 can re-derive every K_i.
Tail truncation is caught by comparing against signed checkpoints (see checkpoint.py).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

GENESIS = "0" * 64


def _evolve(key: bytes) -> bytes:
    return hmac.new(key, b"evolve", hashlib.sha256).digest()


def _entry_hash(prev_hash: str, seq: int, ts: float, payload: str) -> str:
    data = f"{prev_hash}|{seq}|{ts!r}|{payload}".encode()
    return hashlib.sha256(data).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    bad_index: int | None = None
    reason: str = ""


class ChainLogger:
    def __init__(self, path: str, key0: bytes):
        self.path = path
        self._key = key0
        self.seq = 0
        self.prev_hash = GENESIS
        if os.path.exists(path):
            raise FileExistsError(f"{path} exists; refusing to overwrite a log")

    def append(self, payload: str, ts: float | None = None) -> dict:
        ts = time.time() if ts is None else ts
        h = _entry_hash(self.prev_hash, self.seq, ts, payload)
        mac = hmac.new(self._key, h.encode(), hashlib.sha256).hexdigest()
        entry = {"seq": self.seq, "ts": ts, "payload": payload,
                 "prev": self.prev_hash, "hash": h, "mac": mac}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._key = _evolve(self._key)  # forward security: old key is gone
        self.prev_hash = h
        self.seq += 1
        return entry

    @property
    def head(self) -> dict:
        return {"count": self.seq, "head_hash": self.prev_hash}


def verify_chain(path: str, key0: bytes) -> VerifyResult:
    key = key0
    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, n, n, "malformed entry")
            if e.get("seq") != n:
                return VerifyResult(False, n, n, "sequence gap/reorder")
            if e.get("prev") != prev:
                return VerifyResult(False, n, n, "broken link to previous hash")
            expect = _entry_hash(prev, n, e["ts"], e["payload"])
            if e.get("hash") != expect:
                return VerifyResult(False, n, n, "entry content altered (hash mismatch)")
            mac = hmac.new(key, expect.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, e.get("mac", "")):
                return VerifyResult(False, n, n, "MAC invalid (forged entry)")
            key = _evolve(key)
            prev = expect
            n += 1
    return VerifyResult(True, n)
