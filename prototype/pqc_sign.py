#!/usr/bin/env python3
"""Post-quantum signature (ML-DSA-65, FIPS 204) over the log chain head.

  python3 pqc_sign.py sign      sign "<entries>|<head hash>" and store log.sig.json
  python3 pqc_sign.py verify    re-read the log and check the signature (fails if the log changed)
Uses liboqs (oqs) if installed, otherwise the pure-Python 'dilithium-py' (pip install dilithium-py).
"""
import json, sys, time

try:
    import oqs
    ALG = "ML-DSA-65" if "ML-DSA-65" in oqs.get_enabled_sig_mechanisms() else "Dilithium3"

    def keygen():
        s = oqs.Signature(ALG); return s.generate_keypair(), s
    def sign(ctx, m): return ctx.sign(m)
    def verify(pub, m, sig):
        with oqs.Signature(ALG) as v: return v.verify(m, sig, pub)
    BACKEND = "liboqs"
except ImportError:
    from dilithium_py.ml_dsa import ML_DSA_65 as D
    ALG = "ML-DSA-65"
    def keygen():
        pk, sk = D.keygen(); return pk, sk
    def sign(sk, m): return D.sign(sk, m)
    def verify(pub, m, sig): return D.verify(pub, m, sig)
    BACKEND = "dilithium-py (pure Python)"

def head():
    """Recompute the whole hash chain from the entry CONTENT (never trust stored hashes)."""
    import hashlib
    es = [json.loads(l) for l in open("flight.log.jsonl") if l.strip()]
    prev = bytes(32)
    for i, e in enumerate(es):
        prev = hashlib.sha256(prev + i.to_bytes(8, "big") + e["ts"].encode() + e["payload"].encode()).digest()
    return f"{len(es)}|{prev.hex()}".encode(), len(es)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "sign":
        m, n = head()
        pub, ctx = keygen() if BACKEND == "liboqs" else (None, None)
        if BACKEND != "liboqs":
            pub, ctx = keygen()
        t = time.perf_counter(); sig = sign(ctx, m); ms = (time.perf_counter() - t) * 1000
        json.dump({"alg": ALG, "entries": n, "message": m.decode(), "pub": pub.hex(), "sig": sig.hex()}, open("log.sig.json", "w"))
        print(f"{ALG} [{BACKEND}] signed chain head of {n} entries: signature {len(sig)} bytes, public key {len(pub)} bytes, sign {ms:.1f} ms")
        print("saved log.sig.json")
    elif cmd == "verify":
        d = json.load(open("log.sig.json")); m, n = head()
        if m.decode() != d["message"]:
            print(f"PQC SIGNATURE FAIL: log changed since it was signed (signed {d['entries']} entries, log now has {n} / head differs)"); sys.exit(1)
        t = time.perf_counter(); ok = verify(bytes.fromhex(d["pub"]), m, bytes.fromhex(d["sig"])); ms = (time.perf_counter() - t) * 1000
        print(f"{ALG} signature {'VALID' if ok else 'INVALID'} ({ms:.1f} ms) for {n} entries"); sys.exit(0 if ok else 1)
    else:
        print(__doc__)
