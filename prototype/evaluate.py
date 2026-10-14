#!/usr/bin/env python3
"""QuantumBlackBox evaluation on REAL recorded telemetry (real_telemetry.csv, PX4 flight controller).

  python3 evaluate.py [TRIALS]      writes results.json and prints the tables

1. Attack-detection matrix: 8 attacks x 4 schemes (plain log / hash chain / chain+forward-secure MAC / chain+MAC+TPM).
   The verification logic is the same as logger.py (entry_hash, key evolution); PCR23 is modelled in software here
   so thousands of trials run quickly. The live demo uses the real swtpm TPM.
2. Overhead per log entry (software cost, real TPM extend if a TPM is reachable) and verify time.
3. Signature benchmark: ML-DSA-65 (FIPS 204) vs ECDSA P-256 / Ed25519 / RSA-2048, and ML-KEM-768 (if liboqs is present).
"""
import csv, hashlib, hmac, json, os, platform, random, statistics, subprocess, sys, time
from logger import H, entry_hash, ZERO

TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 else 200
random.seed(7)
rows = list(csv.DictReader(open("real_telemetry.csv")))

def payloads():
    out = []
    for i, r in enumerate(rows):
        if i % 10 == 0:
            out.append("HEARTBEAT " + json.dumps({"autopilot": 12, "type": 2, "system_status": 4}, sort_keys=True))
        out.append("ATTITUDE " + json.dumps({"roll": float(r["roll_rad"]), "pitch": float(r["pitch_rad"]), "yaw": float(r["yaw_rad"]),
                                              "rollspeed": float(r["gyro_x"]), "time_boot_ms": int(float(r["t_s"]) * 1000)}, sort_keys=True))
        out.append("HIGHRES_IMU " + json.dumps({"xacc": float(r["acc_x"]), "yacc": float(r["acc_y"]), "zacc": float(r["acc_z"]),
                                                 "xmag": float(r["mag_x"]), "ymag": float(r["mag_y"]), "zmag": float(r["mag_z"])}, sort_keys=True))
    return out

def build(pl, k0):
    es, prev, k, pcr = [], ZERO, k0, b"\x00" * 32
    for i, p in enumerate(pl):
        ts = repr(1.79e9 + i * 0.1)
        h = entry_hash(prev, i, ts, p)
        es.append({"seq": i, "ts": ts, "payload": p, "prev": prev, "hash": h.hex(), "mac": hmac.new(k, h, "sha256").hexdigest()})
        k, prev, pcr = H(k), h.hex(), H(pcr + h)
    return es, pcr

def rechain(es, start=0):
    for i in range(start, len(es)):
        es[i]["seq"] = i
        es[i]["prev"] = es[i - 1]["hash"] if i else ZERO
        es[i]["hash"] = entry_hash(es[i]["prev"], i, es[i]["ts"], es[i]["payload"]).hex()

def verify(es, scheme, k0, pcr_ref):
    """returns True if the scheme ACCEPTS the log (i.e. tampering NOT detected)."""
    if scheme == "plain":
        return True
    k, prev, pcr = k0, ZERO, b"\x00" * 32
    for i, e in enumerate(es):
        if e["seq"] != i or e["prev"] != prev: return False
        h = entry_hash(e["prev"], i, e["ts"], e["payload"])
        if h.hex() != e["hash"]: return False
        if scheme in ("mac", "full") and not hmac.compare_digest(hmac.new(k, h, "sha256").hexdigest(), e["mac"]): return False
        k, prev, pcr = H(k), e["hash"], H(pcr + h)
    if scheme == "full" and pcr != pcr_ref: return False
    return True

def tamper(es, kind, k_now):
    es = json.loads(json.dumps(es)); n = len(es); j = random.randrange(1, n - 25)
    if kind == "edit":                    # naive in-place edit
        es[j]["payload"] += " (altered)"
    elif kind == "edit+rechain":          # edit and repair every later hash
        es[j]["payload"] += " (altered)"; rechain(es, j)
    elif kind == "delete":                # delete a middle entry, repair chain
        del es[j]; rechain(es, j)
    elif kind == "insert":                # insert a fake entry, repair chain
        es.insert(j, {"seq": j, "ts": es[j]["ts"], "payload": "ATTITUDE {\"roll\": 0.0}", "prev": "", "hash": "", "mac": os.urandom(32).hex()}); rechain(es, j)
    elif kind == "reorder":               # swap two entries, repair chain
        es[j], es[j + 1] = es[j + 1], es[j]; rechain(es, j)
    elif kind == "truncate":              # drop the last k entries
        del es[-random.randint(1, 20):]
    elif kind == "stolen-key":            # edit + repair chain + re-MAC with the CURRENT (evolved) key only
        es[j]["payload"] += " (altered)"; rechain(es, j); k = k_now
        for i in range(j, len(es)):
            es[i]["mac"] = hmac.new(k, bytes.fromhex(es[i]["hash"]), "sha256").hexdigest(); k = H(k)
    elif kind == "fabricate":             # whole new flight, fresh chain + attacker's own key
        pl = [e["payload"].replace("roll", "ROLL") for e in es]
        es, _ = build(pl, os.urandom(32))
    return es

ATTACKS = [("edit", "Edit one entry"), ("edit+rechain", "Edit + repair hash chain"), ("delete", "Delete a middle entry"),
           ("insert", "Insert a fake entry"), ("reorder", "Reorder two entries"), ("truncate", "Truncate the tail (1-20 entries)"),
           ("stolen-key", "Forge using the stolen current key"), ("fabricate", "Replace with a fabricated log")]
SCHEMES = [("plain", "Plain log"), ("chain", "Hash chain"), ("mac", "Chain + forward-secure MAC"), ("full", "Chain + MAC + TPM PCR (ours)")]

pl = payloads(); k0 = os.urandom(32)
es, pcr_ref = build(pl, k0)
k_now = k0
for _ in es: k_now = H(k_now)
print(f"log of {len(es)} entries built from {len(rows)} real telemetry samples; {TRIALS} trials per attack")
assert all(verify(es, s, k0, pcr_ref) for s, _ in SCHEMES), "clean log must verify"
matrix = {}
for ak, aname in ATTACKS:
    matrix[ak] = {}
    for sk, _ in SCHEMES:
        det = 0
        for _ in range(TRIALS):
            t = tamper(es, ak, k_now)
            if not verify(t, sk, k0, pcr_ref): det += 1
        matrix[ak][sk] = round(100.0 * det / TRIALS, 1)
print("\nDetection rate (%)"); print("%-38s" % "attack" + "".join("%14s" % s for s, _ in SCHEMES))
for ak, aname in ATTACKS: print("%-38s" % aname + "".join("%14.1f" % matrix[ak][s] for s, _ in SCHEMES))
fp = sum(0 if verify(es, s, k0, pcr_ref) else 1 for s, _ in SCHEMES for _ in range(50))
print("false positives on clean log:", fp)

# ---- overhead
def timeit(f, n):
    t = time.perf_counter()
    for _ in range(n): f()
    return (time.perf_counter() - t) / n * 1000
N = len(pl)
t_plain = timeit(lambda: [json.dumps({"seq": i, "payload": p}) for i, p in enumerate(pl)], 5) / N * 1000
t_chain = timeit(lambda: build_chain_only(pl), 5) / N * 1000 if False else None
def chain_only():
    prev = ZERO
    for i, p in enumerate(pl): prev = entry_hash(prev, i, "0", p).hex()
t_chain = timeit(chain_only, 5) / N * 1000
t_full_sw = timeit(lambda: build(pl, k0), 5) / N * 1000
t_verify = timeit(lambda: verify(es, "full", k0, pcr_ref), 5) / N * 1000
tpm_ms = None
try:
    ts = []
    for i in range(40):
        t = time.perf_counter(); subprocess.run(["tpm2_pcrextend", "23:sha256=" + H(str(i).encode()).hex()], check=True, capture_output=True, timeout=10); ts.append((time.perf_counter() - t) * 1000)
    tpm_ms = statistics.median(ts)
except Exception as e:
    print("no TPM reachable for extend timing:", type(e).__name__)
avg_plain = statistics.mean(len(json.dumps({"ts": e["ts"], "payload": e["payload"]})) for e in es)
avg_full = statistics.mean(len(json.dumps(e)) for e in es)
overhead = {"entries": N, "plain_us": round(t_plain, 2), "chain_us": round(t_chain, 2), "chain_mac_us": round(t_full_sw, 2),
            "verify_us": round(t_verify, 2), "tpm_extend_ms": round(tpm_ms, 2) if tpm_ms else None,
            "bytes_plain": round(avg_plain, 1), "bytes_full": round(avg_full, 1)}
print("\nOverhead:", overhead)

# ---- signature benchmark
def med(f, n):
    xs = []
    for _ in range(n):
        t = time.perf_counter(); f(); xs.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(xs), 3)
msg = b"flight-log-chain-head" * 3
bench = []
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
def classical(name, gen, sign, ver, pubsize, sigsize):
    sk = gen(); pk = sk.public_key(); sg = sign(sk)
    bench.append({"alg": name, "family": "classical (quantum-vulnerable)", "keygen_ms": med(gen, 20), "sign_ms": med(lambda: sign(sk), 100),
                  "verify_ms": med(lambda: ver(pk, sg), 100), "pub_bytes": pubsize(pk), "sig_bytes": len(sg)})
raw = lambda pk: len(pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)) if hasattr(pk, "curve") else None
classical("ECDSA P-256", lambda: ec.generate_private_key(ec.SECP256R1()), lambda sk: sk.sign(msg, ec.ECDSA(hashes.SHA256())),
          lambda pk, sg: pk.verify(sg, msg, ec.ECDSA(hashes.SHA256())), lambda pk: 65, None)
classical("Ed25519", lambda: ed25519.Ed25519PrivateKey.generate(), lambda sk: sk.sign(msg), lambda pk, sg: pk.verify(sg, msg), lambda pk: 32, None)
classical("RSA-2048", lambda: rsa.generate_private_key(65537, 2048), lambda sk: sk.sign(msg, padding.PKCS1v15(), hashes.SHA256()),
          lambda pk, sg: pk.verify(sg, msg, padding.PKCS1v15(), hashes.SHA256()), lambda pk: 294, None)
backend = "none"
try:
    import oqs
    backend = "liboqs " + oqs.oqs_version()
    for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        s = oqs.Signature(alg); pub = s.generate_keypair(); sg = s.sign(msg)
        def kg():
            x = oqs.Signature(alg); x.generate_keypair(); x.free()
        v = oqs.Signature(alg)
        bench.append({"alg": alg, "family": "post-quantum (FIPS 204)", "keygen_ms": med(kg, 50), "sign_ms": med(lambda: s.sign(msg), 200),
                      "verify_ms": med(lambda: v.verify(msg, sg, pub), 200), "pub_bytes": len(pub), "sig_bytes": len(sg)})
    kem = []
    for alg in ("ML-KEM-768",):
        c = oqs.KeyEncapsulation(alg); pk = c.generate_keypair(); ct, ss = oqs.KeyEncapsulation(alg).encap_secret(pk)
        bench.append({"alg": alg, "family": "post-quantum KEM (FIPS 203)", "keygen_ms": med(lambda: oqs.KeyEncapsulation(alg).generate_keypair(), 50),
                      "sign_ms": med(lambda: oqs.KeyEncapsulation(alg).encap_secret(pk), 100), "verify_ms": med(lambda: c.decap_secret(ct), 100),
                      "pub_bytes": len(pk), "sig_bytes": len(ct)})
except ImportError:
    from dilithium_py.ml_dsa import ML_DSA_65 as D
    backend = "dilithium-py (pure Python, slower than C)"
    pk, sk = D.keygen(); sg = D.sign(sk, msg)
    bench.append({"alg": "ML-DSA-65", "family": "post-quantum (FIPS 204)", "keygen_ms": med(D.keygen, 5), "sign_ms": med(lambda: D.sign(sk, msg), 20),
                  "verify_ms": med(lambda: D.verify(pk, msg, sg), 20), "pub_bytes": len(pk), "sig_bytes": len(sg)})
print("\nSignature benchmark (backend:", backend + ")")
for b in bench: print("%-12s keygen %8.3f ms  sign/encap %8.3f ms  verify/decap %8.3f ms  pub %5d B  sig/ct %5d B" % (b["alg"], b["keygen_ms"], b["sign_ms"], b["verify_ms"], b["pub_bytes"], b["sig_bytes"]))

import math
tele = {"t": [float(r["t_s"]) for r in rows], "roll_deg": [round(math.degrees(float(r["roll_rad"])), 3) for r in rows],
        "pitch_deg": [round(math.degrees(float(r["pitch_rad"])), 3) for r in rows], "yaw_deg": [round(math.degrees(float(r["yaw_rad"])), 3) for r in rows],
        "acc_z": [float(r["acc_z"]) for r in rows]}
json.dump({"machine": {"cpu": platform.processor() or platform.machine(), "python": platform.python_version(), "note": "cloud VM, 2 vCPU Xeon 2.8 GHz"},
           "source": "PX4 pyulog test/sample.ulg, hardware AUAV-X2, 69 s, 689 samples at 10 Hz", "log_entries": N, "trials": TRIALS,
           "attacks": [{"key": k, "name": n} for k, n in ATTACKS], "schemes": [{"key": k, "name": n} for k, n in SCHEMES], "matrix": matrix,
           "false_positives": fp, "overhead": overhead, "bench": bench, "bench_backend": backend, "telemetry": tele}, open("results.json", "w"), indent=1)
print("\nwrote results.json")
