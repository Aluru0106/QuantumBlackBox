#!/usr/bin/env python3
"""QuantumBlackBox - forward-secure, TPM-anchored hash-chain flight logger (demo).

  python3 logger.py init          fresh log + fresh key (TPM PCR23 must be zero)
  python3 logger.py add "text"    append one entry by hand
  python3 logger.py run [N]       append live MAVLink messages from UDP 14550 (N entries, 0 = forever)
  python3 logger.py verify        re-check the whole log against the key chain AND the TPM
"""
import hashlib, hmac, json, os, subprocess, sys, time

LOG, STATE, VKEY, PCR = "flight.log.jsonl", "state.key", "verifier.key", "23"
ZERO = "00" * 32


def H(b):
    return hashlib.sha256(b).digest()


def tpm_extend(digest):
    subprocess.run(["tpm2_pcrextend", f"{PCR}:sha256={digest.hex()}"],
                   check=True, capture_output=True)


def tpm_read():
    out = subprocess.run(["tpm2_pcrread", f"sha256:{PCR}"],
                         check=True, capture_output=True, text=True).stdout
    return out.split("0x")[-1].strip().lower()


def entry_hash(prev, seq, ts, payload):
    return H(bytes.fromhex(prev) + seq.to_bytes(8, "big") + ts.encode() + payload.encode())


def load():
    if not os.path.exists(LOG):
        return []
    with open(LOG) as f:
        return [json.loads(l) for l in f if l.strip()]


def init():
    if tpm_read() != ZERO:
        sys.exit("PCR23 is not zero - restart swtpm first (see restart command), then init again.")
    for p in (LOG, LOG + ".orig", "log.sig.json"):   # also clear old attacker backup + old signature
        if os.path.exists(p):
            os.remove(p)
    k0 = os.urandom(32).hex()
    open(STATE, "w").write(k0)   # device keeps only the CURRENT key
    open(VKEY, "w").write(k0)    # demo: verifier's copy of k0 (real system: escrowed / TPM-sealed)
    print("initialised: new log, new key chain, PCR23 = 0")


def add(payload):
    entries = load()
    prev = entries[-1]["hash"] if entries else ZERO
    seq = len(entries)
    ts = repr(time.time())
    h = entry_hash(prev, seq, ts, payload)
    k = bytes.fromhex(open(STATE).read())
    mac = hmac.new(k, h, "sha256").hexdigest()
    open(STATE, "w").write(H(k).hex())     # forward security: evolve key, old key is gone
    tpm_extend(h)                           # anchor into the TPM - a PCR can only be extended
    with open(LOG, "a") as f:
        f.write(json.dumps({"seq": seq, "ts": ts, "payload": payload,
                            "prev": prev, "hash": h.hex(), "mac": mac}) + "\n")
    print(f"[{seq}] {h.hex()[:16]}...  {payload[:60]}")


def run(n):
    from pymavlink import mavutil
    m = mavutil.mavlink_connection("udpin:127.0.0.1:14550")
    print("listening for MAVLink on udp:14550 ...")
    count = 0
    while n == 0 or count < n:
        msg = m.recv_match(blocking=True)
        if msg and msg.get_type() in ("HEARTBEAT", "ATTITUDE", "HIGHRES_IMU", "GLOBAL_POSITION_INT"):
            add(msg.get_type() + " " + json.dumps(msg.to_dict(), sort_keys=True))
            count += 1


def verify():
    k, prev, pcr = bytes.fromhex(open(VKEY).read()), ZERO, b"\x00" * 32

    def fail(i, why):
        print(f"TAMPERING DETECTED at entry {i}: {why}")
        sys.exit(1)

    entries = []
    for i, line in enumerate(l for l in open(LOG) if l.strip()):
        try:
            entries.append(json.loads(line))
        except ValueError:
            fail(i, "entry is corrupted / unreadable")

    for i, e in enumerate(entries):
        if e["seq"] != i:
            fail(i, "sequence gap / reordered entry")
        if e["prev"] != prev:
            fail(i, "hash-chain link broken")
        h = entry_hash(e["prev"], i, e["ts"], e["payload"])
        if h.hex() != e["hash"]:
            fail(i, "entry content was altered")
        if not hmac.compare_digest(hmac.new(k, h, "sha256").hexdigest(), e["mac"]):
            fail(i, "MAC invalid (forged entry)")
        k, prev, pcr = H(k), e["hash"], H(pcr + h)
    if pcr.hex() != tpm_read():
        fail(len(entries), "TPM PCR23 mismatch - log was truncated or rewritten")
    print(f"LOG OK: {len(entries)} entries, hash chain + MAC chain + TPM PCR23 all consistent")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init":
        init()
    elif cmd == "add":
        add(sys.argv[2])
    elif cmd == "run":
        run(int(sys.argv[2]) if len(sys.argv) > 2 else 0)
    elif cmd == "verify":
        verify()
    else:
        print(__doc__)
