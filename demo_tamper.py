#!/usr/bin/env python3
"""Live demo: write a log, show it verifies, then attack it three ways and show detection.

Run:  python demo_tamper.py            (add --tpm to also extend a TPM PCR via swtpm)
"""
import argparse
import hashlib
import hmac
import json
import os
import shutil
import tempfile

from qbb.chain import GENESIS, ChainLogger, _entry_hash, verify_chain
from qbb.checkpoint import (
    check_log_against_checkpoint,
    make_checkpoint,
    new_signer,
    tpm_extend_pcr,
    verify_checkpoint,
)

GREEN, RED, RST = "\033[92m", "\033[91m", "\033[0m"


def banner(t):
    print(f"\n=== {t} ===")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tpm", action="store_true", help="extend TPM PCR16 with each checkpoint head")
    ap.add_argument("--entries", type=int, default=12)
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="qbb_")
    log = os.path.join(work, "flight.log")
    key0 = os.urandom(32)  # root key shared with the (cloud) verifier at provisioning time
    signer, pub = new_signer()

    banner("1. Record flight events (hash chain + forward-secure MAC)")
    lg = ChainLogger(log, key0)
    for i in range(a.entries):
        lg.append(f"GLOBAL_POSITION_INT lat=130000{i:02d} lon=800000{i:02d} alt={100 + i}")
    lg.append("STATUSTEXT: ARMED")
    cp = make_checkpoint(signer, lg.head)
    print(f"entries={lg.head['count']}  head={lg.head['head_hash'][:16]}...  "
          f"checkpoint signed with ML-DSA-65 (sig {len(cp['sig']) // 2} bytes)")
    if a.tpm:
        print("TPM PCR16 extended:", tpm_extend_pcr(lg.head["head_hash"]))

    banner("2. Verify untouched log")
    r = verify_chain(log, key0)
    ok_cp = verify_checkpoint(pub, cp)
    ok, msg = check_log_against_checkpoint(r, cp)
    print(f"{GREEN}chain OK={r.ok} ({r.entries} entries); checkpoint signature valid={ok_cp}; {msg}{RST}")

    attacks = {
        "ATTACK A: edit one entry (hide a GPS jump)": lambda L: [
            L.__setitem__(5, L[5].replace("alt=105", "alt=999"))],
        "ATTACK B: delete a middle entry": lambda L: [L.pop(4)],
        "ATTACK C: truncate the tail (erase the last events)": lambda L: [L.pop(), L.pop(), L.pop()],
    }
    for title, mutate in attacks.items():
        banner(title)
        victim = os.path.join(work, "victim.log")
        shutil.copy(log, victim)
        with open(victim, encoding="utf-8") as f:
            lines = f.read().splitlines()
        mutate(lines)
        with open(victim, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        r = verify_chain(victim, key0)
        ok, msg = check_log_against_checkpoint(r, cp)
        print(f"{RED if not ok else GREEN}DETECTED={not ok}  -> {msg}{RST}")

    banner("3. ATTACK D: root attacker steals the CURRENT key and rebuilds the chain after editing entry 5")
    stolen_key = lg._key  # what a root attacker could read from memory *after* logging: only the latest key
    victim = os.path.join(work, "forged.log")
    with open(log, encoding="utf-8") as f:
        entries = [json.loads(x) for x in f]
    entries[5]["payload"] = entries[5]["payload"].replace("alt=105", "alt=999")
    prev = GENESIS
    for e in entries:  # attacker recomputes every hash AND re-MACs with the only key he has
        e["prev"] = prev
        e["hash"] = _entry_hash(prev, e["seq"], e["ts"], e["payload"])
        e["mac"] = hmac.new(stolen_key, e["hash"].encode(), hashlib.sha256).hexdigest()
        prev = e["hash"]
    with open(victim, "w", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n")
    r = verify_chain(victim, key0)
    ok, msg = check_log_against_checkpoint(r, cp)
    print(f"{RED if not ok else GREEN}DETECTED={not ok}  -> {msg}{RST}")
    print("(hashes alone are forgeable, but MACs for past entries need keys that were erased by the ratchet;")
    print(" and the forged head no longer matches the ML-DSA-signed checkpoint.)")
    forged_head = entries[-1]["hash"]
    print(f"forged head {forged_head[:12]}... != signed head {cp['head']['head_hash'][:12]}...")
    print(f"\nLog directory (keep for screenshots): {work}")


if __name__ == "__main__":
    main()
