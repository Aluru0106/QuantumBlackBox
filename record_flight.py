#!/usr/bin/env python3
"""Record live MAVLink telemetry into the forward-secure chain, then sign a checkpoint.

  python record_flight.py --source sitl            # real ArduPilot SITL on udp 14550
  python record_flight.py --source sim             # built-in MAVLink simulator
"""
import argparse
import json
import os
import threading

from qbb.chain import ChainLogger, verify_chain
from qbb.checkpoint import make_checkpoint, new_signer, tpm_extend_pcr, verify_checkpoint
from qbb.mavlink_source import listen, run_simulator


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["sitl", "sim"], default="sim")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--out", default="evidence/flight.log")
    ap.add_argument("--tpm", action="store_true")
    a = ap.parse_args()

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    if os.path.exists(a.out):
        os.remove(a.out)
    stop = threading.Event()
    if a.source == "sim":
        threading.Thread(target=run_simulator, kwargs={"stop": stop}, daemon=True).start()

    key0 = os.urandom(32)
    signer, pub = new_signer()
    lg = ChainLogger(a.out, key0)
    for mtype, text in listen(count=a.count):
        e = lg.append(f"{mtype} {text}")
        print(f"[{e['seq']:03d}] {mtype:<20} hash={e['hash'][:12]}")
    stop.set()
    cp = make_checkpoint(signer, lg.head)
    with open(a.out + ".checkpoint.json", "w", encoding="utf-8") as f:
        json.dump({"checkpoint": cp, "pubkey": pub.hex(), "key0": key0.hex()}, f)
    if a.tpm:
        print("TPM PCR16 extended:", tpm_extend_pcr(lg.head["head_hash"]))
    r = verify_chain(a.out, key0)
    print(f"verify chain: ok={r.ok} entries={r.entries}; signature valid={verify_checkpoint(pub, cp)}")


if __name__ == "__main__":
    main()
