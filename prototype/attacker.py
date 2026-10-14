#!/usr/bin/env python3
"""Simulated root attacker working on the log file (QUAN-19 attacker rig, file-tampering part).

  python3 attacker.py tamper N     edit the payload of entry N
  python3 attacker.py truncate K   delete the last K entries
  python3 attacker.py forge N      edit entry N AND recompute every hash after it (no keys)
  python3 attacker.py restore      put the original log back
"""
import hashlib, json, os, shutil, sys

LOG, BAK = "flight.log.jsonl", "flight.log.jsonl.orig"


def read():
    return [json.loads(l) for l in open(LOG) if l.strip()]


def write(entries):
    open(LOG, "w").write("".join(json.dumps(e) + "\n" for e in entries))


cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd in ("tamper", "truncate", "forge") and not os.path.exists(BAK):
    shutil.copy(LOG, BAK)
if cmd == "tamper":
    e = read(); n = int(sys.argv[2]); e[n]["payload"] += " [EDITED BY ATTACKER]"; write(e)
    print(f"attacker edited entry {n}")
elif cmd == "truncate":
    e = read(); k = int(sys.argv[2]); write(e[:-k])
    print(f"attacker deleted the last {k} entries")
elif cmd == "forge":
    e = read(); n = int(sys.argv[2]); e[n]["payload"] += " [FORGED]"
    prev = e[n]["prev"]
    for x in e[n:]:
        x["prev"] = prev
        x["hash"] = hashlib.sha256(bytes.fromhex(prev) + x["seq"].to_bytes(8, "big")
                                   + x["ts"].encode() + x["payload"].encode()).hexdigest()
        prev = x["hash"]
    write(e)
    print(f"attacker edited entry {n} and recomputed all later hashes")
elif cmd == "restore":
    shutil.copy(BAK, LOG); os.remove(BAK); print("original log restored")
else:
    print(__doc__)
