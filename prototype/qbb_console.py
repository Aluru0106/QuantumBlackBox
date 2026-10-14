#!/usr/bin/env python3
"""QuantumBlackBox Control Console - everything in one browser page.

  cd ~/qbb && source env.sh && python3 qbb_console.py
  open http://127.0.0.1:8080

Runs your real commands (swtpm, logger, replay, attacker, ML-DSA, evaluate), streams the
terminal output, and shows the log, the hash chain and the results. Standard library only.
"""
import hashlib, hmac, json, os, secrets, signal, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
PORT = int(os.environ.get("QBB_PORT", "8080"))
TOKEN = secrets.token_hex(16)
LOG, VKEY, SIG, RES = "flight.log.jsonl", "verifier.key", "log.sig.json", "results.json"
ZERO = "00" * 32
PRE = "[ -f ./env.sh ] && source ./env.sh; export TPM2TOOLS_TCTI=${TPM2TOOLS_TCTI:-swtpm:host=127.0.0.1,port=2321}; "

TPM_SCRIPT = (
 "if [ -x ./tpm_start.sh ]; then ./tpm_start.sh; else "
 "pkill swtpm 2>/dev/null; sleep 1; mkdir -p /tmp/qbb_tpm; "
 "swtpm socket --tpm2 --tpmstate dir=/tmp/qbb_tpm --server type=tcp,port=2321 "
 "--ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --daemon && sleep 1 && "
 "tpm2_startup -c -T swtpm:host=127.0.0.1,port=2321; fi; tpm2_pcrread sha256:23")

def cmds(key, n):
    n = str(int(n)) if n is not None else "10"
    table = {
     "tpm":      TPM_SCRIPT,
     "deps":     "pip install pymavlink dilithium-py cryptography --break-system-packages",
     "init":     "python3 logger.py init",
     "record":   "python3 logger.py run 40 & L=$!; sleep 2; python3 replay_real.py 2 > /dev/null & R=$!; wait $L; kill $R 2>/dev/null; echo recording finished",
     "verify":   "python3 logger.py verify",
     "sign":     "python3 pqc_sign.py sign",
     "sigverify":"python3 pqc_sign.py verify",
     "tamper":   f"python3 attacker.py tamper {n}",
     "truncate": f"python3 attacker.py truncate {n}",
     "forge":    f"python3 attacker.py forge {n}",
     "restore":  "python3 attacker.py restore",
     "evaluate": "python3 evaluate.py 100",
    }
    return table.get(key)

JOBS, LOCK = {}, threading.Lock()

def start_job(shell, label):
    jid = secrets.token_hex(4)
    job = {"id": jid, "label": label, "lines": [], "done": False, "rc": None, "t": time.time()}
    p = subprocess.Popen(["bash", "-c", PRE + shell], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1, start_new_session=True)
    job["p"] = p
    def pump():
        for line in p.stdout:
            job["lines"].append(line.rstrip("\n"))
        p.wait(); job["rc"] = p.returncode; job["done"] = True
    threading.Thread(target=pump, daemon=True).start()
    with LOCK: JOBS[jid] = job
    return jid

def sh(cmd):
    try:
        return subprocess.run(["bash", "-c", PRE + cmd], capture_output=True, text=True, timeout=8).stdout.strip()
    except Exception:
        return ""

def analyse():
    """Replay the chain (no TPM) and report per-entry status."""
    out = {"entries": [], "bad": None, "reason": None, "count": 0, "types": {}}
    if not os.path.exists(LOG): return out
    try: k = bytes.fromhex(open(VKEY).read().strip())
    except Exception: k = None
    prev, rows = ZERO, []
    for i, line in enumerate(l for l in open(LOG) if l.strip()):
        try: e = json.loads(line)
        except ValueError:
            rows.append({"seq": i, "type": "?", "hash": "", "ok": False, "why": "unreadable entry"}); 
            if out["bad"] is None: out["bad"], out["reason"] = i, "entry is corrupted / unreadable"
            continue
        why = None
        if e.get("seq") != i: why = "sequence gap / reordered entry"
        elif e.get("prev") != prev: why = "hash-chain link broken"
        else:
            h = hashlib.sha256(bytes.fromhex(e["prev"]) + i.to_bytes(8, "big") + e["ts"].encode() + e["payload"].encode()).digest()
            if h.hex() != e["hash"]: why = "entry content was altered"
            elif k is not None and not hmac.compare_digest(hmac.new(k, h, "sha256").hexdigest(), e["mac"]): why = "MAC invalid (forged entry)"
        if why and out["bad"] is None: out["bad"], out["reason"] = i, why
        if k is not None: k = hashlib.sha256(k).digest()
        prev = e.get("hash", prev)
        typ = e.get("payload", "?").split(" ", 1)[0]
        out["types"][typ] = out["types"].get(typ, 0) + 1
        rows.append({"seq": i, "type": typ, "hash": e.get("hash", "")[:12], "ok": why is None, "why": why,
                     "payload": e.get("payload", "")[:140]})
    out["count"] = len(rows)
    out["entries"] = rows[-300:] if out["bad"] is None else rows[max(0, out["bad"] - 100):out["bad"] + 100]
    out["strip"] = [1 if r["ok"] else 0 for r in rows][:1500]
    return out

def state():
    pcr = sh("tpm2_pcrread sha256:23 2>/dev/null | grep -o '0x[0-9A-Fa-f]*' | tail -1")
    return {"swtpm": bool(sh("pgrep -x swtpm")), "pcr23": pcr[2:] if pcr else None,
            "log_exists": os.path.exists(LOG), "sig_exists": os.path.exists(SIG),
            "orig_exists": os.path.exists(LOG + ".orig"), "results_exists": os.path.exists(RES)}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def ok_host(self):
        return (self.headers.get("Host", "").split(":")[0]) in ("127.0.0.1", "localhost")
    def send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if not self.ok_host(): return self.send(403, "bad host", "text/plain")
        u = urlparse(self.path)
        if u.path == "/":
            html = open(os.path.join(HERE, "console.html"), encoding="utf8").read().replace("__TOKEN__", TOKEN)
            return self.send(200, html, "text/html; charset=utf-8")
        if self.headers.get("X-Token") != TOKEN: return self.send(403, "{}")
        if u.path == "/api/state": return self.send(200, json.dumps(state()))
        if u.path == "/api/log": return self.send(200, json.dumps(analyse()))
        if u.path == "/api/results":
            return self.send(200, open(RES).read() if os.path.exists(RES) else "null")
        if u.path == "/api/sig":
            if not os.path.exists(SIG): return self.send(200, "null")
            s = json.load(open(SIG)); s["pub"] = s.get("pub", "")[:48] + "..."; s["sig"] = s.get("sig", "")[:48] + "..."
            return self.send(200, json.dumps(s))
        if u.path.startswith("/api/job/"):
            _, _, _, jid, frm = (u.path + "/0").split("/")[:5]
            j = JOBS.get(jid)
            if not j: return self.send(404, "{}")
            frm = int(frm or 0)
            return self.send(200, json.dumps({"lines": j["lines"][frm:], "next": len(j["lines"]), "done": j["done"], "rc": j["rc"]}))
        self.send(404, "{}")
    def do_POST(self):
        if not self.ok_host() or self.headers.get("X-Token") != TOKEN: return self.send(403, "{}")
        d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"{}")
        if self.path == "/api/run":
            c = cmds(d.get("key"), d.get("n"))
            if not c: return self.send(400, "{}")
            return self.send(200, json.dumps({"id": start_job(c, d.get("key"))}))
        if self.path == "/api/shell":
            return self.send(200, json.dumps({"id": start_job(str(d.get("cmd", ""))[:2000], "shell")}))
        if self.path == "/api/stop":
            j = JOBS.get(d.get("id"))
            if j and not j["done"]:
                try: os.killpg(os.getpgid(j["p"].pid), signal.SIGTERM)
                except Exception: pass
            return self.send(200, "{}")
        self.send(404, "{}")

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"QuantumBlackBox console  ->  http://127.0.0.1:{PORT}   (Ctrl+C to stop)")
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
