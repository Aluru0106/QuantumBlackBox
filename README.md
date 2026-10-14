# QuantumBlackBox

Forward-secure, hash-chained, post-quantum-signed flight-log recorder for drones (20CYS495, Amrita).

* `qbb/chain.py` - hash chain + HMAC key ratchet (forward security)
* `qbb/checkpoint.py` - ML-DSA-65 (FIPS 204) signed checkpoints via liboqs; optional TPM PCR extend
* `qbb/mavlink_source.py` - live MAVLink from ArduPilot SITL, or a built-in MAVLink simulator
* `demo_tamper.py` - edit / delete / truncate / stolen-key forgery, all detected
* `record_flight.py` - record live telemetry into the chain

## Repository layout

| Path | Contents |
|---|---|
| `qbb/`, `tests/`, `demo_tamper.py`, `record_flight.py` | First Review library: hash chain + key ratchet, signed checkpoints, unit tests (run by CI) |
| `prototype/` | Second Review prototype run on Kali: `logger.py` (hash chain + forward-secure MAC + swtpm PCR 23), `pqc_sign.py` (ML-DSA-65), `attacker.py`, `replay_real.py`, `evaluate.py`, `qbb_console.py` + `console.html` (browser control console) |
| `data/` | `real_telemetry.csv` (689 rows at 10 Hz from the public PX4 `sample.ulg`, AUAV-X2, 68.9 s) and `prep_data.py` that produced it |
| `results/results.json` | Measured results: 8 attacks x 4 schemes x 200 trials, overhead, post-quantum benchmark |
| `docs/figures/` | Architecture, threat model, result charts and console screenshots |

## Reproduce the Second Review results (Kali)

See `prototype/KALI_SECOND_REVIEW.md` and `prototype/CONSOLE.md`. In short:

```
pip install pymavlink dilithium-py cryptography --break-system-packages
cd prototype && python3 logger.py init && python3 qbb_console.py
```

Results: plain log detects 0/8 attacks, hash chain 1/8, chain+MAC 7/8, full design (chain + MAC + TPM PCR 23) 8/8, with 0 false positives. Telemetry is real (PX4 sample log); the TPM is a software TPM (swtpm).

Status: First Review scope. TPM is **swtpm (software emulator)**; no physical TPM/Pixhawk yet.
See RUNBOOK_KALI.md.
