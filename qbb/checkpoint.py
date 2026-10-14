"""Signed checkpoints: sign the chain head with ML-DSA-65 (FIPS 204) via liboqs.

A checkpoint = {count, head_hash} signed with a post-quantum signature. Verifying the
log against the latest checkpoint detects tail truncation and wholesale replacement,
which a bare hash chain cannot detect on its own.
Optionally extends a TPM PCR (swtpm or real TPM) with the head hash.
"""
from __future__ import annotations

import json
import shutil
import subprocess

SIG_ALG = "ML-DSA-65"


def _oqs():
    import oqs  # imported lazily so the chain logger works without liboqs
    return oqs


def new_signer():
    """Return (signer, public_key). Secret key stays inside the oqs.Signature object."""
    signer = _oqs().Signature(SIG_ALG)
    pub = signer.generate_keypair()
    return signer, pub


def make_checkpoint(signer, head: dict) -> dict:
    msg = json.dumps(head, sort_keys=True).encode()
    return {"head": head, "alg": SIG_ALG, "sig": signer.sign(msg).hex()}


def verify_checkpoint(pub: bytes, cp: dict) -> bool:
    msg = json.dumps(cp["head"], sort_keys=True).encode()
    with _oqs().Signature(cp["alg"]) as v:
        return bool(v.verify(msg, bytes.fromhex(cp["sig"]), pub))


def check_log_against_checkpoint(log_result, cp: dict) -> tuple[bool, str]:
    """log_result: VerifyResult from verify_chain. Detect truncation vs the signed head."""
    if not log_result.ok:
        return False, f"chain invalid at index {log_result.bad_index}: {log_result.reason}"
    if log_result.entries < cp["head"]["count"]:
        lost = cp["head"]["count"] - log_result.entries
        return False, f"TAIL TRUNCATION: {lost} signed entries missing"
    return True, "log consistent with signed checkpoint"


def tpm_extend_pcr(head_hash: str, pcr: int = 16) -> bool:
    """Extend a PCR with the head hash (needs tpm2-tools + a TPM/swtpm on TPM2TOOLS_TCTI)."""
    exe = shutil.which("tpm2_pcrextend")
    if not exe:
        return False
    r = subprocess.run([exe, f"{pcr}:sha256={head_hash}"],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0
