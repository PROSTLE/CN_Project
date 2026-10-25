"""TPM 2.0 operations via tpm2-tools against swtpm (software TPM - demo only).

Honest description of key protection (TRD TR-L-4): TPM 2.0 stacks here have
no native Ed25519, so the Ed25519 ledger key is stored as a TPM2 *sealed data
object* under a persistent storage primary key of this (software) TPM. The
private bytes on disk are TPM-encrypted; they are unsealed into brain memory
at start. No PCR policy is bound to the seal (PCR 16 changes with every model
/ ruleset measurement). Quotes are produced by a persistent attestation key.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import cfg, path

PRIMARY = "0x81000001"
AK = "0x81010002"


class TPMError(RuntimeError):
    pass


def _env() -> dict:
    e = dict(os.environ)
    e["TPM2TOOLS_TCTI"] = cfg()["ledger"]["tcti"]
    return e


def run(*args: str, input_: bytes | None = None) -> bytes:
    r = subprocess.run(list(args), input=input_, capture_output=True, env=_env(), timeout=30)
    if r.returncode != 0:
        raise TPMError(f"{' '.join(args)}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def tpm_dir() -> Path:
    return path("tpm_dir")


def ensure_swtpm() -> None:
    """Start swtpm if its TCP port is not answering."""
    try:
        run("tpm2_getrandom", "--hex", "4")
        return
    except (TPMError, FileNotFoundError):
        pass
    state = tpm_dir() / "state"
    state.mkdir(parents=True, exist_ok=True)
    subprocess.run(["swtpm", "socket", "--tpmstate", f"dir={state}", "--tpm2", "--server",
                    "type=tcp,port=2321", "--ctrl", "type=tcp,port=2322", "--flags",
                    "not-need-init,startup-clear", "--daemon"], check=True)
    run("tpm2_getrandom", "--hex", "4")


def flush() -> None:
    """No resource manager in front of swtpm: flush transient objects and sessions
    so they do not exhaust the TPM's object slots."""
    for flag in ("-t", "-s"):
        try:
            run("tpm2_flushcontext", flag)
        except TPMError:
            pass


def _persistent() -> str:
    try:
        return run("tpm2_getcap", "handles-persistent").decode()
    except TPMError:
        return ""


def ensure_keys() -> None:
    d = tpm_dir()
    flush()
    have = _persistent()
    if PRIMARY not in have:
        run("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", str(d / "primary.ctx"))
        run("tpm2_evictcontrol", "-C", "o", "-c", str(d / "primary.ctx"), PRIMARY)
        flush()
    if AK not in have or not (d / "ak.pub.pem").exists():
        run("tpm2_createek", "-c", str(d / "ek.ctx"), "-G", "rsa", "-u", str(d / "ek.pub"))
        flush()
        run("tpm2_createak", "-C", str(d / "ek.ctx"), "-c", str(d / "ak.ctx"), "-G", "rsa", "-g", "sha256",
            "-s", "rsassa", "-u", str(d / "ak.pub.pem"), "-f", "pem", "-n", str(d / "ak.name"))
        flush()
        if AK in have:
            run("tpm2_evictcontrol", "-C", "o", "-c", AK)
        run("tpm2_evictcontrol", "-C", "o", "-c", str(d / "ak.ctx"), AK)
        flush()


def seal(secret: bytes, name: str) -> Path:
    d = tpm_dir()
    run("tpm2_create", "-C", PRIMARY, "-i", "-", "-u", str(d / f"{name}.pub"), "-r", str(d / f"{name}.priv"),
        input_=secret)
    flush()
    return d / f"{name}.priv"


def unseal(name: str) -> bytes:
    d = tpm_dir()
    ctx = d / f"{name}.ctx"
    run("tpm2_load", "-C", PRIMARY, "-u", str(d / f"{name}.pub"), "-r", str(d / f"{name}.priv"), "-c", str(ctx))
    try:
        return run("tpm2_unseal", "-c", str(ctx))
    finally:
        flush()


def pcr_index() -> int:
    return int(cfg()["ledger"]["pcr_index"])


def pcr_read() -> str:
    out = run("tpm2_pcrread", f"sha256:{pcr_index()}").decode()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(f"{pcr_index()}") and ":" in line:
            return line.split(":", 1)[1].strip().lower().removeprefix("0x")
    raise TPMError(f"cannot parse pcrread: {out}")


def pcr_reset() -> None:
    run("tpm2_pcrreset", str(pcr_index()))


def pcr_extend(digest_hex: str) -> str:
    run("tpm2_pcrextend", f"{pcr_index()}:sha256={digest_hex}")
    return pcr_read()


def quote(nonce_hex: str, tag: str) -> dict:
    d = tpm_dir() / "quotes"
    d.mkdir(exist_ok=True)
    m, s, p = d / f"{tag}.msg", d / f"{tag}.sig", d / f"{tag}.pcrs"
    run("tpm2_quote", "-c", AK, "-l", f"sha256:{pcr_index()}", "-q", nonce_hex, "-m", str(m), "-s", str(s),
        "-o", str(p), "-g", "sha256")
    flush()
    return {"msg": m.read_bytes().hex(), "sig": s.read_bytes().hex(), "pcrs": p.read_bytes().hex(),
            "nonce": nonce_hex, "pcr_index": pcr_index(), "pcr_value": pcr_read(),
            "ak_pub_pem": (tpm_dir() / "ak.pub.pem").read_text()}


def check_quote(q: dict, workdir: Path) -> tuple[bool, str]:
    workdir.mkdir(parents=True, exist_ok=True)
    files = {}
    for k in ("msg", "sig", "pcrs"):
        files[k] = workdir / f"q.{k}"
        files[k].write_bytes(bytes.fromhex(q[k]))
    ak = workdir / "ak.pub.pem"
    ak.write_text(q["ak_pub_pem"])
    r = subprocess.run(["tpm2_checkquote", "-u", str(ak), "-m", str(files["msg"]), "-s", str(files["sig"]),
                        "-f", str(files["pcrs"]), "-g", "sha256", "-q", q["nonce"]], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-400:]
