#!/usr/bin/env python3
import os
import sys
import ssl
import json
import time
import logging
import subprocess
import urllib.request
from typing import List, Dict, Tuple
import coloredlogs
import IptablesManager
# ───────────────────────────
# Configuration
# ───────────────────────────
LAPI_URL       = os.getenv("LAPI_URL")
CA_CERT        = os.getenv("CA_CERT", "/secrets/ca.crt")
CLIENT_CERT    = os.getenv("CLIENT_CERT", "/secrets/client.crt")
CLIENT_KEY     = os.getenv("CLIENT_KEY", "/secrets/client.key")
ROUTER         = os.getenv("ROUTER")
SSH_PORT       = os.getenv("SSH_PORT", "22")
SSH_KEY        = os.getenv("SSH_KEY", "/secrets/ssh_key")

CHAIN          = os.getenv("CHAIN", "CROWDSEC_BLOCK")
MAX_IPS        = int(os.getenv("MAX_IPS", "400"))
SCOPE_FILTER   = os.getenv("SCOPE", "ip")

WHITELIST_CSV  = os.getenv("WHITELIST", "")
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "/config/whitelist.txt")

LOG_LEVEL      = os.getenv("LOG_LEVEL", "INFO")

# ───────────────────────────
# Logger setup
# ───────────────────────────
logger = logging.getLogger("asus-fw-sync")
coloredlogs.install(
    level=LOG_LEVEL,
    logger=logger,
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level_styles={
        'debug': {'color': 'white'},
        'info': {'color': 'green'},
        'warning': {'color': 'yellow'},
        'error': {'color': 'red', 'bold': True},
        'critical': {'color': 'red', 'bold': True, 'background': 'white'},
    },
    field_styles={
        'asctime': {'color': 'cyan'},
        'levelname': {'color': 'white', 'bold': True},
    }
)

# ───────────────────────────
# CrowdSec communication (mTLS)
# ───────────────────────────
def build_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_CERT)
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    return ctx

def fetch_decisions(ctx: ssl.SSLContext) -> List[Dict]:
    url = f"{LAPI_URL.rstrip('/')}/v1/decisions/stream?startup=true&scope={SCOPE_FILTER}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("new", [])
    except Exception as e:
        logger.error(f"Failed to fetch decisions from CrowdSec: {e}")
        return []

def load_whitelist() -> set:
    wl = set()
    if WHITELIST_CSV:
        wl.update([x.strip() for x in WHITELIST_CSV.split(",") if x.strip()])
    try:
        with open(WHITELIST_FILE, "r") as f:
            for line in f:
                line=line.strip()
                if line and not line.startswith("#"):
                    wl.add(line)
    except FileNotFoundError:
        pass
    return wl

# ───────────────────────────
# SSH helper
# ───────────────────────────
def run_remote(script: str) -> int:
    cmd = [
        "ssh",
        "-i", SSH_KEY,
        "-p", SSH_PORT,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=/secrets/known_hosts",
        ROUTER,
        "ash -s"
    ]
    logger.info(f"Pushing rules to router {ROUTER}:{SSH_PORT}")
    proc = subprocess.run(cmd, input=script.encode("utf-8"))
    return proc.returncode

# ───────────────────────────
# Core logic
# ───────────────────────────
def extract_ips(decisions: List[Dict], whitelist: set) -> List[Tuple[str, Dict]]:
    out = []
    for d in decisions:
        if (d.get("scope") or "").lower() != "ip": 
            continue
        val = (d.get("value") or "").strip()
        if not val or "/" in val or "-" in val:
            continue
        if val in whitelist:
            logger.debug(f"Skipping whitelisted IP {val}")
            continue
        meta = {
            "id": d.get("id"),
            "scenario": d.get("scenario"),
            "origin": d.get("origin"),
            "until": d.get("until")
        }
        out.append((val, meta))
        if len(out) >= MAX_IPS:
            break
    return out

def main():
    logger.info("=== CrowdSec → AsusWRT Firewall Sync Start ===")
    whitelist = load_whitelist()
    logger.info(f"Loaded {len(whitelist)} whitelist entries.")
    ctx = build_ssl_ctx()
    decisions = fetch_decisions(ctx)
    logger.info(f"Fetched {len(decisions)} CrowdSec decisions.")

    bad_ips = extract_ips(decisions, whitelist)
    logger.info(f"{len(bad_ips)} IPs selected after filtering and whitelist.")

    ipt = IptablesManager(CHAIN)
    ipt.setupChain()
    for ip, meta in bad_ips:
        ipt.add(ip, meta)
    script = ipt.commit()

    rc = run_remote(script)
    if rc == 0:
        logger.info(f"Chain '{CHAIN}' updated successfully on router {ROUTER}.")
    else:
        logger.error(f"Failed to apply rules on router (rc={rc}).")
        sys.exit(rc)

    logger.info("=== Sync Complete ===")

if __name__ == "__main__":
    main()
