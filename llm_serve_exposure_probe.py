"""llm-serve-exposure-probe: probe YOUR OWN infrastructure for internet-exposed
LLM-serving endpoints (vLLM, Ollama, Triton, LMCache/ZeroMQ).

Hook (2026-10-07): JFrog disclosed CVE-2026-105192 (CVSS 9.8) in LMCache —
a single ZeroMQ network message runs code as the cache user with no
login; no fixed version exists yet (THN). Operators bind inference
infra to routable addresses by mistake.

Port scanners don't speak AI-inference protocols or prove unauthenticated
access on them. This speaks the protocols: HTTP probes for vLLM/Ollama/
Triton health + model-list endpoints, and a raw-socket ZMTP greeting for
ZeroMQ/LMCache listeners.

AUTHORIZED TESTING ONLY. Point this at infrastructure you own or are
explicitly authorized to test. Private/loopback targets are allowed
(self-scan); scanning third-party hosts you don't own is unauthorized
access — don't.
"""

import json
import socket
import urllib.parse
import urllib.request

VERSION = "1.0.0"

DEFAULT_PORTS = (8000, 11434, 8001, 8002, 5555)

# (label, path, evidence_substring) — HTTP probes that prove an
# unauthenticated inference endpoint.
HTTP_PROBES = (
    ("vllm", "/v1/models", "object"),
    ("ollama", "/api/tags", "models"),
    ("triton-http", "/v2/health/ready", "true"),
    ("openai-compatible", "/v1/models", "data"),
)

# ZMTP 3.0 greeting: 64 bytes, signature + version + mechanism.
ZMTP_GREETING = (b"\xff\x00\x00\x00\x00\x00\x00\x00\x01\x7f"  # signature
                 b"\x03\x00"                                  # version 3.0
                 b"NULL" + b"\x00" * 20                        # mechanism
                 + b"\x00" * 30)                              # filler


def probe_http(host, port, timeout=5):
    """Probe HTTP inference endpoints. Returns findings list."""
    findings = []
    for label, path, evidence in HTTP_PROBES:
        url = "http://%s:%d%s" % (host, port, path)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "llm-serve-exposure-probe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
                if resp.status == 200 and evidence.lower() in body.lower():
                    findings.append({
                        "endpoint": label,
                        "url": url,
                        "severity": "CRITICAL",
                        "evidence": ("HTTP 200 on %s with unauthenticated "
                                     "access — body contains %r." % (path, evidence)),
                    })
        except Exception:
            continue
    return findings


def probe_zmtp(host, port, timeout=5):
    """Send a ZMTP 3.0 greeting; a valid ZMTP reply means a ZeroMQ
    listener (LMCache's attack surface). Returns a finding or None."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(ZMTP_GREETING)
        data = sock.recv(64)
        sock.close()
        # ZMTP replies with its own 64-byte greeting starting 0xff 0x00...
        if len(data) >= 10 and data[0:1] == b"\xff" and data[9:10] == b"\x7f":
            return {
                "endpoint": "zeromq",
                "url": "tcp://%s:%d" % (host, port),
                "severity": "CRITICAL",
                "evidence": ("Valid ZMTP greeting reply — a ZeroMQ listener "
                             "is reachable with no authentication. This is "
                             "the CVE-2026-105192 attack surface (LMCache "
                             "RCE via a single unauthenticated message)."),
            }
    except Exception:
        pass
    return None


def scan_host(host, ports=None, timeout=5):
    """Scan a host's ports for exposed LLM-serving endpoints."""
    ports = ports or DEFAULT_PORTS
    findings = []
    for port in ports:
        findings.extend(probe_http(host, port, timeout=timeout))
        z = probe_zmtp(host, port, timeout=timeout)
        if z:
            findings.append(z)
    return {
        "host": host,
        "ports_scanned": list(ports),
        "findings": findings,
        "verdict": ("CLEAN — no exposed LLM-serving endpoints detected on "
                    "probed ports" if not findings
                    else "%d exposed endpoint(s)" % len(findings)),
        "notice": ("AUTHORIZED TESTING ONLY — only scan infrastructure you "
                   "own or are explicitly authorized to test."),
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Probe your own infra for exposed LLM-serving "
                    "endpoints (vLLM, Ollama, Triton, ZeroMQ/LMCache).")
    ap.add_argument("host", help="host to scan (your own infrastructure)")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="comma-separated ports")
    ap.add_argument("--timeout", type=int, default=5)
    args = ap.parse_args(argv)
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    print(json.dumps(scan_host(args.host, ports, args.timeout), indent=2))


if __name__ == "__main__":
    main()
