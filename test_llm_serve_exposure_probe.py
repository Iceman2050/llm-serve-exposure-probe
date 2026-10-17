"""Tests for llm_serve_exposure_probe (local socket servers; no external net)."""
import socket
import sys
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_serve_exposure_probe import (  # noqa: E402
    probe_http, probe_zmtp, scan_host, ZMTP_GREETING)

PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print("PASS  " + name)
    except Exception as e:  # noqa: BLE001
        FAIL.append((name, repr(e)))
        print("FAIL  %s: %r" % (name, e))


class _VLLM(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            body = b'{"object":"list","data":[{"id":"canary-model"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _zmtp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _run():
        try:
            conn, _ = srv.accept()
            conn.settimeout(3)
            conn.recv(64)
            conn.sendall(ZMTP_GREETING)  # valid ZMTP reply
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=_run, daemon=True).start()
    return port


def t_vllm_detected_critical():
    srv = _serve(_VLLM)
    port = srv.server_address[1]
    f = probe_http("127.0.0.1", port)
    assert any(x["endpoint"] == "vllm" and x["severity"] == "CRITICAL" for x in f), f
    srv.shutdown()


def t_closed_port_no_findings():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert probe_http("127.0.0.1", port) == []
    assert probe_zmtp("127.0.0.1", port) is None


def t_zmtp_greeting_detected():
    port = _zmtp_server()
    f = probe_zmtp("127.0.0.1", port)
    assert f is not None and f["endpoint"] == "zeromq"
    assert f["severity"] == "CRITICAL"
    assert "CVE-2026-105192" in f["evidence"]


def t_scan_host_verdict_clean():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = scan_host("127.0.0.1", ports=[port])
    assert r["verdict"].startswith("CLEAN")
    assert "AUTHORIZED TESTING ONLY" in r["notice"]


def t_scan_host_verdict_exposed():
    srv = _serve(_VLLM)
    port = srv.server_address[1]
    r = scan_host("127.0.0.1", ports=[port])
    assert "exposed endpoint" in r["verdict"]
    srv.shutdown()


def test_all_checks():
    for name, fn in sorted(
            [(k, v) for k, v in globals().items() if k.startswith("t_")]):
        check(name, fn)
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    assert not FAIL


if __name__ == "__main__":
    test_all_checks()
