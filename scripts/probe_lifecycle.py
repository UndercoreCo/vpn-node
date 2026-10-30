#!/usr/bin/env python3
import argparse
import json
import uuid
import time
import subprocess
import socket
import tempfile
import urllib.request
import tomllib
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

parser = argparse.ArgumentParser(
    description="Explicit live lifecycle probe; creates/revokes temporary test access. Requires Python 3.11+ and a verified official SOCKS client. Does not change local routes."
)
parser.add_argument("--api", required=True)
parser.add_argument("--token-file", required=True, type=Path)
parser.add_argument("--binary", required=True, type=Path)
parser.add_argument("--sha256", required=True)
parser.add_argument("--expected-egress", required=True)
parser.add_argument(
    "--stream-url",
    required=True,
    help="Controlled HTTP source sending a continuous stream for at least 30 seconds",
)
parser.add_argument(
    "--agent-host",
    help="Optional SSH test host: permits stopping/starting undercore-trusttunnel-agent.service for expiry test",
)
args = parser.parse_args()
assert args.api.startswith("https://") or args.api.startswith("http://127.0.0.1:")
assert args.token_file.stat().st_mode & 0o077 == 0
assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == args.sha256
TOKEN = args.token_file.read_text().strip()
BINARY = str(args.binary.resolve())


def agent(action):
    if args.agent_host:
        assert not args.agent_host.startswith("-")
        subprocess.run(
            [
                "ssh",
                args.agent_host,
                "systemctl " + action + " undercore-trusttunnel-agent.service",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("API redirects are not permitted")


opener = urllib.request.build_opener(NoRedirect())
children = []
clients = []


def api(path, body=None):
    req = urllib.request.Request(
        args.api.rstrip("/") + "/v1/" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Content-Type": "application/json",
        },
    )
    with opener.open(req, timeout=12) as r:
        assert "no-store" in r.headers["Cache-Control"]
        return json.load(r)


def create(seconds=300):
    payload = dict(
        external_id="lab-" + uuid.uuid4().hex,
        name="Lifecycle test",
        expires_at=(datetime.now(timezone.utc) + timedelta(seconds=seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    )
    c = api("clients", payload)["client"]
    clients.append(c["client_id"])
    assert api("clients", payload)["client"]["client_id"] == c["client_id"]
    return c


folder = tempfile.TemporaryDirectory(prefix="uc-tt-lifecycle-")


def start(c, transport="http2", export=None):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    export = (
        export or api("clients/" + c["client_id"] + "/connection")["endpoint_export"]
    )
    values = tomllib.loads(export)
    assert values["skip_verification"] is False
    values["upstream_protocol"] = transport
    adapted = "[endpoint]\n" + "".join(
        k + " = " + json.dumps(v) + "\n" for k, v in values.items()
    )
    path = Path(folder.name) / f"{port}.toml"
    path.write_text(
        'loglevel = "error"\nvpn_mode = "general"\nkillswitch_enabled = false\n'
        + adapted
        + f'\n[listener.socks]\naddress = "127.0.0.1:{port}"\n'
    )
    path.chmod(0o600)
    child = subprocess.Popen(
        [BINARY, "--config", str(path), "--loglevel", "error"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    children.append(child)
    time.sleep(2)
    assert child.poll() is None
    return port, export


def curl(port, url, timeout=8):
    return subprocess.run(
        [
            "curl",
            "--silent",
            "--fail",
            "--max-time",
            str(timeout),
            "--noproxy",
            "",
            "--proxy",
            f"socks5h://127.0.0.1:{port}",
            url,
        ],
        capture_output=True,
        timeout=timeout + 2,
    )


def stream(port):
    p = Path(folder.name) / f"{port}.stream"
    with p.open("wb") as f:
        proc = subprocess.Popen(
            [
                "curl",
                "--silent",
                "--max-time",
                "25",
                "--noproxy",
                "",
                "--proxy",
                f"socks5h://127.0.0.1:{port}",
                args.stream_url,
            ],
            stdout=f,
            stderr=subprocess.DEVNULL,
        )
    children.append(proc)
    return proc, p


def result(name):
    print(json.dumps({"check": name, "ok": True}), flush=True)


try:
    assert api("health")["capabilities"]["confirmed_revoke"]
    a, b = create(), create()
    pa, old = start(a)
    pb, _ = start(b, "http3")
    for p in [pa, pb]:
        r = curl(p, "https://api.ipify.org")
        assert r.returncode == 0 and r.stdout.strip() == args.expected_egress.encode()
    result("http2_http3_egress_and_idempotent_create")
    sa, fa = stream(pa)
    sb, fb = stream(pb)
    time.sleep(2)
    assert fa.stat().st_size > 0 and fb.stat().st_size > 0
    api("clients/" + a["client_id"] + "/disable", {})
    time.sleep(1)
    sizea = fa.stat().st_size
    sizeb = fb.stat().st_size
    time.sleep(2)
    assert fa.stat().st_size == sizea and fb.stat().st_size > sizeb
    assert curl(pa, "https://example.com", 3).returncode != 0
    result("confirmed_revoke_closes_active_stream_preserves_other_client")
    api("clients/" + a["client_id"] + "/enable", {})
    pa, _ = start(a)
    assert curl(pa, "https://example.com").returncode == 0
    payload = dict(
        expires_at=a["expires_at"],
        idempotency_key="rotate-" + uuid.uuid4().hex,
        expected_external_id=a["external_id"],
        allow_create=False,
    )
    api("clients/" + a["client_id"] + "/replace", payload)
    api("clients/" + a["client_id"] + "/replace", payload)
    assert curl(pa, "https://example.com", 3).returncode != 0
    pn, _ = start(a)
    assert curl(pn, "https://example.com").returncode == 0
    result("durable_rotation_replay_old_password_rejected")
    c = create(10)
    pc, _ = start(c)
    sc, fc = stream(pc)
    time.sleep(1)
    assert fc.stat().st_size > 0
    agent("stop")
    time.sleep(10)
    size = fc.stat().st_size
    time.sleep(2)
    assert fc.stat().st_size == size
    assert curl(pc, "https://example.com", 3).returncode != 0
    result(
        "expiry_closes_active_stream"
        + ("_with_agent_stopped" if args.agent_host else "")
    )
finally:
    cleanup_ok = True
    try:
        agent("start")
        deadline = time.monotonic() + 20
        while True:
            try:
                api("health")
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Agent did not become ready for cleanup"
                    ) from None
                time.sleep(0.25)
        for c in clients:
            try:
                reply = api("clients/" + c + "/disable", {})
                if reply["client"]["status"] not in ("disabled", "expired"):
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
    except Exception:
        cleanup_ok = False
    finally:
        for p in children:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        folder.cleanup()
    if not cleanup_ok:
        raise RuntimeError(
            "Test access cleanup unconfirmed; grants expire within five minutes"
        ) from None
    result("test_grants_revoked")
