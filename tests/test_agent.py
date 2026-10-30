from datetime import datetime, timedelta, timezone
import asyncio
import json
import sqlite3
import time
import pytest
from fastapi.testclient import TestClient
from node_agent.api import create_app
from node_agent.models import Settings, NodeError
from node_agent.runtime import Runtime, atomic_json
from node_agent.store import Store


def future(days=1):
    return (
        (datetime.now(timezone.utc) + timedelta(days=days))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class RuntimeSpy:
    def __init__(self):
        self.fail = False
        self.last = None

    async def apply(self, generation, rows):
        self.last = generation, rows
        if self.fail:
            raise NodeError("runtime_unconfirmed")


@pytest.fixture
def node(tmp_path):
    token = tmp_path / "service.token"
    token.write_text("x" * 40)
    token.chmod(0o600)
    cert = tmp_path / "public-certificate"
    cert.write_text("synthetic-certificate")
    settings = Settings(
        server_id="lab",
        state_directory=str(tmp_path / "state"),
        token_file=str(token),
        hostname="node.example.invalid",
        endpoint_address="203.0.113.10:9443",
        certificate_file=str(cert),
    )
    runtime = RuntimeSpy()
    app = create_app(settings, runtime)
    with TestClient(app) as client:
        client.headers["authorization"] = "Bearer " + "x" * 40
        yield client, runtime, app.state.service, settings


def create(client):
    body = dict(external_id="device-example", name="Mac", expires_at=future())
    response = client.post("/v1/clients", json=body)
    assert response.status_code == 200
    return response.json()["client"], body


def test_auth_precedes_decoding_and_all_responses_are_private(node):
    client, _, _, _ = node
    response = client.post(
        "/v1/clients", headers={"authorization": ""}, content="invalid"
    )
    assert response.status_code == 401
    assert "no-store" in response.headers["cache-control"]
    response = client.post("/v1/clients", content="invalid")
    assert response.status_code == 422 and response.json() == {
        "detail": "invalid_request"
    }
    assert client.post("/v1/clients", content=b"x" * 16385).status_code == 413


def test_create_retry_survives_response_loss_and_agent_restart(node):
    client, runtime, service, settings = node
    body = dict(external_id="device-example", name="Mac", expires_at=future())
    runtime.fail = True
    assert client.post("/v1/clients", json=body).status_code == 503
    rows = service.store.snapshot()[1]
    assert len(rows) == 1
    runtime.fail = False
    with TestClient(create_app(settings, runtime)) as restarted:
        restarted.headers.update(client.headers)
        response = restarted.post("/v1/clients", json=body)
        assert response.status_code == 200
        assert response.json()["client"]["client_id"] == rows[0]["client_id"]
        assert len(service.store.snapshot()[1]) == 1
    assert (
        client.post("/v1/clients", json={**body, "expires_at": future(2)}).status_code
        == 409
    )


def test_connection_is_atomic_private_and_does_not_allocate(node):
    client, _, service, _ = node
    row, _ = create(client)
    before = service.store.snapshot()[0]
    response = client.get("/v1/clients/" + row["client_id"] + "/connection")
    assert response.status_code == 200
    body = response.json()
    assert body["applied"] is True and body["ipv6_available"] is False
    assert "skip_verification = false" in body["endpoint_export"]
    assert row["client_id"] in body["endpoint_export"]
    assert service.store.snapshot()[0] == before
    assert set(body["client"]) == {
        "client_id",
        "external_id",
        "name",
        "expires_at",
        "status",
        "created_at",
        "updated_at",
    }


def test_disable_requires_runtime_ack_and_remains_disabled_after_timeout(node):
    client, runtime, service, _ = node
    row, _ = create(client)
    path = "/v1/clients/" + row["client_id"]
    runtime.fail = True
    assert client.post(path + "/disable", json={}).status_code == 503
    assert (
        service.store.view(service.store.row(row["client_id"]))["status"] == "disabled"
    )
    runtime.fail = False
    for _ in range(2):
        assert (
            client.post(path + "/disable", json={}).json()["client"]["status"]
            == "disabled"
        )
        assert client.get(path + "/connection").status_code == 410
    assert client.post(path + "/enable", json={}).json()["client"]["status"] == "active"


def test_expired_access_cannot_be_enabled_or_exported(node, monkeypatch):
    client, _, service, _ = node
    row, _ = create(client)
    monkeypatch.setattr("node_agent.store.time.time", lambda: 4102444800)
    path = "/v1/clients/" + row["client_id"]
    assert client.get(path).json()["client"]["status"] == "expired"
    assert client.get(path + "/connection").status_code == 410
    assert client.post(path + "/enable", json={}).status_code == 410


def test_rotation_is_durable_idempotent_and_bound_to_owner(node):
    client, runtime, service, _ = node
    row, _ = create(client)
    path = "/v1/clients/" + row["client_id"]
    original = service.store.row(row["client_id"])["secret"]
    body = dict(
        expires_at=future(2),
        idempotency_key="replace-example",
        expected_external_id=row["external_id"],
        allow_create=True,
    )
    assert (
        client.post(
            path + "/replace", json={**body, "expected_external_id": "wrong"}
        ).status_code
        == 409
    )
    runtime.fail = True
    assert client.post(path + "/replace", json=body).status_code == 503
    rotated = service.store.row(row["client_id"])["secret"]
    assert rotated != original
    runtime.fail = False
    assert client.post(path + "/replace", json=body).status_code == 200
    assert service.store.row(row["client_id"])["secret"] == rotated
    assert (
        client.post(
            path + "/replace", json={**body, "expires_at": future(3)}
        ).status_code
        == 409
    )
    client.post(path + "/disable", json={})
    client.post(path + "/replace", json=body)
    assert client.get(path).json()["client"]["status"] == "disabled"


def test_invalid_requests_do_not_change_state_or_echo_input(node):
    client, _, service, _ = node
    response = client.post("/v1/clients", json={"unknown": "private-test-material"})
    assert response.status_code == 422
    assert "private-test-material" not in response.text
    assert service.store.snapshot()[1] == []
    assert client.get("/v1/clients/nonexistent/connection").status_code == 404


def test_private_journal_and_future_schema_refused(node):
    _, _, service, settings = node
    path = service.store.path
    assert path.stat().st_mode & 0o077 == 0
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=2")
    with pytest.raises(NodeError, match="unsupported_schema"):
        Store(settings.state_directory, 10)


def test_ack_must_be_fresh_applied_and_exact_generation(tmp_path):
    runtime = Runtime(tmp_path, timeout=0.08)
    for changes in ({"generation": 1}, {"applied": False}, {"wall_ms": 0}):
        ack = dict(
            generation=2, applied=True, boot="test", wall_ms=int(time.time() * 1000)
        )
        ack.update(changes)
        atomic_json(tmp_path / "ack.json", ack)
        with pytest.raises(NodeError, match="runtime_unconfirmed"):
            asyncio.run(runtime.apply(2, []))
    atomic_json(
        tmp_path / "ack.json",
        dict(generation=2, applied=True, boot="test", wall_ms=int(time.time() * 1000)),
    )
    asyncio.run(runtime.apply(2, []))
    assert json.loads((tmp_path / "snapshot.json").read_bytes()) == dict(
        generation=2, clients=[]
    )
    assert (tmp_path / "snapshot.json").stat().st_mode & 0o077 == 0
