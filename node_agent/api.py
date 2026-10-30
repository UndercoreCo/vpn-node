"""Authenticated management API; no upstream errors or secret documents in logs."""

import asyncio
import hmac
import json
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from .models import Create, Renewal, Replacement, Model, NodeError
from .runtime import Runtime
from .store import Store


class Service:
    def __init__(self, settings, runtime=None):
        self.settings = settings
        self.store = Store(settings.state_directory, settings.capacity)
        self.runtime = runtime or Runtime(
            Path(settings.state_directory), settings.apply_timeout_seconds
        )
        self.lock = asyncio.Lock()
        self.certificate = Path(settings.certificate_file).read_text()

    def envelope(self, **fields):
        return dict(
            schema_version=1,
            server_id=self.settings.server_id,
            protocol="trusttunnel",
            status="ok",
            **fields,
        )

    async def synchronized(self):
        generation, rows = self.store.snapshot()
        await self.runtime.apply(generation, rows)
        return rows

    def client_snapshot(self, remote_id):
        return self.envelope(
            applied=True, client=self.store.view(self.store.row(remote_id))
        )

    def connection(self, remote_id):
        row = self.store.row(remote_id)
        if self.store.view(row)["status"] != "active":
            raise NodeError("access_unavailable", 410)
        values = dict(
            hostname=self.settings.hostname,
            addresses=[self.settings.endpoint_address],
            username=row["client_id"],
            password=row["secret"],
            has_ipv6=False,
            skip_verification=False,
            certificate=self.certificate,
            upstream_protocol="http2",
            anti_dpi=False,
        )
        export = "".join(
            f"{key} = {json.dumps(value)}\n" for key, value in values.items()
        )
        return self.envelope(
            applied=True,
            client=self.store.view(row),
            endpoint_export=export,
            ipv6_available=False,
            transport="http2",
        )


def create_app(settings, runtime=None):
    service = Service(settings, runtime)
    token_path = Path(settings.token_file)
    if token_path.stat().st_mode & 0o077:
        raise ValueError("Token file must be private")
    token = token_path.read_text().strip()
    if len(token) < 32 or any(char.isspace() for char in token):
        raise ValueError("Invalid service token")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service = service

    @app.middleware("http")
    async def protect(request: Request, call_next):
        headers = {"Cache-Control": "private, no-store"}
        if not hmac.compare_digest(
            request.headers.get("authorization", "").encode(),
            ("Bearer " + token).encode(),
        ):
            return JSONResponse(
                {"detail": "unauthorized"}, status_code=401, headers=headers
            )
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                return JSONResponse(
                    {"detail": "request_too_large"}, status_code=413, headers=headers
                )
        request._body = bytes(body)
        try:
            response = await call_next(request)
        except Exception:
            return JSONResponse(
                {"detail": "node_unavailable"}, status_code=503, headers=headers
            )
        response.headers.update(headers)
        return response

    @app.exception_handler(NodeError)
    async def failure(_, error):
        return JSONResponse({"detail": error.code}, status_code=error.status)

    @app.get("/v1/health")
    async def health():
        async with service.lock:
            await service.synchronized()
            return service.envelope(
                capabilities=dict(
                    idempotent_create=True, enforces_expiry=True, confirmed_revoke=True
                )
            )

    @app.get("/v1/clients")
    async def listing():
        async with service.lock:
            rows = await service.synchronized()
            return service.envelope(clients=[service.store.view(row) for row in rows])

    async def parse(request, model):
        try:
            return model.model_validate(await request.json())
        except (ValueError, ValidationError):
            raise NodeError("invalid_request", 422) from None

    @app.post("/v1/clients")
    async def create(request: Request):
        body = await parse(request, Create)
        async with service.lock:
            remote = service.store.create(body)
            await service.synchronized()
            return service.client_snapshot(remote)

    @app.get("/v1/clients/{remote}")
    async def get(remote: str):
        async with service.lock:
            service.store.row(remote)
            await service.synchronized()
            return service.client_snapshot(remote)

    @app.get("/v1/clients/{remote}/connection")
    async def connection(remote: str):
        async with service.lock:
            service.store.row(remote)
            await service.synchronized()
            return service.connection(remote)

    @app.post("/v1/clients/{remote}/{operation}")
    async def mutate(remote: str, operation: str, request: Request):
        models = dict(renew=Renewal, replace=Replacement, enable=Model, disable=Model)
        if operation not in models:
            raise NodeError("unsupported_operation", 422)
        body = await parse(request, models[operation])
        async with service.lock:
            service.store.mutate(remote, operation, body.model_dump())
            await service.synchronized()
            return service.client_snapshot(remote)

    return app
