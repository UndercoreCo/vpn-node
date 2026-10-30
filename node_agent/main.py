import argparse
import os
from pathlib import Path
import uvicorn
from .models import Settings
from .api import create_app


def main():
    parser = argparse.ArgumentParser(
        description="Independent TrustTunnel node agent (experimental)"
    )
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8795)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    args = parser.parse_args()
    if args.listen not in ("127.0.0.1", "::1") and not (args.tls_cert and args.tls_key):
        parser.error("External API requires TLS")
    os.umask(0o077)
    settings = Settings.model_validate_json(args.settings.read_bytes())
    uvicorn.run(
        create_app(settings),
        host=args.listen,
        port=args.port,
        workers=1,
        access_log=False,
        limit_concurrency=64,
        timeout_keep_alive=5,
        ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
        ssl_keyfile=str(args.tls_key) if args.tls_key else None,
    )


if __name__ == "__main__":
    main()
