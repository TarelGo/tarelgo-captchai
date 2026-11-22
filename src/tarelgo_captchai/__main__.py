"""Entrypoint: python -m tarelgo_captchai (or the tarelgo-captchai script)."""

from __future__ import annotations

import uvicorn

from .config import get_settings


def tarelgo_main() -> None:
    """Run the service on the configured host/port (default 127.0.0.1:8008)."""
    settings = get_settings()

    from .main import create_app

    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        access_log=False,          # decisions are logged by our own middleware
        server_header=False,       # do not advertise the implementation
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    tarelgo_main()
