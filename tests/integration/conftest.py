"""
Cross-service integration fixtures for BuildOS Auth Service.

These tests run the real BuildOS User Service as a separate local
uvicorn process and communicate with it over HTTP.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest

from app.core.config import get_settings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
USER_SERVICE_ROOT = PROJECT_ROOT.parent / "019-buildos-user-service"

INTEGRATION_API_KEY = "buildos-cross-service-test-key"


def _find_free_port() -> int:
    """Reserve an available local TCP port."""
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_service(
    base_url: str,
    *,
    timeout: float = 20.0,
) -> None:
    """Wait until the User Service health endpoint responds."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"{base_url}/health",
                timeout=1.0,
            )

            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass

        time.sleep(0.25)

    raise RuntimeError(
        f"User Service did not become available at {base_url}.",
    )


@pytest.fixture(scope="session")
def user_service_url() -> Generator[str, None, None]:
    """
    Start the real 019 User Service for the integration test session.

    The subprocess receives a dedicated test-only internal API key.
    The 018 test configuration is pointed at the same key below.
    """
    if not USER_SERVICE_ROOT.exists():
        pytest.fail(
            f"User Service repository not found: {USER_SERVICE_ROOT}",
        )

    user_service_python = USER_SERVICE_ROOT / ".venv" / "bin" / "python"

    if not user_service_python.exists():
        pytest.fail(
            f"User Service virtualenv not found: {user_service_python}",
        )

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    environment = os.environ.copy()

    # Override 019's .env/default value for this isolated test process.
    environment["INTERNAL_API_KEY"] = INTEGRATION_API_KEY

    process = subprocess.Popen( # pylint: disable=consider-using-with
        [
            str(user_service_python),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=USER_SERVICE_ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_service(base_url)
        yield base_url
    finally:
        if process.poll() is None:
            process.terminate()

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def configure_user_service_url(
    user_service_url: str,  # pylint: disable=redefined-outer-name
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    """
    Point the 018 UserService integration client at the real 019 process.
    """
    settings = get_settings()

    monkeypatch.setattr(
        settings,
        "user_service_url",
        user_service_url,
    )

    # Match the dedicated key supplied to the 019 subprocess.
    monkeypatch.setattr(
        settings,
        "user_service_api_key",
        INTEGRATION_API_KEY,
    )

    monkeypatch.setattr(
        settings,
        "user_service_id",
        "buildos-auth-service",
    )

    return user_service_url


@pytest.fixture
def integration_registration_payload() -> dict[str, str]:
    """Return a unique valid registration payload."""
    unique = uuid.uuid4().hex[:10]
    phone_suffix = str(int(unique, 16))[-8:].zfill(8)

    return {
        "email": f"crossservice_{unique}@example.com",
        "phone": f"+234801{phone_suffix}",
        "username": f"crossservice_{unique}",
        "first_name": "Cross",
        "last_name": "Service",
        "display_name": "Cross Service",
        "country": "NG",
        "timezone": "Africa/Lagos",
        "language": "en",
        "password": "TestPassword123!",
    }
