"""Runtime/auth state shared by the hardened launcher modules."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Optional

from hardening import redact_log_line

ROOT = Path(__file__).resolve().parent
UPSTREAM_FILE = ROOT / "gemini_web2api.py"


def _load_upstream():
    spec = importlib.util.spec_from_file_location("_gemini_web2api_upstream", UPSTREAM_FILE)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load upstream server from {UPSTREAM_FILE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


legacy = _load_upstream()

HARDENED_DEFAULTS = {
    "host": "127.0.0.1",
    "api_keys": [],
    "allow_public": False,
    "cors_allow_origin": None,
    "temporary_chats": True,
    "multimodal_enabled": False,
    "routing_verification": "strict-pro",  # off | warn | strict-pro | strict
    "persist_rotated_cookies": False,
    "cookie_stale_warning_sec": 7200,
    "auth_user_locked": False,
    "xsrf_token_locked": False,
    "gemini_bl_locked": False,
}

AUTH_CACHE = {
    "path": None,
    "mtime": None,
    "cookie": "",
    "sapisid": None,
    "json_payload": None,
}

LAST_ROUTE = {
    "timestamp": None,
    "requested_category": None,
    "requested_model_id": None,
    "served_model_id": None,
    "served_label": None,
    "status": "never-run",
    "detail": "No Gemini request has been completed yet.",
}


def secure_log(message: str):
    if legacy.CONFIG.get("log_requests", True):
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {redact_log_line(str(message))}\n")
        sys.stderr.flush()


legacy.log = secure_log


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    out = {}
    for piece in (cookie_str or "").split(";"):
        if "=" not in piece:
            continue
        name, value = piece.split("=", 1)
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def serialize_cookie_map(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items() if k and v is not None)


def load_auth_file() -> tuple[str, Optional[str]]:
    path = legacy.CONFIG.get("cookie_file")
    if not path:
        return "", None
    path = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.exists(path):
        secure_log("Cookie/auth file does not exist")
        return "", None

    try:
        mtime = os.path.getmtime(path)
        if AUTH_CACHE["path"] == path and AUTH_CACHE["mtime"] == mtime:
            return AUTH_CACHE["cookie"], AUTH_CACHE["sapisid"]

        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        payload = None
        if content.startswith("{"):
            payload = json.loads(content)
            cookie_str = payload.get("cookie", "")
            sapisid = payload.get("sapisid") or parse_cookie_string(cookie_str).get("SAPISID")

            # A fresh export is authoritative unless a field is explicitly locked.
            if payload.get("auth_user") not in (None, "") and not legacy.CONFIG.get("auth_user_locked", False):
                legacy.CONFIG["auth_user"] = payload.get("auth_user")
            if payload.get("xsrf_token") and not legacy.CONFIG.get("xsrf_token_locked", False):
                legacy.CONFIG["xsrf_token"] = payload.get("xsrf_token")
            if payload.get("gemini_bl") and not legacy.CONFIG.get("gemini_bl_locked", False):
                legacy.CONFIG["gemini_bl"] = payload.get("gemini_bl")
        else:
            cookie_str = content
            sapisid = parse_cookie_string(cookie_str).get("SAPISID")

        AUTH_CACHE.update({
            "path": path,
            "mtime": mtime,
            "cookie": cookie_str,
            "sapisid": sapisid or None,
            "json_payload": payload,
        })
        return cookie_str, sapisid or None
    except Exception as exc:
        secure_log(f"Cookie/auth file could not be read: {type(exc).__name__}")
        return AUTH_CACHE.get("cookie", ""), AUTH_CACHE.get("sapisid")


legacy.load_cookie = load_auth_file


def persist_auth_cookie(cookie_str: str) -> None:
    if not legacy.CONFIG.get("persist_rotated_cookies", False):
        return
    path = AUTH_CACHE.get("path")
    payload = AUTH_CACHE.get("json_payload")
    if not path or not isinstance(payload, dict):
        return
    try:
        updated = dict(payload)
        updated["cookie"] = cookie_str
        updated["sapisid"] = parse_cookie_string(cookie_str).get("SAPISID", updated.get("sapisid", ""))
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(updated, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        AUTH_CACHE["mtime"] = os.path.getmtime(path)
        AUTH_CACHE["json_payload"] = updated
    except Exception as exc:
        secure_log(f"Rotated cookies were kept in memory but not persisted: {type(exc).__name__}")


def merge_set_cookie(headers) -> None:
    if not AUTH_CACHE.get("cookie"):
        return
    try:
        if hasattr(headers, "get_list"):
            raw_headers = headers.get_list("set-cookie")
        elif hasattr(headers, "get_all"):
            raw_headers = headers.get_all("Set-Cookie") or []
        else:
            one = headers.get("Set-Cookie") if headers else None
            raw_headers = [one] if one else []
    except Exception:
        raw_headers = []
    if not raw_headers:
        return

    cookies = parse_cookie_string(AUTH_CACHE["cookie"])
    changed = False
    for raw in raw_headers:
        if not raw:
            continue
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            if morsel.value and cookies.get(name) != morsel.value:
                cookies[name] = morsel.value
                changed = True
    if changed:
        cookie_str = serialize_cookie_map(cookies)
        AUTH_CACHE["cookie"] = cookie_str
        AUTH_CACHE["sapisid"] = cookies.get("SAPISID") or AUTH_CACHE.get("sapisid")
        secure_log("Accepted rotated Google session cookies into memory")
        persist_auth_cookie(cookie_str)
