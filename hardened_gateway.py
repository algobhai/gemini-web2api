#!/usr/bin/env python3
"""Hardened launcher for gemini-web2api.

Run:
    python hardened_gateway.py --config config.hardened.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from hardening import constant_time_key_match, is_loopback_host, redact_log_line
from hardened_transport import install_transport_patches

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
    "cookie_stale_warning_sec": 7200,
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
install_transport_patches(legacy, LAST_ROUTE, secure_log)

# Keep upstream cookie/session parsing, but reload non-cookie metadata from a
# freshly exported gemini-auth.json whenever that file changes.
_original_load_cookie = legacy.load_cookie
_auth_meta_mtime = None


def _refresh_auth_metadata() -> None:
    global _auth_meta_mtime
    path = legacy.CONFIG.get("cookie_file")
    if not path:
        return
    path = os.path.abspath(os.path.expanduser(str(path)))
    try:
        mtime = os.path.getmtime(path)
        if _auth_meta_mtime == mtime:
            return
        with open(path, "r", encoding="utf-8") as f:
            content = f.read(1)
            if content != "{":
                _auth_meta_mtime = mtime
                return
            f.seek(0)
            payload = json.load(f)
        if payload.get("auth_user") not in (None, ""):
            legacy.CONFIG["auth_user"] = payload["auth_user"]
        if payload.get("xsrf_token"):
            legacy.CONFIG["xsrf_token"] = payload["xsrf_token"]
        if payload.get("gemini_bl"):
            legacy.CONFIG["gemini_bl"] = payload["gemini_bl"]
        _auth_meta_mtime = mtime
    except (OSError, ValueError, TypeError):
        return


def _load_cookie_with_metadata():
    _refresh_auth_metadata()
    return _original_load_cookie()


legacy.load_cookie = _load_cookie_with_metadata

# Default-off multimodal until upstream's conversation binding is fixed.
_original_upload_images = legacy.upload_images


def _guarded_upload_images(images):
    if images and not legacy.CONFIG.get("multimodal_enabled", False):
        raise RuntimeError(
            "multimodal input is disabled in hardened mode because the current upstream "
            "Gemini Web upload path can fail with BardErrorInfo [1003]"
        )
    return _original_upload_images(images)


legacy.upload_images = _guarded_upload_images


class HardenedHandler(legacy.GeminiHandler):
    def log_message(self, fmt, *args):
        ip = self.client_address[0] if self.client_address else "-"
        secure_log(f"{ip} {redact_log_line(fmt % args)}")

    def send_header(self, keyword, value):
        key = keyword.lower()
        if key == "access-control-allow-origin":
            origin = legacy.CONFIG.get("cors_allow_origin")
            if not origin:
                return
            value = str(origin)
        elif key == "access-control-allow-headers" and not legacy.CONFIG.get("cors_allow_origin"):
            return
        return super().send_header(keyword, value)

    def _authorized(self):
        keys = [str(k) for k in (legacy.CONFIG.get("api_keys") or [])]
        if not keys:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and constant_time_key_match(auth[7:], keys):
            return True
        for header_name in ("x-api-key", "x-goog-api-key"):
            if constant_time_key_match(self.headers.get(header_name, ""), keys):
                return True
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            return any(constant_time_key_match(candidate, keys) for candidate in query.get("key", []))
        except Exception:
            return False

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/v1/_diagnostics/routing":
            if not self._authorized():
                self.send_json({"error": {"message": "invalid api key"}}, 401)
                return
            payload = dict(LAST_ROUTE)
            payload["routing_header_enabled"] = True
            payload["multimodal_enabled"] = bool(legacy.CONFIG.get("multimodal_enabled", False))
            payload["host"] = legacy.CONFIG.get("host")
            payload["cors_allow_origin"] = legacy.CONFIG.get("cors_allow_origin")
            self.send_json(payload)
            return
        return super().do_GET()


class ThreadedServer(legacy.ThreadingMixIn, legacy.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _read_config(path: Optional[str]) -> dict:
    cfg = dict(legacy.DEFAULT_CONFIG)
    cfg.update(HARDENED_DEFAULTS)
    if path:
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        if not isinstance(user_cfg, dict):
            raise ValueError("config must contain a JSON object")
        cfg.update(user_cfg)
    return cfg


def _validate_exposure(cfg: dict) -> None:
    host = str(cfg.get("host") or "127.0.0.1")
    if is_loopback_host(host):
        return
    if not cfg.get("allow_public", False):
        raise SystemExit(
            f"Refusing to bind to non-loopback host {host!r}. Set allow_public=true only if you "
            "understand the exposure and have configured an API key."
        )
    if not (cfg.get("api_keys") or []):
        raise SystemExit("Refusing public bind without api_keys. Configure at least one strong API key.")


def _warn_cookie_age():
    path = legacy.CONFIG.get("cookie_file")
    threshold = int(legacy.CONFIG.get("cookie_stale_warning_sec") or 0)
    if not path or threshold <= 0:
        return
    try:
        age = time.time() - os.path.getmtime(os.path.expanduser(str(path)))
        if age > threshold:
            secure_log(
                f"WARNING: auth file is about {int(age // 60)} minutes old. Gemini Web can silently "
                "downgrade Pro when rotating session cookies become stale; re-export auth if routing fails."
            )
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description="Hardened Gemini Web to OpenAI API gateway")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--config", default="config.hardened.json")
    parser.add_argument("--cookie-file", default=None)
    parser.add_argument("--proxy", default=None)
    args = parser.parse_args()

    config_path = args.config if args.config and os.path.exists(args.config) else None
    cfg = _read_config(config_path)
    if args.port is not None:
        cfg["port"] = args.port
    if args.cookie_file:
        cfg["cookie_file"] = args.cookie_file
    if args.proxy:
        cfg["proxy"] = args.proxy

    legacy.CONFIG.clear()
    legacy.CONFIG.update(cfg)
    _validate_exposure(legacy.CONFIG)
    _refresh_auth_metadata()
    _warn_cookie_age()

    host = legacy.CONFIG["host"]
    port = int(legacy.CONFIG["port"])
    server = ThreadedServer((host, port), HardenedHandler)

    print("gemini-web2api hardened gateway")
    print(f"  Listening: http://{host}:{port}")
    base = f"http://127.0.0.1:{port}/v1" if is_loopback_host(host) else f"http://{host}:{port}/v1"
    print(f"  Base URL:  {base}")
    print(f"  Auth:      {'API key required' if legacy.CONFIG.get('api_keys') else 'local-only / no API key'}")
    print(f"  Cookie:    {'configured' if legacy.CONFIG.get('cookie_file') else 'anonymous'}")
    print(f"  CORS:      {legacy.CONFIG.get('cors_allow_origin') or 'disabled'}")
    print(f"  Images:    {'enabled (experimental)' if legacy.CONFIG.get('multimodal_enabled') else 'disabled'}")
    print(f"  Verify:    {legacy.CONFIG.get('routing_verification')}")
    print("  Diagnostic: /v1/_diagnostics/routing")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
