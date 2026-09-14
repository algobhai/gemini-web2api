"""Minimal transport monkey-patches for current Gemini Web model routing.

The upstream request/auth implementation remains untouched. This module only
adds the model-selection header and verifies non-streaming responses.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
from typing import Optional

from hardening import build_model_header, extract_route_metadata, route_diagnostic

_tls = threading.local()


def _category_from_form(data) -> Optional[int]:
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="strict")
        if not isinstance(data, str):
            return None
        form = urllib.parse.parse_qs(data)
        encoded = form.get("f.req", [None])[0]
        if not encoded:
            return None
        outer = json.loads(encoded)
        inner = json.loads(outer[1])
        category = inner[79]
        return int(category) if category is not None else None
    except (ValueError, TypeError, IndexError, json.JSONDecodeError):
        return None


def install_transport_patches(legacy, route_state: dict, log) -> None:
    """Install routing patches into the loaded upstream single-file module."""
    original_request = legacy.urllib.request.Request
    original_extract = legacy.extract_response_text

    def remember_requested(category: Optional[int], streaming: bool = False):
        if category is None:
            return
        _tls.requested_category = category
        route_state.update({
            "timestamp": int(time.time()),
            "requested_category": category,
            "requested_model_id": None,
            "served_model_id": None,
            "served_label": None,
            "status": "stream-unverified" if streaming else "pending",
            "detail": "Streaming responses are not strictly verified." if streaming else "Awaiting upstream routing metadata.",
        })

    def add_routing_header(headers, category: Optional[int]):
        result = dict(headers or {})
        if category is None:
            return result
        model_header = build_model_header(category)
        if model_header:
            result["x-goog-ext-525001261-jspb"] = model_header
            route_state["requested_model_id"] = json.loads(model_header)[4]
        return result

    def routed_request(url, data=None, headers=None, origin_req_host=None,
                       unverifiable=False, method=None):
        category = _category_from_form(data) if "StreamGenerate" in str(url) else None
        if category is not None:
            remember_requested(category, streaming=False)
            headers = add_routing_header(headers, category)
        return original_request(
            url, data=data, headers=headers or {}, origin_req_host=origin_req_host,
            unverifiable=unverifiable, method=method,
        )

    legacy.urllib.request.Request = routed_request

    # The streaming code uses httpx directly, so patch its Client class too.
    if legacy.HAS_HTTPX:
        original_client = legacy.httpx.Client

        class RoutedHttpxClient(original_client):
            def stream(self, method, url, *args, **kwargs):
                category = None
                if str(method).upper() == "POST" and "StreamGenerate" in str(url):
                    category = _category_from_form(kwargs.get("content"))
                if category is not None:
                    remember_requested(category, streaming=True)
                    kwargs["headers"] = add_routing_header(kwargs.get("headers"), category)
                return super().stream(method, url, *args, **kwargs)

        legacy.httpx.Client = RoutedHttpxClient

    def verified_extract(raw: str) -> str:
        text = original_extract(raw)
        category = getattr(_tls, "requested_category", None)
        if category is None:
            return text

        served_id, served_label = extract_route_metadata(raw)
        diag = route_diagnostic(category, served_id, served_label)
        route_state.update({"timestamp": int(time.time()), **diag.to_dict()})
        if diag.status == "mismatch":
            log(f"ROUTING MISMATCH: {diag.detail}; served={served_label or served_id or 'unknown'}")

        mode = str(legacy.CONFIG.get("routing_verification", "strict-pro")).lower()
        strict_failure = diag.status == "mismatch"
        if diag.status == "unknown" and int(category) == 3 and mode in {"strict-pro", "strict"}:
            strict_failure = True
        if strict_failure and (mode == "strict" or (mode == "strict-pro" and int(category) == 3)):
            raise RuntimeError(f"model routing verification failed: {diag.detail}")
        return text

    legacy.extract_response_text = verified_extract
