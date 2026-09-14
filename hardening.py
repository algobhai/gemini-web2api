"""Security and routing helpers for the hardened gemini-web2api launcher.

This module deliberately contains no network code and no credentials so it can be
unit-tested independently of Gemini Web.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, asdict
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Model IDs observed from Gemini Web browser captures documented in upstream
# issue #82. These are private-web-protocol identifiers, not official API model IDs.
MODEL_ID_FLASH = "56fdd199312815e2"      # observed: Gemini 3.7 Flash
MODEL_ID_PRO = "e6fa609c3fa255c0"        # observed: Gemini 3.1 Pro
MODEL_ID_FLASH_LITE = "8c46e95b1a07cecc" # observed: Gemini 3.5 Flash-Lite
REJECTED_MODEL_ID = "cf41b0e0dd7d53e5"   # observed silent-substitution marker

# MODE_CATEGORY from Gemini Web. "auto" intentionally sends no routing header,
# preserving the account-default behavior.
CATEGORY_TO_MODEL_ID = {
    1: MODEL_ID_FLASH,
    2: MODEL_ID_FLASH,
    3: MODEL_ID_PRO,
    4: None,
    5: MODEL_ID_FLASH,
    6: MODEL_ID_FLASH_LITE,
}


@dataclass
class RouteDiagnostic:
    requested_category: int
    requested_model_id: Optional[str]
    served_model_id: Optional[str]
    served_label: Optional[str]
    status: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def build_model_header(category: int, *, extended: int = 0) -> Optional[str]:
    """Build Gemini Web's current model-selection header.

    Contract observed in browser captures:
      [1,null,null,null,"<model_id>",null,null,0,[4,5,6,8,4,5,6,8],
       null,null,2,null,null,<category>,<extended>,"<fresh UUID>"]

    Category 4 (auto) intentionally returns None so Gemini uses the account
    default model.
    """
    model_id = CATEGORY_TO_MODEL_ID.get(int(category))
    if not model_id:
        return None
    payload = [
        1, None, None, None, model_id, None, None, 0,
        [4, 5, 6, 8, 4, 5, 6, 8], None, None, 2,
        None, None, int(category), int(extended), str(uuid.uuid4()),
    ]
    return json.dumps(payload, separators=(",", ":"))


def extract_route_metadata(raw: str) -> tuple[Optional[str], Optional[str]]:
    """Extract the latest served model id/label from StreamGenerate frames.

    Gemini Web responses have recently exposed the served model id at slot 39
    and human label at slot 42. The parser is defensive because this is an
    undocumented protocol and can change without notice.
    """
    served_id = None
    served_label = None
    for line in (raw or "").splitlines():
        if '"wrb.fr"' not in line:
            continue
        try:
            outer = json.loads(line)
            inner_s = outer[0][2]
            if not isinstance(inner_s, str):
                continue
            inner = json.loads(inner_s)
            if not isinstance(inner, list):
                continue
            if len(inner) > 39 and isinstance(inner[39], str) and inner[39]:
                served_id = inner[39]
            if len(inner) > 42 and isinstance(inner[42], str) and inner[42]:
                served_label = inner[42]
        except (json.JSONDecodeError, IndexError, TypeError, ValueError):
            continue
    return served_id, served_label


def route_diagnostic(category: int, served_id: Optional[str], served_label: Optional[str]) -> RouteDiagnostic:
    requested_id = CATEGORY_TO_MODEL_ID.get(int(category))

    if int(category) == 4:
        return RouteDiagnostic(category, None, served_id, served_label, "auto", "account-default routing requested")

    if not served_id and not served_label:
        return RouteDiagnostic(category, requested_id, None, None, "unknown", "upstream response did not expose routing metadata")

    if served_id == REJECTED_MODEL_ID:
        return RouteDiagnostic(category, requested_id, served_id, served_label, "mismatch", "upstream silently substituted the requested model")

    label = (served_label or "").lower()
    if int(category) == 3:
        if "pro" in label and "flash" not in label:
            return RouteDiagnostic(category, requested_id, served_id, served_label, "ok", "served label is Pro")
        return RouteDiagnostic(category, requested_id, served_id, served_label, "mismatch", "Pro was requested but upstream did not report a Pro label")

    if int(category) == 6:
        if "lite" in label:
            return RouteDiagnostic(category, requested_id, served_id, served_label, "ok", "served label is Flash-Lite")
        return RouteDiagnostic(category, requested_id, served_id, served_label, "mismatch", "Flash-Lite was requested but upstream reported another tier")

    if int(category) in (1, 2, 5):
        # Thinking categories currently share the Flash selector. We can verify
        # the base tier but not independently prove thinking depth from slot42.
        if "flash" in label and "lite" not in label:
            detail = "served Flash tier"
            if int(category) in (2, 5):
                detail += "; thinking depth is not independently verifiable from the model label"
            return RouteDiagnostic(category, requested_id, served_id, served_label, "ok", detail)
        return RouteDiagnostic(category, requested_id, served_id, served_label, "mismatch", "Flash tier was requested but upstream reported another tier")

    return RouteDiagnostic(category, requested_id, served_id, served_label, "unknown", "unrecognized routing category")


def constant_time_key_match(candidate: str, keys: Iterable[str]) -> bool:
    candidate = candidate or ""
    matched = False
    for key in keys:
        if hmac.compare_digest(candidate, str(key)):
            matched = True
    return matched


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if host in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def redact_url_query(url: str) -> str:
    """Redact credential-like query parameters from a URL/path for logs."""
    try:
        parts = urlsplit(url)
        sensitive = {"key", "api_key", "apikey", "token", "access_token"}
        pairs = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            pairs.append((k, "<redacted>" if k.lower() in sensitive else v))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))
    except Exception:
        return re.sub(r"([?&](?:key|api_key|apikey|token|access_token)=)[^&\s]+", r"\1<redacted>", url, flags=re.I)


def redact_log_line(text: str) -> str:
    """Best-effort removal of common credential forms before logging."""
    text = text or ""
    text = re.sub(r"(Authorization:\s*Bearer\s+)[^\s]+", r"\1<redacted>", text, flags=re.I)
    text = re.sub(r"(x-api-key:\s*)[^\s]+", r"\1<redacted>", text, flags=re.I)
    text = re.sub(r"(x-goog-api-key:\s*)[^\s]+", r"\1<redacted>", text, flags=re.I)
    text = re.sub(r"([?&](?:key|api_key|apikey|token|access_token)=)[^&\s\"]+", r"\1<redacted>", text, flags=re.I)
    return text
