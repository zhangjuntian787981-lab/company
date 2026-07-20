#!/usr/bin/env python3
"""Strict report redaction and leak detection.

The harness may inspect request/response data in memory, but persisted evidence is limited
 to hashes, sizes, shapes, counts, and status. This module is the final safety boundary.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

REDACTED = "[REDACTED]"

# Key names whose values must never be persisted. Matching is deliberately broad.
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:authorization|proxy_authorization|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|client[_-]?secret|oauth|credential|secret)(?:$|[_-])",
    re.IGNORECASE,
)
_RAW_BODY_KEY = re.compile(
    r"^(?:raw(?:[_-](?:request|response))?|request[_-]?body|response[_-]?body|"
    r"request|response|headers?)$",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{4,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
)
_JSON_SECRET_FIELD = re.compile(
    r'"(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|'
    r'id[_-]?token|client[_-]?secret)"\s*:\s*"(?!\[REDACTED\])[^"\r\n]+"',
    re.IGNORECASE,
)
_JSON_RAW_BODY_FIELD = re.compile(
    r'"(?:raw|request[_-]?body|response[_-]?body)"\s*:', re.IGNORECASE
)

DEFAULT_CANARIES = (
    "COMPAT-CANARY-AUTH-7a9d1c",
    "COMPAT-CANARY-OAUTH-31f8e2",
    "COMPAT-CANARY-APIKEY-b44c90",
    "COMPAT-CANARY-BODY-5d01af",
)


def is_sensitive_key(key: str) -> bool:
    """Return True when a key could carry a credential or secret."""
    return bool(_SENSITIVE_KEY.search(key))


def is_raw_body_key(key: str) -> bool:
    """Return True for fields that could contain raw headers or bodies."""
    return bool(_RAW_BODY_KEY.match(key))


def sanitize(value: Any, canaries: Sequence[str] = DEFAULT_CANARIES) -> Any:
    """Return a report-safe copy, dropping forbidden fields and redacting strings."""
    if isinstance(value, Mapping):
        clean: Dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if is_sensitive_key(key) or is_raw_body_key(key):
                continue
            clean[key] = sanitize(item, canaries)
        return clean
    if isinstance(value, (list, tuple)):
        return [sanitize(item, canaries) for item in value]
    if isinstance(value, bytes):
        return {
            "payload_bytes": len(value),
            "payload_sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, str):
        result = value
        for canary in canaries:
            if canary and canary in result:
                result = result.replace(canary, REDACTED)
        for pattern in _SECRET_VALUE_PATTERNS:
            result = pattern.sub(REDACTED, result)
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize(str(value), canaries)


def _json_shape(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        safe_keys = sorted(
            str(key)
            for key in value.keys()
            if not is_sensitive_key(str(key)) and not is_raw_body_key(str(key))
        )
        hidden_count = len(value) - len(safe_keys)
        return {
            "kind": "object",
            "field_count": len(value),
            "safe_fields": safe_keys[:32],
            "hidden_field_count": hidden_count,
        }
    if isinstance(value, list):
        return {"kind": "array", "item_count": len(value)}
    if value is None:
        return {"kind": "null"}
    if isinstance(value, bool):
        return {"kind": "boolean"}
    if isinstance(value, (int, float)):
        return {"kind": "number"}
    return {"kind": "string", "character_count": len(str(value))}


def summarize_payload(payload: bytes, content_type: str = "") -> Dict[str, Any]:
    """Summarize a payload without returning any original content."""
    summary: Dict[str, Any] = {
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "content_kind": "json" if "json" in content_type.lower() else "opaque",
    }
    if "json" in content_type.lower() and payload:
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            summary["json_valid"] = False
        else:
            summary["json_valid"] = True
            summary["payload_shape"] = _json_shape(parsed)
    return summary


def find_violations(data: bytes, canaries: Sequence[str] = DEFAULT_CANARIES) -> List[str]:
    """Return violation labels without echoing any matching secret."""
    text = data.decode("utf-8", errors="replace")
    violations: List[str] = []
    for index, pattern in enumerate(_SECRET_VALUE_PATTERNS, start=1):
        if pattern.search(text):
            violations.append("secret-value-pattern-%d" % index)
    if _JSON_SECRET_FIELD.search(text):
        violations.append("secret-json-field")
    if _JSON_RAW_BODY_FIELD.search(text):
        violations.append("raw-body-field")
    for index, canary in enumerate(canaries, start=1):
        if canary and canary in text:
            violations.append("canary-%d" % index)
    return sorted(set(violations))


def assert_safe_bytes(data: bytes, label: str, canaries: Sequence[str] = DEFAULT_CANARIES) -> None:
    violations = find_violations(data, canaries)
    if violations:
        raise ValueError("unsafe report data in %s: %s" % (label, ", ".join(violations)))


def assert_report_files_safe(paths: Iterable[Path], canaries: Sequence[str] = DEFAULT_CANARIES) -> None:
    for path in paths:
        assert_safe_bytes(path.read_bytes(), str(path), canaries)
