#!/usr/bin/env python3
"""Fixture-driven local Codex Responses and synthetic OAuth refresh mock."""

import argparse
import hashlib
import json
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from harness.redaction import assert_safe_bytes, sanitize, summarize_payload

MAX_REQUEST_BYTES = 2 * 1024 * 1024
REQUEST_HASH_PLACEHOLDER = "{{request_sha12}}"


def materialize_fixture(fixture: Mapping[str, Any], body: bytes) -> Dict[str, Any]:
    """Return a request-scoped fixture only when placeholder expansion is enabled."""
    if fixture.get("request_hash_placeholders") is not True:
        return dict(fixture)

    suffix = hashlib.sha256(body).hexdigest()[:12]

    def replace(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): replace(item)
                for key, item in value.items()
                if key != "request_hash_placeholders"
            }
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, str):
            return value.replace(REQUEST_HASH_PLACEHOLDER, suffix)
        return value

    materialized = replace(dict(fixture))
    if not isinstance(materialized, dict):
        raise ValueError("materialized fixture must remain an object")
    return materialized


def contains_object_type(value: Any, expected: str) -> bool:
    if isinstance(value, dict):
        if value.get("type") == expected:
            return True
        return any(contains_object_type(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(contains_object_type(item, expected) for item in value)
    return False


def object_field_values(value: Any, object_type: str, field: str) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        if value.get("type") == object_type and isinstance(value.get(field), str):
            values.append(str(value[field]))
        for item in value.values():
            values.extend(object_field_values(item, object_type, field))
    elif isinstance(value, list):
        for item in value:
            values.extend(object_field_values(item, object_type, field))
    return values


class EvidenceSink:
    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.path.touch(mode=0o600, exist_ok=True)
            os.chmod(str(self.path), 0o600)

    def append(self, event: Mapping[str, Any]) -> None:
        if self.path is None:
            return
        safe_event = sanitize(dict(event))
        line = json.dumps(safe_event, sort_keys=True, ensure_ascii=False) + "\n"
        assert_safe_bytes(line.encode("utf-8"), "mock evidence")
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)


class FixtureRegistry:
    def __init__(self, directory: Path) -> None:
        self.fixtures: Dict[str, Dict[str, Any]] = {}
        self.sequence_counts: Dict[tuple[str, str], int] = {}
        self.sequence_lock = threading.Lock()
        for path in sorted(directory.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            name = str(data.get("name") or path.stem)
            self.fixtures[name] = data
        if not self.fixtures:
            raise ValueError("no scenario fixtures found in %s" % directory)

    def get(self, name: str, sequence_key: str = "") -> Dict[str, Any]:
        try:
            fixture = self.fixtures[name]
        except KeyError:
            raise KeyError("unknown fixture scenario: %s" % name)
        sequence = fixture.get("sequence")
        if not isinstance(sequence, list):
            return fixture
        if not sequence or not all(isinstance(item, str) and item for item in sequence):
            raise KeyError("invalid fixture sequence: %s" % name)
        counter_key = (name, sequence_key)
        with self.sequence_lock:
            index = self.sequence_counts.get(counter_key, 0)
            self.sequence_counts[counter_key] = index + 1
        step = sequence[min(index, len(sequence) - 1)]
        try:
            return self.fixtures[step]
        except KeyError:
            raise KeyError("unknown fixture sequence step: %s" % step)


class MockCodexServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Any, fixtures: FixtureRegistry, evidence: EvidenceSink) -> None:
        super().__init__(address, MockCodexHandler)
        self.fixtures = fixtures
        self.evidence = evidence


class MockCodexHandler(BaseHTTPRequestHandler):
    server: MockCodexServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_REQUEST_BYTES:
            self.send_error(413)
            return b""
        return self.rfile.read(length) if length else b""

    def _record(self, body: bytes, scenario: str) -> None:
        content_type = self.headers.get("Content-Type", "")
        event: Dict[str, Any] = {
            "kind": "mock_request",
            "method": self.command,
            "path": self.path.split("?", 1)[0],
            "scenario": scenario,
            "header_count": len(self.headers),
            "credential_header_present": bool(
                self.headers.get("Authorization") or self.headers.get("X-Api-Key")
            ),
            "stainless_retry_header_present": self.headers.get("X-Stainless-Retry-Count") is not None,
        }
        event.update(summarize_payload(body, content_type))
        if body and "json" in content_type.lower():
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            else:
                if isinstance(parsed, dict):
                    tools = parsed.get("tools")
                    tool_items = tools if isinstance(tools, list) else []
                    input_value = parsed.get("input")
                    input_items = input_value if isinstance(input_value, list) else []
                    input_texts = object_field_values(input_items, "input_text", "text")
                    instructions = parsed.get("instructions")
                    event["protocol_fields"] = {
                        "model": parsed.get("model") if isinstance(parsed.get("model"), str) else None,
                        "stream": parsed.get("stream") is True,
                        "max_output_tokens_present": "max_output_tokens" in parsed,
                        "stop_present": "stop" in parsed or "stop_sequences" in parsed,
                        "context_management_present": "context_management" in parsed,
                        "reasoning_effort": (
                            parsed.get("reasoning", {}).get("effort")
                            if isinstance(parsed.get("reasoning"), dict)
                            else None
                        ),
                        "tool_count": len(tool_items),
                        "tool_names": [
                            str(item.get("name"))
                            for item in tool_items
                            if isinstance(item, dict) and isinstance(item.get("name"), str)
                        ][:64],
                        "strict_true_count": sum(
                            item.get("strict") is True for item in tool_items if isinstance(item, dict)
                        ),
                        "input_item_count": len(input_items),
                        "input_item_types": [
                            str(item.get("type"))
                            for item in input_items
                            if isinstance(item, dict) and isinstance(item.get("type"), str)
                        ][:64],
                        "input_message_roles": [
                            str(item.get("role"))
                            for item in input_items
                            if isinstance(item, dict)
                            and item.get("type") == "message"
                            and isinstance(item.get("role"), str)
                        ][:64],
                        "function_call_ids": object_field_values(
                            input_items, "function_call", "call_id"
                        )[:64],
                        "function_output_call_ids": object_field_values(
                            input_items, "function_call_output", "call_id"
                        )[:64],
                        "input_text_bytes": [len(value.encode("utf-8")) for value in input_texts][
                            :64
                        ],
                        "input_text_sha256": [
                            hashlib.sha256(value.encode("utf-8")).hexdigest()
                            for value in input_texts
                        ][:64],
                        "instructions_sha256": (
                            hashlib.sha256(instructions.encode("utf-8")).hexdigest()
                            if isinstance(instructions, str)
                            else None
                        ),
                    }
        self.server.evidence.append(event)

    def _scenario_from_body(self, body: bytes, default: str) -> str:
        header_value = self.headers.get("X-Compat-Scenario")
        if header_value:
            return header_value
        if body and "json" in self.headers.get("Content-Type", "").lower():
            try:
                parsed = json.loads(body.decode("utf-8"))
                metadata = parsed.get("metadata", {}) if isinstance(parsed, dict) else {}
                value = metadata.get("compat_scenario") if isinstance(metadata, dict) else None
                if isinstance(value, str):
                    return value
                model = parsed.get("model") if isinstance(parsed, dict) else None
                if model == "claude_code_mcp" and contains_object_type(parsed, "function_call_output"):
                    return "claude_code_mcp_done"
                if model == "claude_code_agent" and contains_object_type(parsed, "function_call_output"):
                    return "claude_code_agent_done"
                if isinstance(parsed, dict) and parsed.get("stream") is True and model == "text":
                    return "text_stream"
                if isinstance(model, str) and model in self.server.fixtures.fixtures:
                    return model
                if isinstance(parsed, dict) and parsed.get("stream") is True and default == "text":
                    return "text_stream"
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        return default

    def _sequence_key_from_body(self, body: bytes) -> str:
        if not body or "json" not in self.headers.get("Content-Type", "").lower():
            return ""
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ""
        if not isinstance(parsed, dict):
            return ""
        value = parsed.get("prompt_cache_key")
        return value if isinstance(value, str) else ""

    def _send_json(self, status: int, payload: Mapping[str, Any], headers: Mapping[str, str]) -> None:
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(str(key), str(value))
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def _send_sse(self, fixture: Mapping[str, Any]) -> None:
        status = int(fixture.get("status", 200))
        self.send_response(status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        for key, value in fixture.get("headers", {}).items():
            self.send_header(str(key), str(value))
        self.end_headers()

        truncate_after = fixture.get("truncate_after_bytes")
        disconnect_after = fixture.get("disconnect_after_events")
        sent = 0
        for index, item in enumerate(fixture.get("sse_events", []), start=1):
            event_name = str(item.get("event", "message"))
            data_value = item.get("data", {})
            if isinstance(data_value, str):
                data_text = data_value
            else:
                data_text = json.dumps(data_value, separators=(",", ":"), ensure_ascii=False)
            frame = ("event: %s\ndata: %s\n\n" % (event_name, data_text)).encode("utf-8")
            if truncate_after is not None and sent + len(frame) > int(truncate_after):
                remaining = max(0, int(truncate_after) - sent)
                if remaining:
                    self.wfile.write(frame[:remaining])
                    self.wfile.flush()
                self.close_connection = True
                return
            self.wfile.write(frame)
            self.wfile.flush()
            sent += len(frame)
            per_event_delay = int(fixture.get("event_delay_ms", 0))
            if per_event_delay:
                time.sleep(per_event_delay / 1000.0)
            if disconnect_after is not None and index >= int(disconnect_after):
                self.close_connection = True
                return
        self.close_connection = True

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._record(b"", "health")
            self._send_json(200, {"ok": True}, {})
            return
        self._record(b"", "not_found")
        self._send_json(404, {"error": {"type": "not_found"}}, {})

    def do_POST(self) -> None:
        body = self._read_body()
        path = self.path.split("?", 1)[0]
        if path == "/oauth/token":
            scenario = "oauth_refresh"
        elif path == "/v1/responses":
            scenario = self._scenario_from_body(body, "text")
        else:
            scenario = "not_found"
        self._record(body, scenario)

        if scenario == "not_found":
            self._send_json(404, {"error": {"type": "not_found"}}, {})
            return
        try:
            fixture = self.server.fixtures.get(scenario, self._sequence_key_from_body(body))
        except KeyError:
            self._send_json(400, {"error": {"type": "unknown_scenario"}}, {})
            return
        fixture = materialize_fixture(fixture, body)

        delay_ms = int(fixture.get("delay_ms", 0))
        if delay_ms:
            time.sleep(delay_ms / 1000.0)
        if fixture.get("sse_events") is not None:
            self._send_sse(fixture)
            return
        self._send_json(
            int(fixture.get("status", 200)),
            fixture.get("json", {}),
            fixture.get("headers", {}),
        )


def serve(fixtures_dir: Path, host: str, port: int, evidence_path: Optional[Path], ready_path: Optional[Path]) -> None:
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("mock must bind to loopback")
    if port == 8317:
        raise ValueError("production port 8317 is forbidden")
    registry = FixtureRegistry(fixtures_dir)
    server = MockCodexServer((host, port), registry, EvidenceSink(evidence_path))
    actual_port = int(server.server_address[1])
    if actual_port == 8317:
        server.server_close()
        raise ValueError("production port 8317 is forbidden")
    if ready_path is not None:
        ready_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        ready_path.write_text(
            json.dumps({"host": "127.0.0.1", "port": actual_port}) + "\n",
            encoding="utf-8",
        )
        os.chmod(str(ready_path), 0o600)

    def stop_server(signum: int, frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=0, type=int)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()
    serve(args.fixtures, args.host, args.port, args.evidence, args.ready_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
