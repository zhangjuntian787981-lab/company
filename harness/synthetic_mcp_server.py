#!/usr/bin/env python3
"""Minimal side-effect-free stdio MCP server for Claude Code compatibility tests."""

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


class EvidenceSink:
    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.path.touch(mode=0o600, exist_ok=True)
            os.chmod(str(self.path), 0o600)

    def append(self, method: str, tool_name: Optional[str] = None) -> None:
        if self.path is None:
            return
        event: Dict[str, Any] = {"kind": "mcp_request", "method": method}
        if tool_name is not None:
            event["tool_name"] = tool_name
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")


def send(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(dict(payload), separators=(",", ":")) + "\n")
    sys.stdout.flush()


def result(request_id: Any, value: Mapping[str, Any]) -> None:
    send({"jsonrpc": "2.0", "id": request_id, "result": dict(value)})


def handle(message: Mapping[str, Any], sink: EvidenceSink) -> None:
    method = str(message.get("method") or "")
    request_id = message.get("id")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    tool_name = str(params.get("name")) if method == "tools/call" and params.get("name") else None
    sink.append(method, tool_name)

    if request_id is None:
        return
    if method == "initialize":
        requested = params.get("protocolVersion")
        protocol_version = str(requested) if requested else "2025-06-18"
        result(
            request_id,
            {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "compat", "version": "1.0.0"},
            },
        )
    elif method == "tools/list":
        result(
            request_id,
            {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Return the supplied synthetic value without side effects.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                    },
                    {
                        "name": "add",
                        "description": "Add two synthetic integers without side effects.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "integer"},
                                "b": {"type": "integer"},
                            },
                            "required": ["a", "b"],
                            "additionalProperties": False,
                        },
                    },
                    {
                        "name": "metadata",
                        "description": "Return fixed non-secret compatibility metadata.",
                        "inputSchema": {"type": "object", "additionalProperties": False},
                    },
                ]
            },
        )
    elif method == "tools/call":
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if tool_name == "echo":
            text = "echo:" + str(arguments.get("value") or "")
        elif tool_name == "add":
            text = str(int(arguments.get("a", 0)) + int(arguments.get("b", 0)))
        elif tool_name == "metadata":
            text = "compat-metadata-v1"
        else:
            result(
                request_id,
                {
                    "content": [{"type": "text", "text": "unknown tool"}],
                    "isError": True,
                },
            )
            return
        result(request_id, {"content": [{"type": "text", "text": text}], "isError": False})
    elif method in ("resources/list", "prompts/list"):
        result(request_id, {"resources": []} if method == "resources/list" else {"prompts": []})
    elif method == "ping":
        result(request_id, {})
    else:
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )


def main() -> int:
    evidence_value = os.environ.get("COMPAT_MCP_EVIDENCE")
    sink = EvidenceSink(Path(evidence_value) if evidence_value else None)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            handle(message, sink)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
