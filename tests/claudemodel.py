# SPDX-License-Identifier: Apache-2.0 AND MIT
"""A scripted Anthropic Messages server, so the real Claude Code can be run
under hlyn with no API key and no network.

Adapted from OpenAPPA's `marketplace/plugins/claude-code/claude_model_fixture.py`
(Copyright 2026 Archestra Inc., MIT License: "The above copyright notice and
this permission notice shall be included in all copies or substantial portions
of the Software."). Kept: the server, the streamed event format and picking a
tool by the name Claude Code declares. Changed: their two APPA conversations
are replaced by a plain script of tool calls, one per turn.

Point Claude Code at it with `ANTHROPIC_BASE_URL=model.url`. Each request is
answered with the next step of the script: step N is sent once N tool results
are in the conversation, and after the last step the model says "done". Every
request is recorded, so a test can read exactly what each tool call returned.
"""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

MAX_BODY = 4 * 1024 * 1024


def strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


class Model:
    """`steps` is a list of (tool, input) pairs, e.g. ("Bash", {"command": "ls"})."""

    def __init__(self, steps: list[tuple[str, dict[str, Any]]]) -> None:
        self.steps = list(steps)
        self._lock = threading.Lock()
        self._requests: list[dict[str, Any]] = []
        self._server = _server(self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> Model:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def record(self, request: dict[str, Any]) -> None:
        with self._lock:
            self._requests.append(deepcopy(request))

    def requests(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._requests)

    def results(self) -> list[tuple[bool, str]]:
        """What each tool call returned, in order: (is_error, text), taken
        from the longest conversation the model was sent."""
        longest = max(self.requests(), key=lambda r: len(tool_results(r)), default={})
        return [
            (bool(block.get("is_error")), "\n".join(strings(block.get("content"))))
            for block in tool_results(longest)
        ]


def tool_name(request: dict[str, Any], wanted: str) -> str:
    names = [tool.get("name") for tool in request.get("tools", []) if isinstance(tool, dict)]
    exact = [name for name in names if name == wanted]
    matches = exact or [
        name for name in names if isinstance(name, str) and name.endswith(f"__{wanted}")
    ]
    if len(matches) != 1:
        raise ValueError(f"tool {wanted!r} is missing or ambiguous in Claude Code declarations: {names}")
    return matches[0]


def tool_results(request: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        block
        for message in request.get("messages", [])
        if isinstance(message, dict)
        for block in message.get("content", [])
        if isinstance(message.get("content"), list)
        if isinstance(block, dict) and block.get("type") == "tool_result"
    ]


def next_content(model: Model, request: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    # A request with no tools is Claude Code's own side question (a title, a
    # summary), not the conversation: answer it in words.
    done = len(tool_results(request))
    if not request.get("tools") or done >= len(model.steps):
        return [{"type": "text", "text": "done"}], "end_turn"
    tool, arguments = model.steps[done]
    return [
        {
            "type": "tool_use",
            "id": f"toolu_hlyn_{done}",
            "name": tool_name(request, tool),
            "input": arguments,
        }
    ], "tool_use"


def message(model: Model, request: dict[str, Any]) -> dict[str, Any]:
    content, stop_reason = next_content(model, request)
    return {
        "id": "msg_hlyn_model",
        "type": "message",
        "role": "assistant",
        "model": request.get("model", "hlyn-model"),
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def event_stream(answer: dict[str, Any]) -> bytes:
    start = {**answer, "content": [], "stop_reason": None, "stop_sequence": None}
    events: list[tuple[str, dict[str, Any]]] = [
        ("message_start", {"type": "message_start", "message": start}),
    ]
    for index, block in enumerate(answer["content"]):
        if block["type"] == "text":
            initial = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": block["text"]}
        else:
            initial = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
        events.extend([
            ("content_block_start",
             {"type": "content_block_start", "index": index, "content_block": initial}),
            ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}),
            ("content_block_stop", {"type": "content_block_stop", "index": index}),
        ])
    events.extend([
        ("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": answer["stop_reason"], "stop_sequence": None},
            "usage": {"output_tokens": 1},
        }),
        ("message_stop", {"type": "message_stop"}),
    ])
    return "".join(
        f"event: {kind}\ndata: {json.dumps(payload)}\n\n" for kind, payload in events
    ).encode()


def _server(model: Model) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= MAX_BODY:
                    raise ValueError("request body exceeds the model's limit")
                request = json.loads(self.rfile.read(length))
                if urlsplit(self.path).path != "/v1/messages" or not isinstance(request, dict):
                    raise ValueError("expected an Anthropic /v1/messages request")
                model.record(request)
                answer = message(model, request)
                if request.get("stream"):
                    self.reply(200, event_stream(answer), "text/event-stream")
                else:
                    self.reply(200, json.dumps(answer).encode(), "application/json")
            except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as error:
                body = json.dumps(
                    {"type": "error", "error": {"type": "invalid_request_error", "message": str(error)}}
                ).encode()
                self.reply(400, body, "application/json")

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)
