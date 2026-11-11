"""Strict response checks adapted from the retained probe; no network or authority.

These checks consume synthetic /v1/messages observations. A caller must separately
bind the observations to its attempt, runtime and request. Passing these checks
alone cannot qualify recovery, journal safety, ownership or host execution.
"""

import json
import re


MAX_BYTES = 1024 * 1024
MAX_BLOCKS = 64
NONCE = re.compile(r"[0-9a-f]{32}\Z")


class EvidenceError(ValueError):
    """Incomplete, unrelated or semantically inadequate service evidence."""


def require(condition):
    if not condition:
        # Never include response bodies, tokens or credentials in the error.
        raise EvidenceError("invalid or incomplete service evidence")


def decode(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES)
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise EvidenceError("invalid response encoding") from None


def message(status, raw, model):
    require(status == 200 and isinstance(model, str) and bool(model))
    value = decode(raw)
    require(isinstance(value, dict))
    require(value.get("type") == "message" and value.get("role") == "assistant")
    require(isinstance(value.get("id"), str) and bool(value["id"]))
    require(value.get("model") == model and "error" not in value)
    blocks = value.get("content")
    require(isinstance(blocks, list) and 0 < len(blocks) <= MAX_BLOCKS)
    require(all(isinstance(block, dict) for block in blocks))
    return value


def text_result(status, raw, model, nonce):
    require(isinstance(nonce, str) and NONCE.fullmatch(nonce) is not None)
    value = message(status, raw, model)
    require(value.get("stop_reason") == "end_turn")
    require(all(block.get("type") == "text" and isinstance(block.get("text"), str)
                for block in value["content"]))
    # The synthetic provider returns this exact request-specific answer.
    require("".join(block["text"] for block in value["content"]) == "OK:" + nonce)
    return value


def tool_result_turn(status, raw, model, nonce):
    require(isinstance(nonce, str) and NONCE.fullmatch(nonce) is not None)
    value = message(status, raw, model)
    require(value.get("stop_reason") == "tool_use" and len(value["content"]) == 1)
    call = value["content"][0]
    require(call.get("type") == "tool_use" and call.get("name") == "recovery_echo")
    require(isinstance(call.get("id"), str) and bool(call["id"]))
    require(call.get("input") == {"nonce": nonce})
    # A caller sends this correlated result, then verifies the final answer.
    return {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": call["id"],
                     "content": "OK:" + nonce}],
    }


def tool_continuation(first_status, first_raw, second_status, second_raw, model, nonce):
    turn = tool_result_turn(first_status, first_raw, model, nonce)
    final = text_result(second_status, second_raw, model, nonce)
    first = message(first_status, first_raw, model)
    require(first["id"] != final["id"])
    return turn


def stream_result(status, raw, model, nonce):
    """Require ordered SSE message/block/stop events, not an EOF or substring."""
    require(status == 200 and isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES)
    require(isinstance(nonce, str) and NONCE.fullmatch(nonce) is not None)
    try:
        wire = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError:
        raise EvidenceError("invalid stream encoding") from None
    require(wire.endswith("\n\n"))
    started = terminal = stopped = False
    active = None
    blocks = []
    result = None
    for frame in wire.split("\n\n")[:-1]:
        if not frame or all(line.startswith(":") for line in frame.split("\n")):
            continue
        require(not stopped)
        kind = None
        data = []
        for line in frame.split("\n"):
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                require(kind is None)
                kind = line[6:].lstrip(" ")
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
            else:
                raise EvidenceError("unexpected stream field")
        event = decode("\n".join(data).encode("utf-8"))
        require(isinstance(event, dict) and event.get("type") == kind)
        if kind == "ping":
            continue
        if kind == "message_start":
            require(not started and result is None)
            result = event.get("message")
            require(isinstance(result, dict) and result.get("content") == [])
            require(result.get("stop_reason") is None and "error" not in result)
            result = dict(result)
            started = True
        elif kind == "content_block_start":
            require(started and not terminal and active is None and len(blocks) < MAX_BLOCKS)
            require(type(event.get("index")) is int and event["index"] == len(blocks))
            block = event.get("content_block")
            require(isinstance(block, dict) and block.get("type") == "text" and block.get("text") == "")
            blocks.append({"type": "text", "text": ""})
            active = event["index"]
        elif kind == "content_block_delta":
            require(active is not None and type(event.get("index")) is int and event["index"] == active)
            delta = event.get("delta")
            require(isinstance(delta, dict) and delta.get("type") == "text_delta")
            require(isinstance(delta.get("text"), str))
            blocks[active]["text"] += delta["text"]
        elif kind == "content_block_stop":
            require(active is not None and type(event.get("index")) is int and event["index"] == active)
            active = None
        elif kind == "message_delta":
            require(started and not terminal and active is None and bool(blocks))
            delta = event.get("delta")
            require(isinstance(delta, dict) and delta.get("stop_reason") == "end_turn")
            result["stop_reason"] = "end_turn"
            terminal = True
        elif kind == "message_stop":
            require(started and terminal and active is None)
            stopped = True
        else:
            raise EvidenceError("unexpected stream event")
    require(stopped and result is not None)
    result["content"] = blocks
    return text_result(status, json.dumps(result).encode("utf-8"), model, nonce)
