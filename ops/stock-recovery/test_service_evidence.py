"""Synthetic parser controls only; these do not exercise the stock runtime."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("service_evidence", ROOT / "service_evidence.py")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
MODEL = "synthetic-recovery-model"
NONCE = "0123456789abcdef0123456789abcdef"


def encoded(value):
    return json.dumps(value).encode("utf-8")


def response(identifier="message-final"):
    return {"type": "message", "id": identifier, "role": "assistant", "model": MODEL,
            "content": [{"type": "text", "text": "OK:" + NONCE}], "stop_reason": "end_turn"}


def events():
    initial = response("message-stream")
    initial.update(content=[], stop_reason=None)
    return [
        {"type": "message_start", "message": initial},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "OK:"}},
        {"type": "ping"},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": NONCE}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
        {"type": "message_stop"},
    ]


def stream(items):
    return b"".join(b"event: " + item["type"].encode() + b"\ndata: " + encoded(item) + b"\n\n" for item in items)


def tool():
    value = response("message-tool")
    value.update(stop_reason="tool_use", content=[
        {"type": "tool_use", "id": "call-synthetic", "name": "recovery_echo", "input": {"nonce": NONCE}},
    ])
    return value


class ServiceEvidenceTests(unittest.TestCase):
    def test_nonstream_requires_expected_content_and_terminal_reason(self):
        self.assertEqual(evidence.text_result(200, encoded(response()), MODEL, NONCE)["id"], "message-final")
        for stop in (None, "max_tokens", "tool_use", "error"):
            value = response()
            value["stop_reason"] = stop
            with self.subTest(stop=stop), self.assertRaises(evidence.EvidenceError):
                evidence.text_result(200, encoded(value), MODEL, NONCE)

    def test_http_success_model_list_or_empty_answer_is_not_service(self):
        for value in ({"data": [{"id": MODEL}]}, {}, [], None, response() | {"content": []},
                      response() | {"content": [{"type": "text", "text": ""}]}):
            with self.subTest(value=value), self.assertRaises(evidence.EvidenceError):
                evidence.text_result(200, encoded(value), MODEL, NONCE)
        with self.assertRaises(evidence.EvidenceError):
            evidence.text_result(503, encoded(response()), MODEL, NONCE)

    def test_foreign_model_nonce_role_and_error_are_rejected(self):
        changes = ({"model": "foreign"}, {"role": "user"}, {"id": ""}, {"error": "do-not-log"},
                   {"content": [{"type": "text", "text": "OK:" + "f" * 32}]})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(evidence.EvidenceError):
                evidence.text_result(200, encoded(response() | change), MODEL, NONCE)

    def test_complete_stream_requires_content_and_ordered_terminal_events(self):
        value = evidence.stream_result(200, stream(events()), MODEL, NONCE)
        self.assertEqual(value["content"], response()["content"])
        self.assertEqual(value["stop_reason"], "end_turn")
        evidence.stream_result(200, stream(events()).replace(b"\n", b"\r\n"), MODEL, NONCE)

    def test_each_truncated_stream_prefix_is_rejected(self):
        items = events()
        for count in range(len(items)):
            with self.subTest(count=count), self.assertRaises(evidence.EvidenceError):
                evidence.stream_result(200, stream(items[:count]), MODEL, NONCE)
        with self.assertRaises(evidence.EvidenceError):
            evidence.stream_result(200, stream(items).rstrip(b"\n"), MODEL, NONCE)

    def test_embedded_stop_substring_does_not_complete_a_stream(self):
        items = events()[:3]
        items[2]["delta"]["text"] = "message_stop OK:" + NONCE
        with self.assertRaises(evidence.EvidenceError):
            evidence.stream_result(200, stream(items), MODEL, NONCE)

    def test_stream_error_duplicate_late_and_reordered_events_are_rejected(self):
        items = events()
        cases = [items + [items[-1]], [items[0]] + items, items[:-1] + [{"type": "error"}],
                 items[:5] + items[6:], items[:6] + [items[-1]], [items[1], items[0]] + items[2:],
                 items + [items[2]], items[:-1] + [items[-2], items[-1]]]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(evidence.EvidenceError):
                evidence.stream_result(200, stream(changed), MODEL, NONCE)

    def test_wrong_stream_block_index_type_and_event_name_are_rejected(self):
        for index in (1, -1, True, "0", None):
            items = events()
            items[2]["index"] = index
            with self.subTest(index=index), self.assertRaises(evidence.EvidenceError):
                evidence.stream_result(200, stream(items), MODEL, NONCE)
        wire = stream(events()).replace(b"event: message_stop", b"event: ping")
        with self.assertRaises(evidence.EvidenceError):
            evidence.stream_result(200, wire, MODEL, NONCE)

    def test_tool_result_is_correlated_and_requires_a_new_final_answer(self):
        turn = evidence.tool_continuation(200, encoded(tool()), 200, encoded(response()), MODEL, NONCE)
        self.assertEqual(turn["content"][0]["tool_use_id"], "call-synthetic")
        self.assertEqual(turn["content"][0]["content"], "OK:" + NONCE)
        for final in (tool(), response("message-tool"), response() | {"stop_reason": "max_tokens"}):
            with self.subTest(final=final), self.assertRaises(evidence.EvidenceError):
                evidence.tool_continuation(200, encoded(tool()), 200, encoded(final), MODEL, NONCE)

    def test_missing_wrong_or_repeated_tool_call_fails(self):
        for patch in ({"id": ""}, {"name": "foreign"}, {"input": {"nonce": "f" * 32}},
                      {"type": "text"}, {"input": {"nonce": NONCE, "extra": True}}):
            value = tool()
            value["content"][0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(evidence.EvidenceError):
                evidence.tool_result_turn(200, encoded(value), MODEL, NONCE)
        value = tool()
        value["content"].append(copy.deepcopy(value["content"][0]))
        with self.assertRaises(evidence.EvidenceError):
            evidence.tool_result_turn(200, encoded(value), MODEL, NONCE)

    def test_invalid_encoding_size_nonce_and_content_do_not_leak(self):
        for raw in (b"", b"not-json-do-not-log", b"\xff", b"x" * (evidence.MAX_BYTES + 1), b"null"):
            with self.subTest(size=len(raw)), self.assertRaises(evidence.EvidenceError) as caught:
                evidence.text_result(200, raw, MODEL, NONCE)
            self.assertNotIn("do-not-log", str(caught.exception))
        for nonce in ("", "abc", "f" * 33, "F" * 32, None):
            with self.subTest(nonce=nonce), self.assertRaises(evidence.EvidenceError):
                evidence.text_result(200, encoded(response()), MODEL, nonce)


if __name__ == "__main__":
    unittest.main()
