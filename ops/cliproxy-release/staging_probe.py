"""Synthetic Meta route smoke, run inside the gateway's loopback-only namespace."""

import http.server
import json
import socket
import threading
import time
import urllib.error
import urllib.request

MODEL = "muse-spark-1.3-contributor"
CLIENT_MODEL = "meta-muse/" + MODEL
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if (self.path != "/meta/responses" or payload.get("model") != MODEL
                or self.headers.get("Authorization") != "Bearer staging-meta"):
            self.send_error(400)
            return
        response = {"id": "resp_stage", "object": "response", "created_at": 1, "model": MODEL}
        events = [
            {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
            {"type": "response.output_text.delta", "item_id": "msg_stage", "output_index": 0,
             "content_index": 0, "delta": "stage-complete"},
            {"type": "response.completed", "response": {**response, "status": "completed",
             "output": [{"id": "msg_stage", "type": "message", "role": "assistant", "status": "completed",
                         "content": [{"type": "output_text", "text": "stage-complete"}]}],
             "usage": {"input_tokens": 2, "output_tokens": 2, "total_tokens": 4}}},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
            self.wfile.flush()


def request(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    target = urllib.request.Request("http://127.0.0.1:19237" + path, data, {
        "Authorization": "Bearer staging-client", "Content-Type": "application/json",
    })
    return OPENER.open(target, timeout=4)


def completed(events, expected_text="stage-complete"):
    if not events or events[-1] != b"[DONE]":
        return False
    text = []
    finished = False
    for event in events[:-1]:
        chunk = json.loads(event)
        if "error" in chunk:
            return False
        for choice in chunk["choices"]:
            if choice["index"] != 0:
                continue
            content = choice["delta"].get("content")
            reason = choice["finish_reason"]
            if finished and (content or reason is not None):
                return False
            if content:
                text.append(content)
            if reason is not None:
                if (reason != "stop" or not text
                        or (expected_text is not None and "".join(text) != expected_text)):
                    return False
                finished = True
    return finished


def check(request, model, expected_text=None):
    deadline = time.monotonic() + 12
    while True:
        try:
            with request("/healthz") as health, request("/v1/models") as catalogue:
                models = catalogue.read(256 * 1024 + 1)
                if (health.status == catalogue.status == 200 and len(models) <= 256 * 1024
                        and any(entry["id"] == model for entry in json.loads(models)["data"])):
                    break
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("gateway or Meta model unavailable")
        time.sleep(0.1)
    with request("/v1/chat/completions", {
        "model": model, "stream": True, "messages": [{"role": "user", "content": "fixture"}],
    }) as response:
        if response.status != 200 or response.headers.get_content_type() != "text/event-stream":
            raise RuntimeError("gateway did not start an SSE stream")
        body = response.read(256 * 1024 + 1)
        if len(body) > 256 * 1024:
            raise RuntimeError("unexpected stream size")
        events = [line.removeprefix(b"data:").strip() for line in body.splitlines() if line.startswith(b"data:")]
    if not completed(events, expected_text):
        raise RuntimeError("missing Meta content or stream terminal")


if __name__ == "__main__":
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("unexpected gateway network interface")
    with http.server.ThreadingHTTPServer(("127.0.0.1", 19238), Upstream) as mock:
        threading.Thread(target=mock.serve_forever, daemon=True).start()
        check(request, CLIENT_MODEL, "stage-complete")
