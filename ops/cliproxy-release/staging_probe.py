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


def check():
    deadline = time.monotonic() + 12
    while True:
        try:
            with request("/healthz") as health, request("/v1/models") as catalogue:
                if health.status == 200 and any(model["id"] == CLIENT_MODEL for model in json.load(catalogue)["data"]):
                    break
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("gateway or Meta model unavailable")
        time.sleep(0.1)
    with request("/v1/chat/completions", {
        "model": CLIENT_MODEL, "stream": True, "messages": [{"role": "user", "content": "fixture"}],
    }) as response:
        events = [line.strip() for line in response if line.startswith(b"data:")]
    if not events or events[-1] != b"data: [DONE]" or not any(b"stage-complete" in event for event in events[:-1]):
        raise RuntimeError("missing Meta content or stream terminal")


if __name__ == "__main__":
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("unexpected gateway network interface")
    with http.server.ThreadingHTTPServer(("127.0.0.1", 19238), Upstream) as mock:
        threading.Thread(target=mock.serve_forever, daemon=True).start()
        check()
