"""Isolated, bounded-output synthetic loopback Messages HTTP helper.

Run only from trusted package code with Python -I. The parent meters and kills
this local helper; no established upstream socket timeout is set. It never reads
credentials/config/environment, follows redirects, retries or logs HTTP data.
"""
import base64
import http.client
import json
import re
import sys

MAX_BODY = 1024 * 1024
MAX_WIRE = 2 * MAX_BODY
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
PREFIX = "X-CPA-Recovery-"
FIELDS = {PREFIX + name for name in ("Attempt-ID", "Probe-ID", "Request-ID", "Parent-Request-ID", "Turn")}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def main():
    conn = None
    try:
        raw = sys.stdin.buffer.read(MAX_WIRE + 1)
        if not 0 < len(raw) <= MAX_WIRE:
            return 1
        value = json.loads(raw, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {"port", "ipv6", "token", "headers", "body_b64"}
                or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
                or type(value["ipv6"]) is not bool or type(value["headers"]) is not dict
                or set(value["headers"]) != FIELDS or type(value["body_b64"]) is not str):
            return 1
        headers = value["headers"]
        if (any(type(headers[PREFIX + name]) is not str or ID.fullmatch(headers[PREFIX + name]) is None
                for name in ("Attempt-ID", "Probe-ID", "Request-ID"))
                or headers[PREFIX + "Turn"] not in ("1", "2")):
            return 1
        parent = headers[PREFIX + "Parent-Request-ID"]
        if (headers[PREFIX + "Turn"] == "1" and parent != ""
                or headers[PREFIX + "Turn"] == "2" and (type(parent) is not str or ID.fullmatch(parent) is None
                                                         or parent == headers[PREFIX + "Request-ID"])):
            return 1
        token = value["token"]
        if token is not None:
            if (type(token) is not str or not 1 <= len(token) <= 8192
                    or any(not 33 <= ord(c) <= 126 for c in token)):
                return 1
            headers["Authorization"] = "Bearer " + token
        headers.update({"Content-Type": "application/json", "Accept": "application/json",
                        "Accept-Encoding": "identity", "anthropic-version": "2023-06-01"})
        body = base64.b64decode(value["body_b64"], validate=True)
        if not 0 < len(body) <= MAX_BODY:
            return 1
        conn = http.client.HTTPConnection("::1" if value["ipv6"] else "127.0.0.1", value["port"])
        conn.request("POST", "/v1/messages", body=body, headers=headers)
        reply = conn.getresponse()
        content_types = reply.headers.get_all("Content-Type", [])
        lengths = reply.headers.get_all("Content-Length", [])
        transfers = reply.headers.get_all("Transfer-Encoding", [])
        encodings = reply.headers.get_all("Content-Encoding", [])
        if (len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
                or len(encodings) > 1 or encodings and encodings[0].lower() != "identity"
                or len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
                or transfers and transfers[0].lower() != "chunked"
                or lengths and (not lengths[0].isascii() or not lengths[0].isdigit()
                                or not 0 < int(lengths[0]) <= MAX_BODY)):
            return 1
        response = reply.read(MAX_BODY + 1)
        if (not 0 < len(response) <= MAX_BODY
                or lengths and len(response) != int(lengths[0])):
            return 1
        result = {"status": reply.status, "body_b64": base64.b64encode(response).decode("ascii")}
        sys.stdout.buffer.write((json.dumps(result, separators=(",", ":")) + "\n").encode("ascii"))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
