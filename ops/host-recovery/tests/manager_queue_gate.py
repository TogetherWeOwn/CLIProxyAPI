"""Inert Actions oneshot gate; a real socket release, never a timed sleep."""
import json
import os
import socket
import sys


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0:
        raise SystemExit("explicit disposable root fixture required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(25.)
        peer.connect(sys.argv[1])
        peer.sendall(json.dumps({"gate": os.getpid()}).encode("ascii"))
        raw, _, flags, _ = peer.recvmsg(32)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or raw != b"release":
            raise SystemExit("explicit complete gate release required")


if __name__ == "__main__":
    main()
