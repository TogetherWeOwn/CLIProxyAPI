"""Inert, bounded Actions unit payload; no daemon, application or recovery work."""
import json
import os
import signal
import socket
import sys


def main():
    if len(sys.argv) != 2 or os.geteuid() != 0:
        raise SystemExit("explicit disposable root fixture required")
    # Both processes ignore TERM so the manager must exercise whole-unit KILL.
    # The pipe establishes child readiness before the parent reports either PID.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.write(write_fd, b"R")
        os.close(write_fd)
        while True:
            signal.pause()
    os.close(write_fd)
    if os.read(read_fd, 1) != b"R":
        raise SystemExit("child readiness failed")
    os.close(read_fd)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.connect(sys.argv[1])
        peer.sendall(json.dumps({"parent": os.getpid(), "child": child}).encode("ascii"))
    os.waitpid(child, 0)


if __name__ == "__main__":
    main()
