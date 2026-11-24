"""Serialize an operator hold with launches from participating terminal wrappers."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from uuid import uuid4


@contextmanager
def state_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError("invalid state directory")
        yield directory
    finally:
        os.close(directory)


@contextmanager
def locked(directory):
    fd = os.open("lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, "rb") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise OSError("invalid lock file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def held(directory):
    try:
        os.stat("held", dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def reserve(directory, name):
    os.close(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=directory))


def launch(directory, command):
    with locked(directory):
        if held(directory):
            print("terminal launcher is held", file=sys.stderr)
            return os.EX_TEMPFAIL
        # Reserve before spawning. Losing the supervisor leaves an unresolved record.
        record = f"run-{uuid4().hex}"
        reserve(directory, record)
        # Terminal Ctrl-C reaches the child in this foreground group. Handle
        # it in the supervisor through spawn, wait and record retirement.
        # Exec resets caught signal handlers to the default in the child.
        signal.signal(signal.SIGINT, lambda *_: None)
        try:
            child = subprocess.Popen(command)
        except OSError:
            os.unlink(record, dir_fd=directory)
            raise

    result = child.wait()
    if result < 0:
        return 128 - result
    with locked(directory):
        os.unlink(record, dir_fd=directory)
    return result


def main(args):
    if (len(args) < 2 or not os.path.isabs(args[0])
            or not ((args[1] == "run" and len(args) > 2)
                    or (args[1] in {"hold", "undo", "status"} and len(args) == 2))):
        print("usage: launch_hold.py ABSOLUTE_STATE_DIR {hold|undo|status|run COMMAND ...}", file=sys.stderr)
        return os.EX_USAGE
    path, action, *command = args
    with state_directory(Path(path)) as directory:
        if action == "run":
            return launch(directory, command)
        with locked(directory):
            if action == "hold":
                if not held(directory):
                    reserve(directory, "held")
            elif action == "undo":
                if held(directory):
                    os.unlink("held", dir_fd=directory)
            else:
                phase = "held" if held(directory) else "open"
                count = sum(name.startswith("run-") for name in os.listdir(directory))
                print(f"{phase} {count} (unmanaged callers unverified)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except OSError:
        sys.exit("terminal launcher state or child launch failed")
