"""Restore either of two approved versions of a gateway ingress file."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile

from production import ReleaseError

LIMIT = 1024 * 1024


def read(path):
    if not path.is_absolute() or path.resolve() != path:
        raise ReleaseError("ingress file path is not canonical")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT or os.listxattr(file.fileno()):
            raise ReleaseError("invalid ingress file")
        contents = file.read(LIMIT + 1)
        if len(contents) > LIMIT:
            raise ReleaseError("ingress file exceeds size limit")
    return contents, (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


@dataclass(frozen=True)
class IngressFile:
    live: Path
    original: Path
    adopted: Path
    original_sha256: str
    adopted_sha256: str
    metadata: tuple[int, int, int]

    def versions(self):
        original, _ = read(self.original)
        adopted, _ = read(self.adopted)
        if (len({self.original, self.adopted, self.live}) != 3
                or self.original_sha256 == self.adopted_sha256
                or hashlib.sha256(original).hexdigest() != self.original_sha256
                or hashlib.sha256(adopted).hexdigest() != self.adopted_sha256):
            raise ReleaseError("ingress backups do not match the binding")
        return original, adopted

    def verify(self, *, adopted):
        versions = self.versions()
        if read(self.live) != (versions[adopted], self.metadata):
            raise ReleaseError("ingress file does not match the expected layout")

    def apply(self, *, adopted):
        """Run while the site holds the writer and ingress fences."""
        versions = self.versions()
        current, metadata = read(self.live)
        if metadata != self.metadata or current not in versions:
            raise ReleaseError("ingress drift prevents restoration")
        expected = versions[adopted]
        if current == expected:
            return
        with tempfile.NamedTemporaryFile(dir=self.live.parent, delete=False) as file:
            pending = Path(file.name)
            try:
                uid, gid, mode = self.metadata
                os.fchown(file.fileno(), uid, gid)
                os.fchmod(file.fileno(), mode)
                file.write(expected)
                file.flush()
                os.fsync(file.fileno())
                if read(self.live) != (current, metadata):
                    raise ReleaseError("ingress changed during restoration")
                os.replace(pending, self.live)
                directory = os.open(self.live.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                pending.unlink(missing_ok=True)
