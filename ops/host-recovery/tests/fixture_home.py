"""Select synthetic fixture placement without changing production path guards."""
import os
import pwd


def fixture_home():
    path = os.environ.get("CPA_RECOVERY_TEST_ROOT", pwd.getpwuid(os.geteuid()).pw_dir)
    if not path or not os.path.isabs(path):
        raise ValueError("absolute component fixture root required")
    # Production acquisition still validates every ancestor, including xattrs.
    # Never chmod, clear metadata or fall back after an explicitly bad root.
    return path
