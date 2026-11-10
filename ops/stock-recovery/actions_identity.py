#!/usr/bin/env python3
"""Write the Actions evidence identity for source and bootstrap jobs.

Standard-library-only, offline, no execution. This binds one exact PR head,
run and job to its retained ``actions-identity.json`` evidence file while
retaining **qualification=HOLD**, **service_recovery=NOT_TESTED** and
**journal_matrix=NOT_RUN**. It only records which Actions run produced the
evidence: the file is identity evidence, never service, journal, watchdog,
quiescence, restart, or recovery proof.

The two jobs use different key spellings (lowercase for the source packet,
uppercase for the bootstrap job); both are preserved exactly.
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys


OUTPUT_NAME = "actions-identity.json"

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_NUMERIC = re.compile(r"[0-9]+\Z")
_JOB_STATUSES = frozenset(("success", "failure", "cancelled"))
_SOURCE_KEYS = ("head_sha", "run_id", "run_attempt", "job")
_BOOTSTRAP_KEYS = ("HEAD_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "JOB_STATUS")


class ActionsIdentityError(ValueError):
    """The Actions identity cannot be established."""


def _checked_env(env, name, pattern=None):
    """Return one bounded environment value, failing closed on bad input."""
    value = env.get(name)
    if not isinstance(value, str) or not value:
        raise ActionsIdentityError("missing actions environment value: " + name)
    if value != value.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ActionsIdentityError("malformed actions environment value: " + name)
    if len(value) > 256:
        raise ActionsIdentityError("oversized actions environment value: " + name)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ActionsIdentityError("malformed actions environment value: " + name)
    return value


def build_identity(mode, env):
    if mode not in ("source", "bootstrap"):
        raise ActionsIdentityError("unknown actions identity mode")
    if not hasattr(env, "get"):
        raise ActionsIdentityError("actions environment must be a mapping")
    head_sha = _checked_env(env, "HEAD_SHA", _SHA)
    run_id = _checked_env(env, "GITHUB_RUN_ID", _NUMERIC)
    run_attempt = _checked_env(env, "GITHUB_RUN_ATTEMPT", _NUMERIC)
    job = _checked_env(env, "GITHUB_JOB")
    if mode == "source":
        result = dict(zip(_SOURCE_KEYS, (head_sha, run_id, run_attempt, job)))
        result.update(qualification="HOLD", service_recovery="NOT_TESTED")
        return result
    job_status = _checked_env(env, "JOB_STATUS")
    if job_status not in _JOB_STATUSES:
        raise ActionsIdentityError("unknown job status")
    result = dict(zip(_BOOTSTRAP_KEYS, (head_sha, run_id, run_attempt, job, job_status)))
    result.update(qualification="HOLD", service_recovery="NOT_TESTED", journal_matrix="NOT_RUN")
    return result


def write_identity(output, identity):
    output = Path(output)
    if output.name != OUTPUT_NAME:
        raise ActionsIdentityError("identity output must be named " + OUTPUT_NAME)
    if output.is_symlink():
        raise ActionsIdentityError("identity output is a symlink")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ActionsIdentityError("identity output directory is a symlink")
    output.write_text(json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "bootstrap"), required=True)
    parser.add_argument("--output", required=True, help="identity output file")
    args = parser.parse_args(argv)
    try:
        identity = build_identity(args.mode, os.environ)
        write_identity(args.output, identity)
    except (ActionsIdentityError, OSError) as exc:
        # Do not print untrusted environment values into CI logs.
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
