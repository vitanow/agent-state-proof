#!/usr/bin/env python3
"""
asp_audit - append-only, hash-chained audit log of Claude Code tool calls.

  hook    read a Claude Code hook event on stdin, append one log entry
  verify  re-walk the log and check that the chain is intact

Tamper-evidence only. It never blocks a tool call (see README).
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl  # POSIX only
except ImportError:  # Windows: no file locking, see README
    fcntl = None

GENESIS = "0" * 64


def log_path() -> Path:
    return Path(os.environ.get("ASP_AUDIT_LOG", ".asp/audit.jsonl"))


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def secret():
    key = os.environ.get("ASP_SECRET")
    return key.encode("utf-8") if key else None


def mac(entry_hash: str, key: bytes) -> str:
    return hmac.new(key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def make_entry(prev_hash: str, seq: int, event: dict, key=None) -> dict:
    tool_input = event.get("tool_input")
    entry = {
        "seq": seq,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "session_id": event.get("session_id"),
        "tool_name": event.get("tool_name"),
        "tool_input_sha256": sha(canon(tool_input)),
        "prev_hash": prev_hash,
    }
    if os.environ.get("ASP_AUDIT_FULL") == "1":
        entry["tool_input"] = tool_input  # opt-in: may contain secrets
    entry["entry_hash"] = sha(canon(entry))
    if key:
        entry["mac"] = mac(entry["entry_hash"], key)
    return entry


def load_entries(path: Path) -> list:
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"line {n} is not valid JSON")
            if not isinstance(entry, dict):
                raise ValueError(f"line {n} is not a JSON object")
            entries.append(entry)
    return entries


def check_chain(entries: list, key=None, expect_head=None):
    """Return None if the chain is intact, otherwise a description of the break."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return f"entry {i}: unexpected seq {e.get('seq')!r}"
        if e.get("prev_hash") != prev:
            return f"entry {i}: prev_hash does not match the previous entry"
        body = {k: v for k, v in e.items() if k not in ("entry_hash", "mac")}
        try:
            h = sha(canon(body))
        except ValueError:
            return f"entry {i}: cannot be serialized"
        if not hmac.compare_digest(h, str(e.get("entry_hash", ""))):
            return f"entry {i}: content does not match entry_hash"
        if key:
            m = e.get("mac")
            if not isinstance(m, str) or not hmac.compare_digest(mac(h, key), m):
                return f"entry {i}: MAC missing or wrong key"
        prev = h
    if expect_head and not hmac.compare_digest(prev, expect_head):
        return "head hash differs from --expect-head (entries added, removed or changed)"
    return None


def cmd_hook(_args) -> int:
    # Never exit 2: that would block the tool call. Exit 1 is a visible,
    # non-blocking error in Claude Code.
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("stdin is not a JSON object")
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+", encoding="utf-8") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            seq, last = 0, None
            for line in f:
                if line.strip():
                    last, seq = line, seq + 1
            prev = json.loads(last)["entry_hash"] if last else GENESIS
            entry = make_entry(prev, seq, event, secret())
            f.write(canon(entry) + "\n")
            f.flush()
    except Exception as exc:  # noqa: BLE001 - logging must not crash the agent
        print(f"asp-audit: NOT LOGGED: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_verify(args) -> int:
    path = Path(args.log) if args.log else log_path()
    try:
        entries = load_entries(path)
    except OSError as exc:
        print(f"Error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"BROKEN: {exc}")
        return 1

    key = secret()
    problem = check_chain(entries, key, args.expect_head)
    if problem:
        print(f"BROKEN: {problem}")
        return 1

    head = entries[-1]["entry_hash"] if entries else GENESIS
    print(f"OK: {len(entries)} entries, chain intact")
    print(f"Head:  {head}")
    print("MACs:  checked" if key else "MACs:  not checked (ASP_SECRET not set)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash-chained audit log for Claude Code tool calls")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hook = sub.add_parser("hook", help="Claude Code hook: log the event read from stdin")
    p_hook.set_defaults(func=cmd_hook)

    p_verify = sub.add_parser("verify", help="Verify the log")
    p_verify.add_argument("--log", help="Path to the log (default: $ASP_AUDIT_LOG or .asp/audit.jsonl)")
    p_verify.add_argument("--expect-head", help="Head hash saved elsewhere; detects removed tail entries")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
