## Audit hook for Claude Code (v0.2, prototype)

`asp_audit.py` records every tool call Claude Code is about to make in an
append-only log where each entry contains the hash of the previous one.
If an entry is edited or removed from the middle, `verify` reports it.

Unlike the snapshot CLI, this logs what the agent **actually asked to do**
(tool name and a hash of the parameters), taken from the hook event, not from
a JSON file the agent writes itself.

### Threat model

- **In scope:** an AI agent that takes a harmful action, by mistake (drift, wrong context) or because of prompt injection.
- **v0.2 goal (this hook):** every tool call made through Claude Code is recorded in a hash-chained log, so edits and gaps in the record are detectable after an incident. It never blocks anything.
- **v0.3 goal (not built yet):** a gate outside the agent's control blocks actions that violate policy before they run.
- **Known weakness:** the agent runs as the same user as the hook. If it has shell or file-write tools, it can edit the log and the hook configuration, and read `ASP_SECRET` from its environment. The log is only as trustworthy as where its head hash (and ideally the log itself) is kept: copy it somewhere the agent cannot write, such as another machine or an append-only location.
- **Out of scope:** an attacker who controls the machine, the hook or the keys; tool calls that do not go through Claude Code; what happened after a call (only the request is logged).

### Setup

Add to `.claude/settings.json` (project) or `~/.claude/settings.json` (global):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "python3 /absolute/path/to/asp_audit.py hook" }
        ]
      }
    ]
  }
}
```

Optional, set in the environment that runs Claude Code and the verifier:

- `ASP_SECRET`: adds an HMAC to each entry, so a rewritten chain is detected
  without the key. Keep it out of the repository.
- `ASP_AUDIT_LOG`: log path (default `.asp/audit.jsonl`; add `.asp/` to `.gitignore`).
- `ASP_AUDIT_FULL=1`: also store the full tool parameters. Off by default,
  because commands and file contents can contain secrets.

### Verify

```bash
python3 asp_audit.py verify
python3 asp_audit.py verify --expect-head <hash printed earlier>
```

Exit codes: `0` chain intact, `1` broken, `2` error (log missing/unreadable).

### Limitations

- The hook exits `1` (a visible, non-blocking error) if it cannot log; it never
  exits `2`, which would block the tool call. A failed write means a gap in the
  log that the chain cannot reveal, so watch for "NOT LOGGED" messages.
- Without the head hash stored somewhere else, removing the last entries is not detected.
- Each call reads the whole log: fine for sessions, not for millions of entries.
- File locking uses `fcntl`, so parallel tool calls are safe on Linux/macOS only.
  On Windows, parallel hooks could interleave.
- The HMAC key is symmetric: whoever can verify can also forge.
- Logs `PreToolUse` events only: what was requested, not whether it ran or what happened.
