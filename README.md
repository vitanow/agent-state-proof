# Agent State Proof (MVP)

**Minimal HMAC-signed snapshot of an AI agent's declared state.**

Identity tells you *who* an agent is.  
This tool creates a signed snapshot of *what the agent claims its state is* at a given moment.

---

## What This Does

1. Accepts a JSON description of the agent's declared state
2. Normalizes it deterministically (together with a timestamp)
3. Signs the result with HMAC-SHA256 using a secret key (`ASP_SECRET`)
4. Saves a snapshot that can later detect if the state or timestamp changed

This is **tamper-evidence for a file**, not a cryptographic proof that the JSON reflects the real internal state of a running agent.

---

## Limitations

- **No agent integration.** You must manually export the state to JSON.
- **Trust is in the key.** Anyone with `ASP_SECRET` can create valid snapshots. Without the key, snapshots cannot be forged.
- **No freshness.** There is no expiry. An old snapshot remains valid forever.
- **Does not prove real agent state.** It only proves that the JSON file (and the timestamp it was signed with) has not changed.
- **Summary fields are declared, not verified.** Values like memory status come from the same JSON you provide and are not part of the signature.

---

## v0.2: audit hook for Claude Code

See [README_audit.md](README_audit.md) for the hash-chained audit log of real Claude Code tool calls, including the threat model.

---

## Quick Start

```bash
export ASP_SECRET="your-secret-key-here"

python asp.py prove examples/example_state.json
python asp.py verify proofs/asp_xxxx.json examples/example_state.json
```

---

## Commands

```bash
# Create a signed snapshot
python asp.py prove state.json

# Verify a snapshot against current state
python asp.py verify proofs/asp_xxxx.json state.json
```

Exit codes:
- `0` - match (state unchanged)
- `1` - mismatch (state or timestamp changed, or wrong key)
- `2` - error (missing file, bad JSON, missing secret, non-object JSON)

---

## State Format

See `examples/example_state.json`.

---

## Running Tests

```bash
python -m unittest test_asp.py test_asp_audit.py
```

---

## License

MIT
