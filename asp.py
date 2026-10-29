#!/usr/bin/env python3
"""
Agent State Proof - Minimal MVP
Generates an HMAC-signed snapshot of an AI agent's declared state.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, dict):
        print(f"Error: expected JSON object in {path}, got {type(data).__name__}", file=sys.stderr)
        sys.exit(2)
    return data


def normalize(obj: dict) -> str:
    """Deterministic JSON serialization for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)


def get_secret() -> bytes:
    key = os.environ.get("ASP_SECRET")
    if not key:
        print("Error: ASP_SECRET environment variable is not set", file=sys.stderr)
        sys.exit(2)
    return key.encode("utf-8")


def sign(content: str) -> str:
    return hmac.new(get_secret(), content.encode("utf-8"), hashlib.sha256).hexdigest()


def summarize(state: dict) -> dict:
    tools = state.get("tools", [])
    if not isinstance(tools, list):
        tools = []
    allowed = 0
    for t in tools:
        if isinstance(t, dict) and t.get("allowed"):
            allowed += 1

    memory = state.get("memory", {})
    context = state.get("context", {})
    if not isinstance(memory, dict):
        memory = {}
    if not isinstance(context, dict):
        context = {}

    return {
        "agent_id": state.get("agent_id", "unknown"),
        "declared_memory_status": "current" if not memory.get("drift_detected") else "drift",
        "tools_allowed": allowed,
        "tools_total": len(tools),
        "context_messages": context.get("message_count", 0),
        "intended_action": state.get("intended_action", "none"),
    }


def cmd_prove(args):
    state = load_json(args.state_file)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = summarize(state)

    # Sign both the state and the timestamp so neither can be freely edited
    signed_payload = {
        "state": state,
        "timestamp": timestamp,
    }
    mac = sign(normalize(signed_payload))
    proof_id = f"asp_{mac[:12]}"

    proof = {
        "proof_id": proof_id,
        "timestamp": timestamp,
        "mac": mac,
        "summary": summary,
        "state_file": str(Path(args.state_file).name),
    }

    proofs_dir = Path("proofs")
    proofs_dir.mkdir(exist_ok=True)
    proof_path = proofs_dir / f"{proof_id}.json"
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2)

    print("=== Agent State Snapshot ===")
    print(f"Proof ID:    {proof_id}")
    print(f"Timestamp:   {timestamp}")
    print(f"MAC:         {mac}")
    print()
    print("Summary (declared, not verified):")
    print(f"  Agent:     {summary['agent_id']}")
    print(f"  Memory:    {summary['declared_memory_status']}")
    print(f"  Tools:     {summary['tools_allowed']}/{summary['tools_total']} allowed")
    print(f"  Context:   {summary['context_messages']} messages")
    print(f"  Action:    {summary['intended_action']}")
    print()
    print(f"Snapshot saved to: {proof_path}")


def cmd_verify(args):
    proof = load_json(args.proof_file)
    current_state = load_json(args.state_file)

    stored_mac = proof.get("mac", "")
    stored_timestamp = proof.get("timestamp", "")

    # Reconstruct the signed payload
    signed_payload = {
        "state": current_state,
        "timestamp": stored_timestamp,
    }
    current_mac = sign(normalize(signed_payload))

    print("=== Verification ===")
    print(f"Proof ID:      {proof.get('proof_id')}")
    print(f"Stored MAC:    {stored_mac}")
    print(f"Current MAC:   {current_mac}")

    if hmac.compare_digest(current_mac, stored_mac):
        print("Result:        MATCH - state unchanged")
        sys.exit(0)
    else:
        print("Result:        MISMATCH - state has changed since snapshot was generated")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Agent State Proof - HMAC-signed snapshot of declared agent state"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_prove = sub.add_parser("prove", help="Generate a signed state snapshot")
    p_prove.add_argument("state_file", help="Path to agent state JSON")
    p_prove.set_defaults(func=cmd_prove)

    p_verify = sub.add_parser("verify", help="Verify a snapshot against current state")
    p_verify.add_argument("proof_file", help="Path to previously generated snapshot JSON")
    p_verify.add_argument("state_file", help="Path to current agent state JSON")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
