#!/usr/bin/env python3
"""Basic tests for Agent State Proof."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ASP = Path(__file__).parent / "asp.py"
SECRET = "test-secret-key-do-not-use-in-production"


class TestASP(unittest.TestCase):
    def setUp(self):
        self.env = os.environ.copy()
        self.env["ASP_SECRET"] = SECRET
        self.tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_asp(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(ASP), *args],
            env=env or self.env,
            capture_output=True,
            text=True,
            cwd=self.tmpdir,
        )

    def write_state(self, data, name="state.json") -> Path:
        path = self.tmpdir / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_prove_and_verify_match(self):
        state = {"agent_id": "test", "tools": [{"name": "read", "allowed": True}]}
        state_path = self.write_state(state)

        r1 = self.run_asp("prove", str(state_path))
        self.assertEqual(r1.returncode, 0, r1.stderr)

        proof_files = list((self.tmpdir / "proofs").glob("asp_*.json"))
        self.assertEqual(len(proof_files), 1)

        r2 = self.run_asp("verify", str(proof_files[0]), str(state_path))
        self.assertEqual(r2.returncode, 0)
        self.assertIn("MATCH", r2.stdout)

    def test_verify_detects_change(self):
        state = {"agent_id": "test", "value": 1}
        state_path = self.write_state(state)

        r1 = self.run_asp("prove", str(state_path))
        self.assertEqual(r1.returncode, 0)

        state["value"] = 2
        state_path.write_text(json.dumps(state), encoding="utf-8")

        proof_files = list((self.tmpdir / "proofs").glob("asp_*.json"))
        r2 = self.run_asp("verify", str(proof_files[0]), str(state_path))
        self.assertEqual(r2.returncode, 1)
        self.assertIn("MISMATCH", r2.stdout)

    def test_tampered_proof_fails(self):
        state = {"agent_id": "test", "value": 1}
        state_path = self.write_state(state)

        r1 = self.run_asp("prove", str(state_path))
        self.assertEqual(r1.returncode, 0)

        proof_files = list((self.tmpdir / "proofs").glob("asp_*.json"))
        proof_path = proof_files[0]
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        proof["timestamp"] = "1999-01-01T00:00:00Z"  # tamper
        proof_path.write_text(json.dumps(proof), encoding="utf-8")

        r2 = self.run_asp("verify", str(proof_path), str(state_path))
        self.assertEqual(r2.returncode, 1)
        self.assertIn("MISMATCH", r2.stdout)

    def test_wrong_secret_fails(self):
        state = {"agent_id": "test"}
        state_path = self.write_state(state)

        r1 = self.run_asp("prove", str(state_path))
        self.assertEqual(r1.returncode, 0)

        wrong_env = self.env.copy()
        wrong_env["ASP_SECRET"] = "wrong-secret"
        proof_files = list((self.tmpdir / "proofs").glob("asp_*.json"))
        r2 = self.run_asp("verify", str(proof_files[0]), str(state_path), env=wrong_env)
        self.assertEqual(r2.returncode, 1)
        self.assertIn("MISMATCH", r2.stdout)

    def test_missing_secret(self):
        env = os.environ.copy()
        env.pop("ASP_SECRET", None)
        state_path = self.write_state({"a": 1})
        r = self.run_asp("prove", str(state_path), env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("ASP_SECRET", r.stderr)

    def test_missing_file(self):
        r = self.run_asp("prove", "nonexistent.json")
        self.assertEqual(r.returncode, 2)

    def test_invalid_json(self):
        bad = self.tmpdir / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        r = self.run_asp("prove", str(bad))
        self.assertEqual(r.returncode, 2)

    def test_non_object_state(self):
        path = self.write_state([1, 2, 3])
        r = self.run_asp("prove", str(path))
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
