import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import asp_audit  # noqa: E402

SCRIPT = HERE / "asp_audit.py"


class AuditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = Path(self._tmp.name) / "audit.jsonl"
        self.env = {**os.environ, "ASP_AUDIT_LOG": str(self.log)}
        self.env.pop("ASP_SECRET", None)
        self.env.pop("ASP_AUDIT_FULL", None)

    def run_cli(self, *args, stdin=None, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=stdin, env=env or self.env,
            capture_output=True, text=True,
        )

    def hook(self, tool="Bash", tool_input=None, env=None):
        event = {"session_id": "s1", "hook_event_name": "PreToolUse",
                 "tool_name": tool, "tool_input": tool_input or {"command": "ls"}}
        return self.run_cli("hook", stdin=json.dumps(event), env=env)

    def fill(self, n=3, env=None):
        for i in range(n):
            self.assertEqual(self.hook(tool_input={"command": f"cmd{i}"}, env=env).returncode, 0)

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines()

    def write_lines(self, lines):
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_chain_verifies(self):
        self.fill(3)
        r = self.run_cli("verify")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("3 entries", r.stdout)

    def test_edited_entry_is_detected(self):
        self.fill(3)
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["tool_name"] = "Read"
        lines[1] = json.dumps(entry)
        self.write_lines(lines)
        r = self.run_cli("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("BROKEN", r.stdout)

    def test_deleted_middle_entry_is_detected(self):
        self.fill(3)
        lines = self.lines()
        del lines[1]
        self.write_lines(lines)
        self.assertEqual(self.run_cli("verify").returncode, 1)

    def test_corrupted_line_is_detected(self):
        self.fill(2)
        self.write_lines(self.lines() + ["{not json"])
        self.assertEqual(self.run_cli("verify").returncode, 1)

    def test_rewritten_chain_needs_the_key(self):
        env = {**self.env, "ASP_SECRET": "k"}
        self.fill(3, env=env)
        entries = [json.loads(line) for line in self.lines()]
        entries[1]["tool_name"] = "Read"
        # Attacker recomputes every hash but does not know the key.
        prev = asp_audit.GENESIS
        for e in entries:
            e["prev_hash"] = prev
            body = {k: v for k, v in e.items() if k not in ("entry_hash", "mac")}
            e["entry_hash"] = asp_audit.sha(asp_audit.canon(body))
            prev = e["entry_hash"]
        self.write_lines([json.dumps(e) for e in entries])
        # Without the key the forgery looks fine; with it, it is caught.
        self.assertEqual(self.run_cli("verify").returncode, 0)
        self.assertEqual(self.run_cli("verify", env=env).returncode, 1)

    def test_tail_truncation_needs_expect_head(self):
        self.fill(3)
        head = json.loads(self.lines()[-1])["entry_hash"]
        self.write_lines(self.lines()[:-1])
        self.assertEqual(self.run_cli("verify").returncode, 0)  # known limitation
        self.assertEqual(self.run_cli("verify", "--expect-head", head).returncode, 1)

    def test_bad_stdin_is_logged_as_error_but_never_blocks(self):
        r = self.run_cli("hook", stdin="not json")
        self.assertEqual(r.returncode, 1)  # 2 would block the tool call
        self.assertIn("NOT LOGGED", r.stderr)
        self.assertFalse(self.log.exists())

    def test_tool_input_is_hashed_unless_full_logging_is_on(self):
        self.hook(tool_input={"command": "export KEY=sk-123"})
        self.assertNotIn("sk-123", self.log.read_text(encoding="utf-8"))
        self.log.unlink()
        self.hook(tool_input={"command": "export KEY=sk-123"}, env={**self.env, "ASP_AUDIT_FULL": "1"})
        self.assertIn("sk-123", self.log.read_text(encoding="utf-8"))

    def test_missing_log_is_exit_2(self):
        self.assertEqual(self.run_cli("verify").returncode, 2)

    @unittest.skipUnless(asp_audit.fcntl, "file locking needs POSIX")
    def test_parallel_hooks_keep_the_chain_intact(self):
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        procs = [subprocess.Popen([sys.executable, str(SCRIPT), "hook"], stdin=subprocess.PIPE,
                                  env=self.env, text=True) for _ in range(8)]
        for p in procs:
            p.communicate(event)
        self.assertTrue(all(p.returncode == 0 for p in procs))
        r = self.run_cli("verify")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("8 entries", r.stdout)


if __name__ == "__main__":
    unittest.main()
