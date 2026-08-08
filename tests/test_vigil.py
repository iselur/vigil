"""vigil enforcement suite: decide() units, effect-level kill-test, fault injection."""

import http.server
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import vigil  # noqa: E402

PY = sys.executable


# ---------- pure-core unit tests (mutation-campaign kill set) ----------

class DecideTests(unittest.TestCase):
    def d(self, **kw):
        base = dict(entries=["E1"], claims={}, live={}, strikes={}, notified={},
                    now=1000000.0, mem_ok=True)
        base.update(kw)
        return vigil.decide(**base)

    def claim(self, age=9999):
        return {"entry": "E1", "created_epoch": 1000000.0 - age}

    def test_unclaimed_alerts_once_then_dedupes(self):
        r1 = self.d()
        self.assertEqual(r1["states"]["E1"], "unclaimed")
        self.assertEqual(len(r1["alerts"]), 1)
        r2 = self.d(notified=r1["notified"])
        self.assertEqual(r2["alerts"], [])

    def test_cold_start_claim_is_healthy_and_silent(self):
        r = self.d(claims={"E1": self.claim(age=10)}, live={"E1": "dead"})
        self.assertEqual(r["states"]["E1"], "healthy")
        self.assertEqual(r["alerts"], [])
        self.assertIsNone(r["recover"])

    def test_cold_start_boundary_is_exact(self):
        r = self.d(claims={"E1": self.claim(age=vigil.COLD_START_S)},
                   live={"E1": "dead"})
        self.assertEqual(r["states"]["E1"], "orphaned")

    def test_dead_below_budget_recovers(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "dead"},
                   strikes={"E1": 1})
        self.assertEqual(r["states"]["E1"], "orphaned")
        self.assertEqual(r["recover"], "E1")

    def test_dead_at_budget_quarantines_no_recover(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "dead"},
                   strikes={"E1": vigil.MAX_STRIKES})
        self.assertEqual(r["states"]["E1"], "quarantined")
        self.assertIsNone(r["recover"])
        self.assertIn("quarantined", r["alerts"][0][2])

    def test_unknown_alerts_but_never_recovers(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "unknown"})
        self.assertEqual(r["states"]["E1"], "unknown")
        self.assertIsNone(r["recover"])
        self.assertIn("observation failure", r["alerts"][0][2])

    def test_low_memory_blocks_recovery_and_alerts(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "dead"}, mem_ok=False)
        self.assertIsNone(r["recover"])
        self.assertTrue(any(s == "memory-low" for _, s, _ in r["alerts"]))

    def test_healthy_clears_notified(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "alive"},
                   notified={"E1": "orphaned"})
        self.assertNotIn("E1", r["notified"])

    def test_one_recovery_per_cycle(self):
        r = self.d(entries=["E2", "E1"],
                   claims={"E1": self.claim(), "E2": dict(self.claim(), entry="E2")},
                   live={"E1": "dead", "E2": "dead"})
        self.assertEqual(r["recover"], "E1")  # sorted order, exactly one


class ResumeArgvTests(unittest.TestCase):
    def test_codex_flags_precede_resume_subcommand(self):
        claim = {"entry": "E1", "session": "sid123", "vendor": "codex",
                 "policy": {"codex-sandbox": "read-only"}, "workdir": "/tmp"}
        argv = vigil.resume_argv(claim, "p")
        i = argv.index("exec")
        self.assertEqual(argv[i + 1: i + 4], ["--sandbox", "read-only", "resume"])
        self.assertEqual(argv[-2], "sid123")

    def test_claude_policy_not_elevated(self):
        claim = {"entry": "E1", "session": "sid123", "vendor": "claude",
                 "policy": {}, "workdir": "/tmp"}
        argv = vigil.resume_argv(claim, "p")
        self.assertIn("default", argv)
        self.assertNotIn("bypassPermissions", argv)


class LedgerParseTests(unittest.TestCase):
    HDR = "| id | date | request | lane | plan-ref | status | evidence |\n|--|--|--|--|--|--|--|\n"

    def test_open_rows_extracted(self):
        rows = vigil.parse_ledger_md(
            self.HDR + "| R1 | d | words | — | — | open | x |\n"
                       "| R2 | d | words | — | — | done | x |\n")
        self.assertEqual([r for r, s in rows if s == "open"], ["R1"])

    def test_malformed_row_raises(self):
        with self.assertRaises(ValueError):
            vigil.parse_ledger_md("| R1 | only | three |\n")


# ---------- effect-level kill-test ----------

class NtfyRecorder(http.server.BaseHTTPRequestHandler):
    posts = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        NtfyRecorder.posts.append((self.path, self.headers.get("Title", ""),
                                   body.decode()))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class KillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vigil-test-"))
        self.state = self.tmp / "state"
        self.config = self.tmp / "config"
        self.bins = self.tmp / "bins"
        self.home = self.tmp / "home"
        self.work = self.tmp / "work"
        for d in (self.state, self.config, self.bins, self.home, self.work):
            d.mkdir(parents=True)
        self.session = "deadbeefsess"
        # ledger with one open entry
        self.ledger = self.tmp / "LEDGER.md"
        self.ledger.write_text(
            "| id | date | request | lane | plan-ref | status | evidence |\n"
            "|--|--|--|--|--|--|--|\n"
            "| R900 | 2026-08-08 | test | — | — | open | DONE WHEN: never |\n")
        (self.config / "sources.json").write_text(json.dumps(
            [{"name": "t", "type": "ledger-md", "path": str(self.ledger),
              "workdir": str(self.work)}]))
        # fake transcript so preflight passes
        tdir = self.home / ".claude" / "projects" / "x"
        tdir.mkdir(parents=True)
        (tdir / ("%s.jsonl" % self.session)).write_text(
            '{"type":"user"}\n{"type":"assistant"}\n')
        # fake claude: agents --json => empty registry; --resume => stay alive 60s
        fake_claude = self.bins / "claude"
        fake_claude.write_text(
            "#!/bin/bash\n"
            'if [ "$1" = agents ]; then echo \'{"agents": []}\'; exit 0; fi\n'
            "sleep 60\n")
        fake_claude.chmod(0o755)
        # fake tmux: record argv, run the command after -- in background
        fake_tmux = self.bins / "tmux"
        fake_tmux.write_text(
            "#!/bin/bash\n"
            "printf '%s\\n' \"$@\" >> \"$TMUX_ARGV_LOG\"\n"
            "printf -- '----\\n' >> \"$TMUX_ARGV_LOG\"\n"
            "while [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\n"
            "shift\n"
            "nohup \"$@\" >/dev/null 2>&1 &\n")
        fake_tmux.chmod(0o755)
        self.argv_log = self.tmp / "tmux.argv"
        # ntfy recorder
        NtfyRecorder.posts = []
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), NtfyRecorder)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.ntfy = "http://127.0.0.1:%d/topic" % self.httpd.server_port

    def tearDown(self):
        self.httpd.shutdown()
        subprocess.run(["pkill", "-f", str(self.bins / "claude")],
                       capture_output=True)

    def env(self, fault=""):
        e = dict(os.environ,
                 VIGIL_STATE=str(self.state), VIGIL_CONFIG=str(self.config),
                 VIGIL_CLAUDE=str(self.bins / "claude"),
                 VIGIL_TMUX=str(self.bins / "tmux"),
                 VIGIL_NTFY=self.ntfy, VIGIL_MIN_FREE_KB="0",
                 HOME=str(self.home), TMUX_ARGV_LOG=str(self.argv_log))
        if fault:
            e["VIGIL_FAULT"] = fault
        else:
            e.pop("VIGIL_FAULT", None)
        return e

    def dead_claim(self):
        """Claim pointing at a genuinely dead process generation."""
        p = subprocess.Popen(["sleep", "300"])
        st = vigil.proc_starttime(p.pid)
        p.kill()
        p.wait()
        claims = self.state / "claims"
        claims.mkdir(parents=True, exist_ok=True)
        (claims / "R900.json").write_text(json.dumps(
            {"entry": "R900", "session": self.session, "vendor": "claude",
             "pid": p.pid, "starttime": st, "generation": 1,
             "policy": {"permission-mode": "bypassPermissions"},
             "workdir": str(self.work),
             "created": "x", "created_epoch": time.time() - 3600}))
        return p.pid

    def check(self, fault=""):
        return subprocess.run([PY, str(ROOT / "vigil.py"), "check"],
                              env=self.env(fault), capture_output=True, text=True,
                              timeout=120)

    def test_full_recovery_effects(self):
        self.dead_claim()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        # effect 1: alert reached the (fake) server before launch
        titles = [t for _, t, _ in NtfyRecorder.posts]
        self.assertTrue(any("resuming R900" in t for t in titles), titles)
        # effect 2: launch used an exact argv vector, no shell
        argv = self.argv_log.read_text().splitlines()
        self.assertIn("new-session", argv)
        self.assertIn("vigil-R900", argv)
        self.assertIn("--resume", argv)
        self.assertIn(self.session, argv)
        self.assertIn("bypassPermissions", argv)  # policy preserved, not elevated
        # effect 3: claim transferred to the new generation, and it is alive
        c = json.loads((self.state / "claims" / "R900.json").read_text())
        self.assertEqual(c["generation"], 2)
        self.assertEqual(vigil.generation_alive(c["pid"], c["starttime"]), "alive")
        # effect 4: durable intent/commit pair
        log = (self.state / "incidents.log").read_text()
        self.assertIn("event=intent", log)
        self.assertIn("event=commit", log)
        # effect 5: healthy on the next check — no second resume
        n_alerts = len(NtfyRecorder.posts)
        r2 = self.check()
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(self.argv_log.read_text().splitlines().count("new-session"), 1)
        self.assertEqual(len(NtfyRecorder.posts), n_alerts)

    def test_crash_after_intent_consumes_strike_and_reconciles(self):
        self.dead_claim()
        r = self.check(fault="post-intent")
        self.assertEqual(r.returncode, 41)
        self.assertNotIn("new-session",
                         self.argv_log.read_text() if self.argv_log.exists() else "")
        # rerun: reconciles the dangling intent, then recovers on strike 2
        r2 = self.check()
        self.assertEqual(r2.returncode, 0, r2.stderr)
        log = (self.state / "incidents.log").read_text()
        self.assertIn("reconciled:no-process", log)
        self.assertEqual(log.count("event=intent"), 2)
        self.assertEqual(log.count("event=commit"), 1)
        # kill the resumed process: budget is spent, so quarantine, not resume
        c = json.loads((self.state / "claims" / "R900.json").read_text())
        os.kill(c["pid"], signal.SIGKILL)
        time.sleep(0.5)
        # age the claim past cold-start grace to simulate the next hourly cycle
        c["created_epoch"] = time.time() - 3600
        (self.state / "claims" / "R900.json").write_text(json.dumps(c))
        r3 = self.check()
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.assertEqual(self.argv_log.read_text().splitlines().count("new-session"), 1)
        self.assertTrue(any("quarantined" in b for _, _, b in NtfyRecorder.posts))

    def test_crash_after_launch_reconciles_to_commit_not_double_launch(self):
        self.dead_claim()
        r = self.check(fault="post-launch")
        self.assertEqual(r.returncode, 41)
        self.assertEqual(self.argv_log.read_text().splitlines().count("new-session"), 1)
        r2 = self.check()
        self.assertEqual(r2.returncode, 0, r2.stderr)
        # the crashed launch was adopted (committed), not repeated
        self.assertEqual(self.argv_log.read_text().splitlines().count("new-session"), 1)
        log = (self.state / "incidents.log").read_text()
        self.assertIn("note=reconciled", log)
        c = json.loads((self.state / "claims" / "R900.json").read_text())
        self.assertEqual(vigil.generation_alive(c["pid"], c["starttime"]), "alive")

    def test_unknown_liveness_never_resumes(self):
        self.dead_claim()
        # break the registry: claude exits 1 => UNKNOWN
        (self.bins / "claude").write_text("#!/bin/bash\nexit 1\n")
        (self.bins / "claude").chmod(0o755)
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.argv_log.exists())
        self.assertTrue(any("observation failure" in b
                            for _, _, b in NtfyRecorder.posts))

    def test_lock_blocks_second_checker(self):
        self.dead_claim()
        self.state.mkdir(exist_ok=True)
        lock = open(self.state / "lock", "w")
        import fcntl as f
        f.flock(lock, f.LOCK_EX)
        r = self.check()
        self.assertEqual(r.returncode, 0)
        self.assertIn("another check holds the lock", r.stdout)
        self.assertFalse(self.argv_log.exists())
        lock.close()

    def test_source_parse_failure_alerts_not_silent(self):
        self.ledger.write_text("| broken | row |\n")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("source unreadable" in t
                            for _, t, _ in NtfyRecorder.posts))


if __name__ == "__main__":
    unittest.main(verbosity=2)
