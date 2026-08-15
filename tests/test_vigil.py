"""vigil enforcement suite: decide() units, effect-level kill-test, fault injection."""

import contextlib
import http.server
import json
import os
import signal
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

# Keep every direct import and grill-spawned unittest process away from the
# user's real state/config, even when a test fails before restoring globals.
_TEST_HOME_DIR = tempfile.TemporaryDirectory(prefix="vigil-suite-home-")
_TEST_STATE_DIR = tempfile.TemporaryDirectory(prefix="vigil-suite-state-")
_TEST_CONFIG_DIR = tempfile.TemporaryDirectory(prefix="vigil-suite-config-")
_TEST_DEFAULT_STATE_DIR = Path(_TEST_HOME_DIR.name) / ".local" / "state" / "vigil"
_TEST_DEFAULT_CONFIG_DIR = Path(_TEST_HOME_DIR.name) / ".config" / "vigil"
_TEST_DEFAULT_STATE_DIR.mkdir(parents=True)
_TEST_DEFAULT_CONFIG_DIR.mkdir(parents=True)
_TEST_DEFAULT_STATE_SENTINEL = _TEST_DEFAULT_STATE_DIR / "claims" / "R136.json"
_TEST_DEFAULT_STATE_SENTINEL.parent.mkdir(parents=True)
_TEST_DEFAULT_STATE_SENTINEL.write_bytes(b'{"default-state":"sentinel"}\n')
_TEST_DEFAULT_CONFIG_SENTINEL = _TEST_DEFAULT_CONFIG_DIR / "sentinel"
_TEST_DEFAULT_CONFIG_SENTINEL.write_bytes(b"default-config-sentinel\n")
os.environ["HOME"] = _TEST_HOME_DIR.name
os.environ["VIGIL_STATE"] = _TEST_STATE_DIR.name
os.environ["VIGIL_CONFIG"] = _TEST_CONFIG_DIR.name

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import vigil  # noqa: E402

_IMPORTED_STATE = vigil.STATE
_IMPORTED_CONFIG = vigil.CONFIG

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

    def test_unclaimed_is_started_not_reported(self):
        # Reporting an unclaimed row asks the owner to be the scheduler. vigil already knows
        # how to launch a session; it just had no verb for "never claimed" (owner, 2026-08-14).
        r = self.d()
        self.assertEqual(r["states"]["E1"], "unclaimed")
        self.assertEqual(r["start"], "E1")
        self.assertEqual(r["alerts"], [])

    def test_unclaimed_alerts_once_starting_is_exhausted(self):
        r1 = self.d(starts={"E1": vigil.MAX_STARTS})
        self.assertIsNone(r1["start"])
        self.assertEqual(len(r1["alerts"]), 1)
        r2 = self.d(starts={"E1": vigil.MAX_STARTS}, notified=r1["notified"])
        self.assertEqual(r2["alerts"], [])

    def test_quiet_start_attempts_do_not_suppress_exhaustion_alert(self):
        r1 = self.d(starts={})
        self.assertEqual(r1["alerts"], [])
        self.assertNotIn("E1", r1["notified"])
        r2 = self.d(starts={"E1": 1}, notified=r1["notified"])
        self.assertEqual(r2["alerts"], [])
        self.assertNotIn("E1", r2["notified"])
        r3 = self.d(starts={"E1": vigil.MAX_STARTS}, notified=r2["notified"])
        self.assertEqual(len(r3["alerts"]), 1)
        self.assertEqual(r3["notified"]["E1"], "unclaimed")

    def test_low_memory_does_not_start_work(self):
        r = self.d(mem_ok=False)
        self.assertIsNone(r["start"])

    def test_only_one_row_is_started_per_check(self):
        r = self.d(entries=["E1", "E2"])
        self.assertEqual(r["start"], "E1")

    def test_a_claimed_row_is_never_started(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "alive"})
        self.assertIsNone(r["start"])

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
        self.assertIn("stopped", r["alerts"][0][2])
        self.assertIn("vigil reset E1", r["alerts"][0][2])

    def test_unknown_alerts_but_never_recovers(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "unknown"})
        self.assertEqual(r["states"]["E1"], "unknown")
        self.assertIsNone(r["recover"])
        self.assertIn("check itself failed", r["alerts"][0][2])

    def test_low_memory_blocks_recovery_and_alerts(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "dead"}, mem_ok=False)
        self.assertIsNone(r["recover"])
        self.assertTrue(any(s == "memory-low" for _, s, _ in r["alerts"]))

    def test_healthy_clears_notified(self):
        r = self.d(claims={"E1": self.claim()}, live={"E1": "alive"},
                   notified={"E1": "orphaned"})
        self.assertNotIn("E1", r["notified"])

    def test_blocked_claim_is_blocked_not_healthy(self):
        r = self.d(claims={"E1": dict(self.claim(), blocked={"ask": "promote?"})},
                   live={"E1": "alive"})
        self.assertEqual(r["states"]["E1"], "blocked")
        self.assertIsNone(r["recover"])
        self.assertIn("waiting on a decision", r["alerts"][0][2])

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


class StartArgvTests(unittest.TestCase):
    def test_codex_start_is_sol_high_and_claims_as_codex(self):
        argv = vigil.start_argv("E1", "/tmp", "codex")
        self.assertEqual(argv[:8], [vigil.TMUX_BIN, "new-session", "-d", "-s",
                                   "vigil-start-E1", "-c", "/tmp", "--"])
        self.assertIn(vigil.CODEX_BIN, argv)
        self.assertIn("gpt-5.6-sol", argv)
        self.assertIn("model_reasoning_effort=high", argv)
        self.assertIn("--vendor codex", argv[-1])
        self.assertNotIn(vigil.CLAUDE_BIN, argv[8:-1])

    def test_claude_start_claims_as_claude(self):
        argv = vigil.start_argv("E1", "/tmp", "claude")
        self.assertIn(vigil.CLAUDE_BIN, argv)
        self.assertIn("--vendor claude", argv[-1])
        self.assertNotIn(vigil.CODEX_BIN, argv[8:-1])


class ClaimLockTests(unittest.TestCase):
    def setUp(self):
        self._threads = []
        self._release_events = []
        self._release_paths = []
        self._processes = []
        self.sandbox_state = Path(_TEST_STATE_DIR.name)
        self.tmp = Path(tempfile.mkdtemp(prefix="vigil-lock-test-"))
        self.state = self.tmp / "state"
        self.state.mkdir()
        self.old_state = vigil.STATE
        vigil.STATE = self.state
        self.entry = "R136"
        self.pid = os.getpid()
        self.starttime = vigil.proc_starttime(self.pid)
        self.claim = {
            "entry": self.entry, "session": "native-1", "vendor": "codex",
            "pid": self.pid, "starttime": self.starttime, "generation": 1,
            "policy": {}, "workdir": str(self.tmp), "created": "x",
            "created_epoch": time.time(),
        }
        self.env = dict(os.environ, VIGIL_STATE=str(self.state))
        self.claim_path = self.state / "claims" / (self.entry + ".json")
        self.claim_path.parent.mkdir()
        self.claim_path.write_text(json.dumps(self.claim))

    def tearDown(self):
        for event in self._release_events:
            event.set()
        for path in self._release_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("yes")
        for process in self._processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        for thread in self._threads:
            if thread.ident is not None:
                thread.join(timeout=5)
        alive = [thread.name for thread in self._threads if thread.is_alive()]
        vigil.STATE = self.sandbox_state
        if alive:
            self.fail("test threads survived teardown: %s" % ", ".join(alive))
        for path in self.state.rglob("*"):
            if path.is_file():
                path.unlink()
        for path in sorted(self.state.rglob("*"), reverse=True):
            if path.is_dir():
                path.rmdir()
        self.state.rmdir()

    def start_thread(self, target, name, release_event=None, release_path=None,
                    start=True):
        if release_event is not None:
            self._release_events.append(release_event)
        if release_path is not None:
            self._release_paths.append(Path(release_path))
        thread = threading.Thread(target=target, name=name)
        self._threads.append(thread)
        if start:
            thread.start()
        return thread

    def track_process(self, process):
        self._processes.append(process)
        return process

    def test_entry_lock_is_stable_and_validated(self):
        with vigil.entry_lock(self.entry):
            lock = self.state / "claim-locks" / (self.entry + ".lock")
            self.assertTrue(lock.is_file())
            self.assertEqual(vigil.claim_lock_path(self.entry), lock)
        with self.assertRaises(ValueError):
            vigil.claim_lock_path("../escape")

    def test_claim_commands_leave_external_production_like_state_unchanged(self):
        default_state_before = _TEST_DEFAULT_STATE_SENTINEL.read_bytes()
        default_config_before = _TEST_DEFAULT_CONFIG_SENTINEL.read_bytes()
        self.assertTrue(Path(_IMPORTED_STATE).is_relative_to(
            Path(_TEST_STATE_DIR.name)))
        self.assertTrue(Path(_IMPORTED_CONFIG).is_relative_to(
            Path(_TEST_CONFIG_DIR.name)))
        self.assertNotEqual(Path(_IMPORTED_STATE), _TEST_DEFAULT_STATE_DIR)
        self.assertNotEqual(Path(_IMPORTED_CONFIG), _TEST_DEFAULT_CONFIG_DIR)

        suite_claim = Path(_IMPORTED_STATE) / "claims" / (self.entry + ".json")
        suite_claim.parent.mkdir(parents=True, exist_ok=True)
        suite_claim.write_text(json.dumps(self.claim))
        vigil.STATE = Path(_IMPORTED_STATE)
        try:
            self.assertEqual(vigil.cmd_claim([
                self.entry, "--session", "native-2", "--vendor", "codex",
                "--pid", str(self.pid)]), 0)
            with mock.patch.object(vigil, "alert", return_value=True):
                self.assertEqual(vigil.cmd_blocked([
                    self.entry, "owner ask", "--recommend", "continue",
                    "--by", "later"]), 0)
        finally:
            vigil.STATE = self.state
        self.assertEqual(_TEST_DEFAULT_STATE_SENTINEL.read_bytes(),
                         default_state_before)
        self.assertEqual(_TEST_DEFAULT_CONFIG_SENTINEL.read_bytes(),
                         default_config_before)

    def test_guard_exports_claim_and_propagates_child_exit(self):
        child = (
            "import json,os,sys; value=json.loads(os.environ['VIGIL_CLAIM_JSON']); "
            "assert list(value) == sorted(value); assert value['entry']=='R136'; "
            "assert value['session']=='native-1'; sys.exit(23)"
        )
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            code = vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", child,
            ])
        self.assertEqual(code, 23)

    def test_guard_holds_entry_lock_until_child_exit(self):
        started = self.tmp / "child-started"
        release_child = self.tmp / "release-child"
        child = (
            "import pathlib,time; marker=pathlib.Path(%r); marker.write_text('yes'); "
            "release=pathlib.Path(%r); exec(\"while not release.exists():\\n "
            "time.sleep(.01)\")"
        ) % (str(started), str(release_child))
        errors = []
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            worker = self.start_thread(lambda: vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", child]), "guard-worker", release_path=release_child)
            for _ in range(500):
                if started.exists():
                    break
                time.sleep(.01)
            self.assertTrue(started.exists())
            acquired = threading.Event()

            def contender():
                try:
                    with vigil.entry_lock(self.entry):
                        acquired.set()
                except BaseException as exc:
                    errors.append(exc)

            contender_reached = threading.Event()
            real_flock = vigil.fcntl.flock

            def flock(handle, operation):
                if (operation == vigil.fcntl.LOCK_EX and
                        threading.current_thread().name == "guard-contender"):
                    contender_reached.set()
                return real_flock(handle, operation)

            contender_thread = self.start_thread(contender, "guard-contender",
                                                 start=False)
            with mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
                contender_thread.start()
                self.assertTrue(contender_reached.wait(5))
                self.assertFalse(acquired.is_set())
                release_child.write_text("yes")
                worker.join(5)
                contender_thread.join(5)
        self.assertEqual(errors, [])
        self.assertTrue(acquired.is_set())

    def test_guard_refuses_session_and_process_generation_mismatch(self):
        for actor in (
            (self.pid, self.starttime, "codex"),
            (self.pid, self.starttime, "claude"),
        ):
            with mock.patch.object(vigil, "_find_agent_process", return_value=actor):
                self.assertEqual(vigil.cmd_guard([
                    self.entry, "--session", "wrong", "--", sys.executable,
                    "-c", "raise SystemExit(0)"],), 2)
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid + 1, self.starttime, "codex")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime + 1, "codex")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "claude")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)

    def test_claim_rejects_whitespace_session_without_mutating(self):
        before = self.claim_path.read_bytes()
        self.assertEqual(vigil.cmd_claim([
            self.entry, "--session", " \t ", "--vendor", "codex",
            "--pid", str(self.pid),
        ]), 2)
        self.assertEqual(self.claim_path.read_bytes(), before)

    def test_guard_rejects_whitespace_session_without_mutating(self):
        self.claim_path.write_text(json.dumps(dict(self.claim, session=" \t ")))
        before = self.claim_path.read_bytes()
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", " \t ", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)
        self.assertEqual(self.claim_path.read_bytes(), before)

    def test_claim_rejects_whitespace_workdir_without_mutating(self):
        before = self.claim_path.read_bytes()
        self.assertEqual(vigil.cmd_claim([
            self.entry, "--session", "native-1", "--vendor", "codex",
            "--pid", str(self.pid), "--workdir", " \t ",
        ]), 2)
        self.assertEqual(self.claim_path.read_bytes(), before)

    def test_guard_rejects_whitespace_workdir_without_mutating(self):
        self.claim_path.write_text(json.dumps(dict(self.claim, workdir=" \t ")))
        before = self.claim_path.read_bytes()
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)
        self.assertEqual(self.claim_path.read_bytes(), before)

    def test_guard_refuses_missing_workdir_and_nonpositive_generation(self):
        for field, value in (("workdir", ""), ("generation", 0)):
            claim = dict(self.claim, **{field: value})
            self.claim_path.write_text(json.dumps(claim))
            with mock.patch.object(vigil, "_find_agent_process",
                                   return_value=(self.pid, self.starttime, "codex")):
                self.assertEqual(vigil.cmd_guard([
                    self.entry, "--session", "native-1", "--", sys.executable,
                    "-c", "raise SystemExit(0)"],), 2)
            self.claim_path.write_text(json.dumps(self.claim))

    def test_agent_ancestry_uses_exact_argv0_vendor_processes(self):
        probe = ("import vigil; found=vigil._find_agent_process(); "
                 "print(found[2] if found else 'none')")
        for vendor in ("codex", "claude"):
            exact = "exec -a %s bash -c %s" % (
                vendor, shlex.quote("python3 -c %s & wait" % shlex.quote(probe)))
            exact_result = subprocess.run(["bash", "-c", exact],
                                           env=dict(os.environ, PYTHONPATH=str(ROOT)),
                                           capture_output=True, text=True, check=True)
            self.assertEqual(exact_result.stdout.strip(), vendor)
            wrapper = ["/bin/sh", "--vendor=%s" % vendor]
            self.assertIsNone(vigil._agent_vendor(wrapper))
            proc_probe = (
                "import os,pathlib,vigil; argv=pathlib.Path(f'/proc/{os.getppid()}/cmdline') "
                ".read_bytes().decode().split('\\0'); "
                "print(vigil._agent_vendor(argv) or 'none')"
            )
            wrapper = "exec -a wrapper bash -c %s %s" % (
                shlex.quote("python3 -c %s & wait" % shlex.quote(proc_probe)),
                vendor)
            wrapper_result = subprocess.run(
                ["bash", "-c", wrapper],
                env=dict(os.environ, PYTHONPATH=str(ROOT)),
                capture_output=True, text=True, check=True)
            self.assertEqual(wrapper_result.stdout.strip(), "none")
        self.assertIsNone(vigil._agent_vendor(["/bin/sh", "codex"]))
        self.assertEqual(vigil._agent_vendor(["/opt/codex"]), "codex")

    def test_transfer_first_refuses_former_session(self):
        before = self.claim_path.read_bytes()
        result = vigil.cmd_claim([
            self.entry, "--session", "native-2", "--vendor", "codex",
            "--pid", str(self.pid)])
        self.assertEqual(result, 0)
        transferred = self.claim_path.read_bytes()
        self.assertNotEqual(transferred, before)
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            self.assertEqual(vigil.cmd_guard([
                self.entry, "--session", "native-1", "--", sys.executable,
                "-c", "raise SystemExit(0)"],), 2)
        self.assertEqual(self.claim_path.read_bytes(), transferred)

    def test_guard_wins_then_real_claim_transfer_waits(self):
        started = self.tmp / "guard-started"
        release_guard = self.tmp / "release-guard"
        child = (
            "import pathlib,time; marker=pathlib.Path(%r); marker.write_text('yes'); "
            "release=pathlib.Path(%r); exec(\"while not release.exists():\\n "
            "time.sleep(.01)\")"
        ) % (str(started), str(release_guard))
        guard_result = []
        transfer_result = []
        with mock.patch.object(vigil, "_find_agent_process",
                               return_value=(self.pid, self.starttime, "codex")):
            guard = self.start_thread(
                lambda: guard_result.append(vigil.cmd_guard([
                    self.entry, "--session", "native-1", "--", sys.executable,
                    "-c", child]),), "guard-consumer", release_path=release_guard)
            for _ in range(500):
                if started.exists():
                    break
                time.sleep(.01)
            self.assertTrue(started.exists())
            transfer_reached = threading.Event()
            real_flock = vigil.fcntl.flock

            def flock(handle, operation):
                if (operation == vigil.fcntl.LOCK_EX and
                        threading.current_thread().name == "real-transfer"):
                    transfer_reached.set()
                return real_flock(handle, operation)

            def transfer():
                transfer_result.append(vigil.cmd_claim([
                    self.entry, "--session", "native-2", "--vendor", "codex",
                    "--pid", str(self.pid)]))

            with mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
                writer = self.start_thread(transfer, "real-transfer", start=False)
                writer.start()
                self.assertTrue(transfer_reached.wait(5))
                self.assertEqual(json.loads(self.claim_path.read_text())["session"],
                                 "native-1")
                release_guard.write_text("yes")
                guard.join(5)
                writer.join(5)
        self.assertEqual(guard_result, [0])
        self.assertEqual(transfer_result, [0])
        self.assertEqual(json.loads(self.claim_path.read_text())["session"],
                         "native-2")

    def test_guard_transfer_matrix_both_orders_and_generations(self):
        cases = (
            ("codex", "claude", "codex-session", "claude-session"),
            ("claude", "codex", "claude-session", "codex-session"),
            ("codex", "codex", "same-session", "same-session"),
        )
        for n, (old_vendor, new_vendor, old_session, new_session) in enumerate(cases):
            old_proc = self.track_process(subprocess.Popen(["sleep", "30"]))
            new_proc = self.track_process(subprocess.Popen(["sleep", "30"]))
            old_start = vigil.proc_starttime(old_proc.pid)
            new_start = vigil.proc_starttime(new_proc.pid)
            old_claim = dict(self.claim, vendor=old_vendor, session=old_session,
                             pid=old_proc.pid, starttime=old_start, generation=1)
            self.claim_path.write_text(json.dumps(old_claim))

            # Transfer-first: the former live process is refused and the new
            # claim remains byte-identical after the refusal.
            self.assertEqual(vigil.cmd_claim([
                self.entry, "--session", new_session, "--vendor", new_vendor,
                "--pid", str(new_proc.pid)]), 0)
            transferred = self.claim_path.read_bytes()
            with mock.patch.object(vigil, "_find_agent_process",
                                   return_value=(old_proc.pid, old_start, old_vendor)):
                self.assertEqual(vigil.cmd_guard([
                    self.entry, "--session", old_session, "--", sys.executable,
                    "-c", "raise SystemExit(0)"],), 2)
            self.assertEqual(self.claim_path.read_bytes(), transferred)
            self.assertEqual(json.loads(transferred)["generation"], 2)

            # Mutation-first: the old guard owns the lock, then a real claim
            # transfer reaches and waits on that same lock until child exit.
            self.claim_path.write_text(json.dumps(old_claim))
            started = self.tmp / ("matrix-started-%d" % n)
            release = self.tmp / ("matrix-release-%d" % n)
            child = (
                "import pathlib,time; pathlib.Path(%r).write_text('yes'); "
                "r=pathlib.Path(%r); exec(\"while not r.exists():\\n "
                "time.sleep(.01)\")"
            ) % (str(started), str(release))
            guard_result = []
            transfer_result = []
            with mock.patch.object(vigil, "_find_agent_process",
                                   return_value=(old_proc.pid, old_start, old_vendor)):
                guard = self.start_thread(lambda: guard_result.append(
                    vigil.cmd_guard([
                        self.entry, "--session", old_session, "--", sys.executable,
                        "-c", child])), "matrix-guard-%d" % n,
                    release_path=release)
                for _ in range(500):
                    if started.exists():
                        break
                    time.sleep(.01)
                self.assertTrue(started.exists())
                transfer_reached = threading.Event()
                real_flock = vigil.fcntl.flock

                def flock(handle, operation):
                    if (operation == vigil.fcntl.LOCK_EX and
                            threading.current_thread().name == "matrix-transfer-%d" % n):
                        transfer_reached.set()
                    return real_flock(handle, operation)

                def transfer():
                    transfer_result.append(vigil.cmd_claim([
                        self.entry, "--session", new_session, "--vendor", new_vendor,
                        "--pid", str(new_proc.pid)]))

                with mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
                    writer = self.start_thread(
                        transfer, "matrix-transfer-%d" % n, start=False)
                    writer.start()
                    self.assertTrue(transfer_reached.wait(5))
                    self.assertEqual(json.loads(self.claim_path.read_text())["session"],
                                     old_session)
                    release.write_text("yes")
                    guard.join(5)
                    writer.join(5)
            self.assertEqual(guard_result, [0])
            self.assertEqual(transfer_result, [0])
            final = json.loads(self.claim_path.read_text())
            self.assertEqual(final["session"], new_session)
            self.assertEqual(final["vendor"], new_vendor)
            self.assertEqual(final["generation"], 2)

    def recovery_patches(self):
        return (
            mock.patch.object(vigil, "preflight", return_value=True),
            mock.patch.object(vigil, "alert", return_value=True),
            mock.patch.object(vigil, "resume_argv", return_value=["resume"]),
            mock.patch.object(vigil, "find_resumed",
                              return_value=(self.pid, self.starttime)),
            mock.patch.object(vigil.subprocess, "run"),
        )

    def test_recovery_transfer_first_refuses_without_overwrite(self):
        old_bytes = self.claim_path.read_bytes()
        with contextlib.ExitStack() as stack:
            for patcher in self.recovery_patches():
                stack.enter_context(patcher)
            self.assertEqual(vigil.cmd_claim([
                self.entry, "--session", "native-2", "--vendor", "codex",
                "--pid", str(self.pid)]), 0)
            transferred = self.claim_path.read_bytes()
            self.assertFalse(vigil.recover(self.entry, dict(self.claim), {}))
        self.assertNotEqual(transferred, old_bytes)
        self.assertEqual(self.claim_path.read_bytes(), transferred)
        self.assertIn("note=commit:claim-changed",
                      (self.state / "incidents.log").read_text())

    def test_recovery_wins_then_transfer_waits_and_preserves_both_commits(self):
        reached = threading.Event()
        release = threading.Event()
        transfer_reached = threading.Event()
        recovery_result = []
        transfer_result = []
        real_write_json = vigil.write_json
        real_flock = vigil.fcntl.flock

        def write_json(path, obj):
            if (Path(path) == self.claim_path and
                    threading.current_thread().name == "recovery"):
                reached.set()
                if not release.wait(5):
                    raise AssertionError("recovery write barrier timed out")
            return real_write_json(path, obj)

        def flock(handle, operation):
            if (operation == vigil.fcntl.LOCK_EX and
                    threading.current_thread().name == "recovery-transfer"):
                transfer_reached.set()
            return real_flock(handle, operation)

        def recover():
            with contextlib.ExitStack() as stack:
                for patcher in self.recovery_patches():
                    stack.enter_context(patcher)
                recovery_result.append(vigil.recover(
                    self.entry, dict(self.claim), {}))

        def transfer():
            transfer_result.append(vigil.cmd_claim([
                self.entry, "--session", "native-2", "--vendor", "codex",
                "--pid", str(self.pid)]))

        with mock.patch.object(vigil, "write_json", side_effect=write_json), \
                mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
            recovery = self.start_thread(recover, "recovery",
                                         release_event=release, start=False)
            recovery.start()
            self.assertTrue(reached.wait(5))
            writer = self.start_thread(transfer, "recovery-transfer", start=False)
            writer.start()
            self.assertTrue(transfer_reached.wait(5))
            self.assertEqual(json.loads(self.claim_path.read_text())["session"],
                             "native-1")
            release.set()
            recovery.join(5)
            writer.join(5)
        self.assertEqual(recovery_result, [True])
        self.assertEqual(transfer_result, [0])
        final = json.loads(self.claim_path.read_text())
        self.assertEqual(final["session"], "native-2")
        self.assertEqual(final["generation"], 3)

    def append_dangling_intent(self, attempt="dangling"):
        vigil.append_incident(
            event="intent", attempt=attempt, entry=self.entry,
            session=self.claim["session"], vendor=self.claim["vendor"],
            pid=self.claim["pid"], starttime=self.claim["starttime"],
            generation=self.claim["generation"])

    def test_dangling_reconcile_transfer_first_refuses_without_overwrite(self):
        self.append_dangling_intent()
        self.assertEqual(vigil.cmd_claim([
            self.entry, "--session", "native-2", "--vendor", "codex",
            "--pid", str(self.pid)]), 0)
        transferred = self.claim_path.read_bytes()
        with mock.patch.object(vigil, "find_resumed",
                               side_effect=AssertionError("stale reconcile searched")):
            vigil.reconcile()
        self.assertEqual(self.claim_path.read_bytes(), transferred)
        self.assertIn("note=reconciled:claim-identity-mismatch",
                      (self.state / "incidents.log").read_text())

    def test_dangling_reconcile_wins_then_transfer_waits(self):
        self.append_dangling_intent()
        found_reached = threading.Event()
        release_found = threading.Event()
        transfer_reached = threading.Event()
        transfer_result = []
        real_flock = vigil.fcntl.flock

        def find_resumed(claim, deadline_s=1):
            found_reached.set()
            if not release_found.wait(5):
                raise AssertionError("reconcile find barrier timed out")
            return self.pid, self.starttime

        def flock(handle, operation):
            if (operation == vigil.fcntl.LOCK_EX and
                    threading.current_thread().name == "dangling-transfer"):
                transfer_reached.set()
            return real_flock(handle, operation)

        def transfer():
            transfer_result.append(vigil.cmd_claim([
                self.entry, "--session", "native-2", "--vendor", "codex",
                "--pid", str(self.pid)]))

        with mock.patch.object(vigil, "find_resumed", side_effect=find_resumed), \
                mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
            reconcile = self.start_thread(
                vigil.reconcile, "dangling-reconcile",
                release_event=release_found, start=False)
            reconcile.start()
            self.assertTrue(found_reached.wait(5))
            writer = self.start_thread(transfer, "dangling-transfer", start=False)
            writer.start()
            self.assertTrue(transfer_reached.wait(5))
            self.assertEqual(json.loads(self.claim_path.read_text())["session"],
                             "native-1")
            release_found.set()
            reconcile.join(5)
            writer.join(5)
        self.assertEqual(transfer_result, [0])
        final = json.loads(self.claim_path.read_text())
        self.assertEqual(final["session"], "native-2")
        self.assertEqual(final["generation"], 3)

    def test_dangling_legacy_intent_fails_closed(self):
        vigil.append_incident(event="intent", attempt="legacy", entry=self.entry,
                              session=self.claim["session"], vendor=self.claim["vendor"])
        before = self.claim_path.read_bytes()
        vigil.reconcile()
        self.assertEqual(self.claim_path.read_bytes(), before)
        self.assertIn("note=reconciled:claim-identity-mismatch",
                      (self.state / "incidents.log").read_text())

    def _assert_writer_waits(self, writer):
        entered = threading.Event()
        release = threading.Event()

        def hold():
            with vigil.entry_lock(self.entry):
                entered.set()
                release.wait(5)

        holder = self.start_thread(hold, "lock-holder", release_event=release)
        self.assertTrue(entered.wait(5))
        finished = threading.Event()
        writer_reached = threading.Event()
        errors = []

        def run():
            try:
                writer()
            except BaseException as exc:  # surface writer failures below
                errors.append(exc)
            finally:
                finished.set()

        real_flock = vigil.fcntl.flock

        def flock(handle, operation):
            if (operation == vigil.fcntl.LOCK_EX and
                    threading.current_thread().name == "lock-writer"):
                writer_reached.set()
            return real_flock(handle, operation)

        worker = self.start_thread(run, "lock-writer", start=False)
        with mock.patch.object(vigil.fcntl, "flock", side_effect=flock):
            worker.start()
            self.assertTrue(writer_reached.wait(5))
            self.assertFalse(finished.is_set())
            release.set()
            worker.join(5)
            holder.join(5)
        self.assertTrue(finished.is_set())
        self.assertEqual(errors, [])

    def test_each_claim_content_writer_waits_on_the_entry_lock(self):
        self._assert_writer_waits(lambda: vigil.cmd_claim([
            self.entry, "--session", "native-2", "--vendor", "codex",
            "--pid", str(self.pid)]))
        with mock.patch.object(vigil, "alert", return_value=True):
            self._assert_writer_waits(lambda: vigil.cmd_blocked([
                self.entry, "owner ask", "--recommend", "continue", "--by", "later"]))
            self._assert_writer_waits(lambda: vigil.cmd_blocked([
                self.entry, "--clear"]))
        self.assertEqual(vigil.cmd_claim([
            self.entry, "--session", "native-1", "--vendor", "codex",
            "--pid", str(self.pid)]), 0)
        with mock.patch.object(vigil, "preflight", return_value=True), \
                mock.patch.object(vigil, "alert", return_value=True), \
                mock.patch.object(vigil, "resume_argv", return_value=["resume"]), \
                mock.patch.object(vigil, "find_resumed",
                                  return_value=(self.pid, self.starttime)), \
                mock.patch.object(vigil.subprocess, "run"):
            self._assert_writer_waits(lambda: vigil.recover(
                self.entry, dict(self.claim), {}))
        vigil.append_incident(event="intent", attempt="dangling", entry=self.entry)
        with mock.patch.object(vigil, "find_resumed",
                               return_value=(self.pid, self.starttime)):
            self._assert_writer_waits(vigil.reconcile)


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
        self._threads = []
        self._processes = []
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
        fake_codex = self.bins / "codex"
        fake_codex.write_text("#!/bin/bash\nsleep 60\n")
        fake_codex.chmod(0o755)
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
        self.http_thread = threading.Thread(target=self.httpd.serve_forever,
                                            name="ntfy-server", daemon=True)
        self._threads.append(self.http_thread)
        self.http_thread.start()
        self.ntfy = "http://127.0.0.1:%d/topic" % self.httpd.server_port

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.http_thread.join(timeout=5)
        for process in self._processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        for binary in (self.bins / "claude", self.bins / "codex"):
            subprocess.run(["pkill", "-f", str(binary)], capture_output=True)
            for _ in range(50):
                remaining = subprocess.run(["pgrep", "-f", str(binary)],
                                           capture_output=True)
                if remaining.returncode != 0:
                    break
                time.sleep(.01)
            self.assertNotEqual(remaining.returncode, 0,
                                "test process survived teardown: %s" % binary)
        alive = [thread.name for thread in self._threads if thread.is_alive()]
        self.assertEqual(alive, [])

    def env(self, fault=""):
        e = dict(os.environ,
                 VIGIL_STATE=str(self.state), VIGIL_CONFIG=str(self.config),
                 VIGIL_CLAUDE=str(self.bins / "claude"),
                 VIGIL_CODEX=str(self.bins / "codex"),
                 VIGIL_TMUX=str(self.bins / "tmux"),
                 VIGIL_NTFY=self.ntfy, VIGIL_MIN_FREE_KB="0",
                 HOME=str(self.home), TMUX_ARGV_LOG=str(self.argv_log))
        if fault:
            e["VIGIL_FAULT"] = fault
        else:
            e.pop("VIGIL_FAULT", None)
        return e

    def dead_claim(self, role="orchestrator"):
        """Claim pointing at a genuinely dead process generation."""
        p = subprocess.Popen(["sleep", "300"])
        st = vigil.proc_starttime(p.pid)
        p.kill()
        p.wait()
        claims = self.state / "claims"
        claims.mkdir(parents=True, exist_ok=True)
        claim = {"entry": "R900", "session": self.session, "vendor": "claude",
                 "pid": p.pid, "starttime": st, "generation": 1,
                 "policy": {"permission-mode": "bypassPermissions"},
                 "workdir": str(self.work),
                 "created": "x", "created_epoch": time.time() - 3600}
        if role is not None:
            claim["role"] = role
        (claims / "R900.json").write_text(json.dumps(claim))
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
        self.assertTrue(any("Restarting work on R900" in t for t in titles), titles)
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

    def test_unclaimed_start_uses_persisted_codex_vendor(self):
        (self.config / "start-vendor").write_text("codex\n")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = self.argv_log.read_text().splitlines()
        self.assertIn(str(self.bins / "codex"), argv)
        self.assertNotIn(str(self.bins / "claude"), argv)
        self.assertIn("gpt-5.6-sol", argv)
        self.assertIn("model_reasoning_effort=high", argv)
        self.assertTrue(any("--vendor codex" in part for part in argv))

    def test_vendor_command_switches_persistently(self):
        for vendor in ("codex", "claude"):
            r = subprocess.run([PY, str(ROOT / "vigil.py"), "vendor", vendor],
                               env=self.env(), capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((self.config / "start-vendor").read_text(), vendor + "\n")
            shown = subprocess.run([PY, str(ROOT / "vigil.py"), "vendor"],
                                   env=self.env(), capture_output=True, text=True)
            self.assertEqual(shown.stdout.strip(), vendor)

    def test_unconfigured_start_fails_closed(self):
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.argv_log.exists())
        log = (self.state / "incidents.log").read_text()
        self.assertIn("why=start_vendor_unconfigured", log)
        self.assertNotIn("event=start", log)

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
        self.assertTrue(any("stopped retrying" in b.replace("\n", " ") for _, _, b in NtfyRecorder.posts))

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
        self.assertTrue(any("check itself failed" in b
                            for _, _, b in NtfyRecorder.posts))

    def test_legacy_claude_claim_without_role_alerts_once_without_running_claude(self):
        self.dead_claim(role=None)
        called = self.tmp / "claude-called"
        fake_claude = self.bins / "claude"
        fake_claude.write_text(
            "#!/bin/bash\n"
            "touch %s\n"
            "exit 1\n" % shlex.quote(str(called)))
        fake_claude.chmod(0o755)
        env = self.env()
        env["VIGIL_HEARTBEAT_H"] = "0"

        for _ in range(2):
            r = subprocess.run([PY, str(ROOT / "vigil.py"), "check"], env=env,
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)

        self.assertFalse(called.exists())
        self.assertFalse(self.argv_log.exists())
        self.assertEqual(NtfyRecorder.posts, [
            ("/topic", "R900: manual-only",
             "R900 has a legacy Claude claim without role orchestrator. "
             "Vigil will not probe or resume it; reclaim it explicitly before "
             "automatic recovery.")
        ])

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

    def live_claim(self):
        p = subprocess.Popen(["sleep", "300"])
        self._processes.append(p)
        st = vigil.proc_starttime(p.pid)
        claims = self.state / "claims"
        claims.mkdir(parents=True, exist_ok=True)
        (claims / "R900.json").write_text(json.dumps(
            {"entry": "R900", "session": self.session, "vendor": "claude",
             "role": "orchestrator", "pid": p.pid, "starttime": st,
             "generation": 1, "policy": {},
             "workdir": str(self.work),
             "created": "x", "created_epoch": time.time() - 3600}))

    def test_daily_heartbeat_once_then_quiet(self):
        self.live_claim()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        beats = [b for _, t, b in NtfyRecorder.posts if "Daily check-in" in b
                 or "watching" in b]
        self.assertEqual(len(beats), 1, NtfyRecorder.posts)
        self.assertIn("R900 healthy", beats[0])
        r2 = self.check()
        self.assertEqual(r2.returncode, 0, r2.stderr)
        beats2 = [b for _, t, b in NtfyRecorder.posts if "watching" in b]
        self.assertEqual(len(beats2), 1)  # not repeated within the day

    def test_heartbeat_disabled_by_zero(self):
        self.live_claim()
        env = self.env(); env["VIGIL_HEARTBEAT_H"] = "0"
        r = subprocess.run([PY, str(ROOT / "vigil.py"), "check"], env=env,
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(NtfyRecorder.posts, [])

    def test_blocked_command_alerts_and_heartbeat_lists_it(self):
        self.live_claim()
        r = subprocess.run([PY, str(ROOT / "vigil.py"), "blocked", "R900",
                            "Promote PR #1 to main?", "--recommend", "yes",
                            "--by", "18:00"], env=self.env(),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("needs a decision" in t for _, t, _ in NtfyRecorder.posts))
        body = [b for _, t, b in NtfyRecorder.posts if "needs a decision" in t][0]
        self.assertIn("Promote PR #1 to main?", body)
        self.assertIn("Recommended: yes", body)
        self.assertIn("18:00", body)
        c = self.check()
        self.assertEqual(c.returncode, 0, c.stderr)
        beats = [b for _, t, b in NtfyRecorder.posts if "watching" in b]
        self.assertTrue(any("R900 blocked" in b for b in beats), beats)
        r2 = subprocess.run([PY, str(ROOT / "vigil.py"), "blocked", "R900",
                             "--clear"], env=self.env(),
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertNotIn("blocked", json.loads(
            (self.state / "claims" / "R900.json").read_text()))

    def test_ask_reaches_the_owner(self):
        r = subprocess.run([PY, str(ROOT / "vigil.py"), "ask", "Ledger is empty.",
                            "Backlog has 2 parked items. Want anything started?"],
                           env=self.env(), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("session has a question" in t
                            for _, t, _ in NtfyRecorder.posts))
        self.assertTrue(any("Ledger is empty" in b for _, _, b in NtfyRecorder.posts))

    def test_source_parse_failure_alerts_not_silent(self):
        self.ledger.write_text("| broken | row |\n")
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any("read the work list" in t
                            for _, t, _ in NtfyRecorder.posts))


if __name__ == "__main__":
    unittest.main(verbosity=2)
