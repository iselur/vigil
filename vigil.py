#!/usr/bin/env python3
"""vigil — the outer loop for agent sessions.

Detects open ledger work whose owning Claude/Codex session died, alerts, and
resumes the session under a strict budget. Level-triggered: every check
re-derives the world from current state and acts on the diff.

Layout: pure decision core (decide) surrounded by thin I/O adapters.
State: ~/.local/state/vigil   Config: ~/.config/vigil
"""

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

STATE = Path(os.environ.get("VIGIL_STATE", "~/.local/state/vigil")).expanduser()
CONFIG = Path(os.environ.get("VIGIL_CONFIG", "~/.config/vigil")).expanduser()
CLAUDE_BIN = os.environ.get("VIGIL_CLAUDE", "claude")
CODEX_BIN = os.environ.get("VIGIL_CODEX", "codex")
TMUX_BIN = os.environ.get("VIGIL_TMUX", "tmux")

ENTRY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
COLD_START_S = 300
CYCLE_S = 3600
MAX_STRIKES = 2
MAX_STARTS = 2   # attempts to START work on a row nobody ever claimed
MIN_FREE_KB = int(os.environ.get("VIGIL_MIN_FREE_KB", str(700 * 1024)))

ALIVE, DEAD, UNKNOWN = "alive", "dead", "unknown"


def fault(point):
    # crash-injection seam for the fault-injection suite
    if os.environ.get("VIGIL_FAULT") == point:
        sys.exit(41)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---------- process identity ----------

def proc_starttime(pid):
    """starttime (field 22 of /proc/pid/stat) or None if no such process."""
    try:
        stat = Path("/proc/%d/stat" % pid).read_text()
    except OSError:
        return None
    try:
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (IndexError, ValueError):
        return None


def generation_alive(pid, starttime):
    st = proc_starttime(pid)
    if st is None:
        return DEAD
    return ALIVE if st == starttime else DEAD  # differing starttime = PID reuse


def scan_proc_cmdlines():
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            raw = (p / "cmdline").read_bytes()
        except OSError:
            continue
        if raw:
            yield int(p.name), raw.decode("utf-8", "replace").split("\0")


# ---------- vendor liveness (tri-state; failure is UNKNOWN, never DEAD) ----------

def claude_registry_liveness(session_id):
    try:
        out = subprocess.run([CLAUDE_BIN, "agents", "--json"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return UNKNOWN
        blob = out.stdout
        json.loads(blob)  # malformed registry => UNKNOWN via except
    except Exception:
        return UNKNOWN
    return ALIVE if session_id and session_id in blob else DEAD


def codex_proc_liveness(session_id):
    try:
        for _pid, argv in scan_proc_cmdlines():
            joined = " ".join(argv)
            if "codex" in joined and session_id and session_id in argv:
                return ALIVE
        return DEAD
    except Exception:
        return UNKNOWN


def liveness(claim):
    """Combined tri-state. DEAD only when generation AND vendor signal agree."""
    gen = generation_alive(claim["pid"], claim["starttime"])
    if gen == ALIVE:
        return ALIVE
    vendor = claim.get("vendor")
    if vendor == "claude":
        ven = claude_registry_liveness(claim.get("session"))
    elif vendor == "codex":
        ven = codex_proc_liveness(claim.get("session"))
    else:
        ven = UNKNOWN
    if ven == ALIVE:
        return ALIVE
    if ven == UNKNOWN:
        return UNKNOWN
    return DEAD


# ---------- state files ----------

def read_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    p = Path(path)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1, sort_keys=True))
    tmp.replace(p)


def claim_lock_path(entry):
    """Return Vigil's one stable private lock path for a validated entry."""
    if not isinstance(entry, str) or not ENTRY_RE.fullmatch(entry):
        raise ValueError("invalid entry id")
    return STATE / "claim-locks" / (entry + ".lock")


@contextmanager
def entry_lock(entry):
    """Serialize claim replacement and guarded consumers for one entry."""
    path = claim_lock_path(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    with os.fdopen(fd, "r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def claim_path(entry):
    if not isinstance(entry, str) or not ENTRY_RE.fullmatch(entry):
        raise ValueError("invalid entry id")
    return claims_dir() / (entry + ".json")


def load_claim_strict(entry, session):
    """Reload the current claim under the caller's already-held entry lock."""
    if not isinstance(session, str) or not session:
        raise ValueError("invalid session")
    path = claim_path(entry)
    try:
        claim = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("invalid claim") from exc
    if not isinstance(claim, dict) or claim.get("entry") != entry:
        raise ValueError("invalid claim")
    if claim.get("session") != session:
        raise ValueError("claim session mismatch")
    if claim.get("vendor") not in ("claude", "codex"):
        raise ValueError("invalid claim vendor")
    if (not isinstance(claim.get("workdir"), str) or
            not claim["workdir"] or
            isinstance(claim.get("generation"), bool) or
            not isinstance(claim.get("generation"), int) or
            claim["generation"] <= 0):
        raise ValueError("invalid claim identity")
    pid = claim.get("pid")
    starttime = claim.get("starttime")
    if (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or
            isinstance(starttime, bool) or not isinstance(starttime, int) or
            starttime < 0 or proc_starttime(pid) != starttime):
        raise ValueError("claim process generation mismatch")
    return claim


CLAIM_IDENTITY_FIELDS = ("entry", "session", "vendor", "pid", "starttime",
                         "generation")


def claim_identity_matches(left, right):
    return (isinstance(left, dict) and isinstance(right, dict) and
            all(left.get(key) == right.get(key)
                for key in CLAIM_IDENTITY_FIELDS))


def intent_identity_matches(claim, intent):
    if not isinstance(claim, dict):
        return False
    if any(not intent.get(key) for key in CLAIM_IDENTITY_FIELDS):
        return False
    return all(str(claim.get(key)) == intent.get(key)
               for key in CLAIM_IDENTITY_FIELDS)


def claims_dir():
    d = STATE / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_claims():
    out = {}
    for f in claims_dir().glob("*.json"):
        c = read_json(f, None)
        if c and ENTRY_RE.match(c.get("entry", "")):
            out[c["entry"]] = c
    return out


def incidents_path():
    STATE.mkdir(parents=True, exist_ok=True)
    return STATE / "incidents.log"


def append_incident(**kv):
    parts = [now_iso()] + ["%s=%s" % (k, str(v).replace(" ", "_"))
                           for k, v in kv.items()]
    with open(incidents_path(), "a") as f:
        f.write(" ".join(parts) + "\n")
        f.flush()
        os.fsync(f.fileno())


def parse_incidents():
    """Return (strikes per entry since last reset, dangling intents)."""
    strikes, intents = {}, {}
    try:
        lines = incidents_path().read_text().splitlines()
    except OSError:
        lines = []
    for ln in lines:
        kv = dict(p.split("=", 1) for p in ln.split()[1:] if "=" in p)
        ev, entry = kv.get("event"), kv.get("entry")
        if not entry:
            continue
        if ev == "intent":
            strikes[entry] = strikes.get(entry, 0) + 1
            intents[kv.get("attempt")] = kv
        elif ev in ("commit", "fail") and kv.get("attempt") in intents:
            del intents[kv["attempt"]]
        elif ev == "reset":
            strikes[entry] = 0
    return strikes, list(intents.values())


# ---------- sources ----------

def load_sources():
    return read_json(CONFIG / "sources.json", [])


def parse_ledger_md(text):
    """Markdown-table ledger -> [(entry_id, status)]. Raises on malformed rows."""
    rows = []
    for ln in text.splitlines():
        if not ln.startswith("|") or ln.startswith("| id") or set(ln) <= {"|", "-", " "}:
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < 6:
            raise ValueError("malformed ledger row: %s" % ln[:80])
        rows.append((cells[0], cells[5].lower()))
    return rows


def open_entries():
    """[(entry, source_dict)] from all sources; raises SourceError per file."""
    out, errors = [], []
    for src in load_sources():
        try:
            with tempfile.NamedTemporaryFile(suffix=".snap", delete=False) as tmp:
                shutil.copyfile(src["path"], tmp.name)
                text = Path(tmp.name).read_text()
            os.unlink(tmp.name)
            for entry, status in parse_ledger_md(text):
                if status == "open":
                    if not ENTRY_RE.match(entry):
                        raise ValueError("bad entry id: %r" % entry[:40])
                    out.append((entry, src))
        except (OSError, ValueError) as e:
            errors.append((src.get("name", "?"), str(e)))
    return out, errors


# ---------- alerting ----------

def ntfy_url():
    env = read_json(CONFIG / "alert.json", None)
    if env:
        return env.get("url")
    try:
        for ln in (CONFIG / "alert.env").read_text().splitlines():
            if ln.startswith("NTFY_TOPIC="):
                return "https://ntfy.sh/" + ln.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def alert(title, msg, require_ack=False):
    """Publish; on failure persist to pending. Returns True on server ack."""
    url = os.environ.get("VIGIL_NTFY") or ntfy_url()
    ok = False
    if url:
        for _ in range(2):
            try:
                req = urllib.request.Request(url, data=msg.encode(),
                                             headers={"Title": title})
                with urllib.request.urlopen(req, timeout=10) as r:
                    ok = 200 <= r.status < 300
                if ok:
                    break
            except Exception:
                time.sleep(1)
    if not ok:
        with open(STATE / "alerts-pending.log", "a") as f:
            f.write("%s %s | %s\n" % (now_iso(), title, msg))
    return ok


def replay_pending_alerts():
    p = STATE / "alerts-pending.log"
    try:
        lines = p.read_text().splitlines()
    except OSError:
        return
    if not lines:
        return
    p.unlink()
    for ln in lines:
        title, _, msg = ln.partition(" | ")
        alert("(missed earlier) " + title, msg)


# ---------- the pure decision core (mutation-campaign target) ----------

def decide(entries, claims, live, strikes, notified, now, mem_ok, starts=None):
    """Pure. No I/O.

    entries: [entry_id]                     claims: {entry: claim_dict}
    live: {entry: alive|dead|unknown}       strikes: {entry: int}
    notified: {entry: last_alerted_state}   now: epoch seconds
    mem_ok: bool

    Returns {"states": {entry: state}, "alerts": [(entry, state, message)],
             "recover": entry_or_None, "notified": new_notified}
    """
    states, alerts = {}, []
    starts = starts or {}
    recover = None
    start = None
    new_notified = dict(notified)
    for entry in sorted(entries):
        claim = claims.get(entry)
        if claim is None:
            state = "unclaimed"
        elif now - claim.get("created_epoch", 0) < COLD_START_S:
            state = "healthy"  # cold-start grace: never act on a fresh claim
        else:
            lv = live.get(entry, UNKNOWN)
            if lv == ALIVE:
                state = "blocked" if claim.get("blocked") else "healthy"
            elif lv == UNKNOWN:
                state = "unknown"
            elif strikes.get(entry, 0) >= MAX_STRIKES:
                state = "quarantined"
            else:
                state = "orphaned"
        states[entry] = state
        quiet = state == "unclaimed" and starts.get(entry, 0) < MAX_STARTS
        if state != notified.get(entry, "healthy") and state != "healthy" and not quiet:
            alerts.append((entry, state, _alert_text(entry, state, strikes)))
        if state == "healthy" or quiet:
            new_notified.pop(entry, None)
        else:
            new_notified[entry] = state
        # An unclaimed row is work nobody ever picked up. Reporting it to the owner asks
        # him to be the scheduler; vigil already knows how to launch a session, it just had
        # no verb for "never claimed" — only "claimed, then died". Start it.
        if state == "unclaimed" and start is None and mem_ok:
            if starts.get(entry, 0) < MAX_STARTS:
                start = entry
        if state == "orphaned" and recover is None:
            if mem_ok:
                recover = entry
            else:
                alerts.append((entry, "memory-low",
                               "The session working on %s died, but the machine "
                               "is low on memory, so I'm waiting instead of "
                               "restarting it." % entry))
    return {"states": states, "alerts": alerts, "recover": recover,
            "start": start, "notified": new_notified}


def _alert_text(entry, state, strikes):
    if state == "unclaimed":
        return ("%s is open in the ledger and no session picked it up. I tried to start "
                "one %d times and it never claimed the row, so it needs a look."
                % (entry, MAX_STARTS))
    if state == "unknown":
        return ("I can't tell whether the session working on %s is still alive "
                "— the check itself failed, so the session may be fine. Worth "
                "a look." % entry)
    if state == "blocked":
        return ("%s is waiting on a decision from you — details were sent when "
                "it blocked; `vigil status` shows the ask." % entry)
    if state == "quarantined":
        return ("The session working on %s died %d times, so I've stopped "
                "retrying. When you're ready: vigil reset %s"
                % (entry, strikes.get(entry, 0), entry))
    return "The session working on %s died — restarting it now." % entry


# ---------- recovery ----------

def _claude_transcript_ok(session_id):
    for f in Path("~/.claude/projects").expanduser().glob("*/%s.jsonl" % session_id):
        try:
            with open(f, "rb") as fh:
                fh.seek(max(0, os.path.getsize(f) - 65536))
                tail = fh.read().splitlines()
            for ln in reversed(tail[1:]):
                if ln.strip():
                    json.loads(ln)
                    return True
        except (OSError, ValueError):
            return False
    return False


def _codex_thread_ok(session_id):
    import sqlite3
    db = Path("~/.codex/state_5.sqlite").expanduser()
    if not db.exists():
        return False
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
        row = con.execute("SELECT 1 FROM threads WHERE id LIKE ?",
                          ("%%%s%%" % session_id,)).fetchone()
        con.close()
        return row is not None
    except sqlite3.Error:
        return False


def preflight(claim):
    if claim["vendor"] == "claude":
        return _claude_transcript_ok(claim["session"])
    if claim["vendor"] == "codex":
        return _codex_thread_ok(claim["session"])
    return False


def resume_argv(claim, prompt):
    entry = claim["entry"]
    policy = claim.get("policy", {})
    workdir = claim.get("workdir") or str(Path.home())
    tmux_name = "vigil-%s" % entry
    if claim["vendor"] == "claude":
        inner = [CLAUDE_BIN, "--resume", claim["session"],
                 "--permission-mode", policy.get("permission-mode", "default"),
                 prompt]
    else:
        # codex requires flags BEFORE the `resume` subcommand (verified live)
        inner = [CODEX_BIN, "exec"]
        sandbox = policy.get("codex-sandbox")
        if sandbox in ("read-only", "workspace-write", "danger-full-access"):
            inner += ["--sandbox", sandbox]
        if policy.get("codex-bypass") == "true":
            inner += ["--dangerously-bypass-approvals-and-sandbox"]
        inner += ["resume", claim["session"], prompt]
    return [TMUX_BIN, "new-session", "-d", "-s", tmux_name, "-c", workdir,
            "--"] + inner


def find_resumed(claim, deadline_s=20):
    """Locate the freshly launched process; return (pid, starttime) or None."""
    key = claim["session"]
    end = time.time() + deadline_s
    while time.time() < end:
        for pid, argv in scan_proc_cmdlines():
            if key in argv and ("--resume" in argv or "resume" in argv):
                st = proc_starttime(pid)
                if st is not None:
                    return pid, st
        time.sleep(1)
    return None


def build_prompt(claim, strikes):
    tail = []
    try:
        for ln in incidents_path().read_text().splitlines():
            if "entry=%s" % claim["entry"] in ln:
                tail.append(ln)
    except OSError:
        pass
    pending = ""
    if claim.get("blocked"):
        pending = ("Pending owner ask you had raised: %s\n"
                   % claim["blocked"]["ask"])
    return (
        "vigil auto-resume: your session owned open work '%s' and was found dead. "
        "Strike %d of %d. Recovery is at-least-once: reconcile observed state "
        "(files, PRs, running units) before repeating any action not confirmed in "
        "your transcript. Recent incidents:\n%s\n%s"
        "Re-claim with: vigil claim %s --session <your-session-id> --vendor %s, "
        "then continue the work."
        % (claim["entry"], strikes.get(claim["entry"], 0) + 1, MAX_STRIKES,
           "\n".join(tail[-2:]) or "(none)", pending, claim["entry"],
           claim["vendor"])
    )


def count_starts():
    """How many times vigil has already tried to START each entry."""
    counts = {}
    try:
        for ln in incidents_path().read_text().splitlines():
            if "event=start" not in ln:
                continue
            for field in ln.split():
                if field.startswith("entry="):
                    key = field.split("=", 1)[1]
                    counts[key] = counts.get(key, 0) + 1
    except OSError:
        pass
    return counts


def selected_start_vendor():
    """Configured vendor for new, unclaimed work; invalid or absent is disabled."""
    try:
        vendor = (CONFIG / "start-vendor").read_text().strip()
    except OSError:
        return None
    return vendor if vendor in ("claude", "codex") else None


def start_argv(entry, workdir, vendor):
    prompt = (
        "vigil: ledger row %s is open and no session ever claimed it. Read it in the ledger, "
        "claim it with `vigil claim %s --session <your-session-id> --vendor %s`, then do "
        "the work. Reconcile observed state first (files, PRs, running units) — another "
        "session may have done part of it without claiming. If the row turns out to be "
        "already finished, close it with evidence instead of redoing it."
        % (entry, entry, vendor))
    if vendor == "codex":
        inner = [CODEX_BIN, "-m", "gpt-5.6-sol", "-c",
                 "model_reasoning_effort=high", "--sandbox", "danger-full-access",
                 "-a", "never", prompt]
    elif vendor == "claude":
        inner = [CLAUDE_BIN, "--permission-mode", "default", prompt]
    else:
        raise ValueError("unsupported start vendor")
    return [TMUX_BIN, "new-session", "-d", "-s", "vigil-start-%s" % entry,
            "-c", workdir, "--"] + inner


def start_work(entry, workdir, starts):
    """Launch a session on a ledger row nobody ever claimed.

    Distinct from recover(): there is no session to resume and no claim to read a vendor or
    policy from, so this starts a fresh one and tells it to claim the row itself. Bounded by
    MAX_STARTS so a row that never claims escalates to the owner instead of respawning hourly.
    """
    vendor = selected_start_vendor()
    if vendor is None:
        append_incident(event="fail", entry=entry,
                        why="start_vendor_unconfigured")
        return False
    workdir = workdir or str(Path.home())
    attempt = uuid.uuid4().hex[:12]
    append_incident(event="start", attempt=attempt, entry=entry,
                    n=starts.get(entry, 0) + 1, vendor=vendor)
    argv = start_argv(entry, workdir, vendor)
    try:
        subprocess.run(argv, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        append_incident(event="fail", attempt=attempt, entry=entry,
                        why=str(exc)[:80].replace(" ", "_"))
        return False
    return True


def recover(entry, claim, strikes):
    attempt = uuid.uuid4().hex[:12]
    append_incident(event="intent", attempt=attempt, entry=entry,
                    strikes=strikes.get(entry, 0) + 1, session=claim["session"],
                    vendor=claim["vendor"], pid=claim["pid"],
                    starttime=claim["starttime"], generation=claim["generation"])
    fault("post-intent")
    if not preflight(claim):
        append_incident(event="fail", attempt=attempt, entry=entry,
                        note="preflight:continuity-unprovable")
        alert("%s can't be restored" % entry,
              "The session working on %s died, and its saved transcript can't "
              "prove a safe restart — so I won't try. This one needs you."
              % entry)
        return False
    alert("Restarting work on %s" % entry,
          "The session working on %s died. I'm restarting it now "
          "(attempt %d of %d)."
          % (entry, strikes.get(entry, 0) + 1, MAX_STRIKES),
          require_ack=True)
    fault("post-alert")
    prompt = build_prompt(claim, strikes)
    argv = resume_argv(claim, prompt)
    try:
        subprocess.run(argv, check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, OSError) as e:
        append_incident(event="fail", attempt=attempt, entry=entry,
                        note="launch:%s" % type(e).__name__)
        return False
    fault("post-launch")
    found = find_resumed(claim)
    if not found:
        append_incident(event="fail", attempt=attempt, entry=entry,
                        note="verify:process-not-found")
        return False
    pid, st = found
    fault("pre-commit")
    with entry_lock(entry):
        current = read_json(claim_path(entry), None)
        if not claim_identity_matches(current, claim):
            append_incident(event="fail", attempt=attempt, entry=entry,
                            note="commit:claim-changed")
            return False
        newclaim = dict(current, pid=pid, starttime=st,
                        generation=current.get("generation", 1) + 1,
                        created=now_iso(), created_epoch=time.time())
        write_json(claim_path(entry), newclaim)
    append_incident(event="commit", attempt=attempt, entry=entry, pid=pid,
                    starttime=st, generation=newclaim["generation"])
    return True


def reconcile():
    """Close out dangling intents from a crashed prior recovery."""
    _, dangling = parse_incidents()
    for kv in dangling:
        entry, attempt = kv.get("entry"), kv.get("attempt")
        if not ENTRY_RE.fullmatch(entry or ""):
            append_incident(event="fail", attempt=attempt, entry=entry,
                            note="reconciled:invalid-entry")
            continue
        with entry_lock(entry):
            claim = read_json(claim_path(entry), None)
            if not intent_identity_matches(claim, kv):
                append_incident(event="fail", attempt=attempt, entry=entry,
                                note="reconciled:claim-identity-mismatch")
                continue
            found = find_resumed(claim, deadline_s=1) if claim else None
            if found:
                pid, st = found
                newclaim = dict(claim, pid=pid, starttime=st,
                                generation=claim.get("generation", 1) + 1,
                                created=now_iso(), created_epoch=time.time())
                write_json(claim_path(entry), newclaim)
                append_incident(event="commit", attempt=attempt, entry=entry, pid=pid,
                                starttime=st, note="reconciled")
            else:
                append_incident(event="fail", attempt=attempt, entry=entry,
                                note="reconciled:no-process")


# ---------- commands ----------

def mem_ok():
    try:
        for ln in Path("/proc/meminfo").read_text().splitlines():
            if ln.startswith("MemAvailable:"):
                return int(ln.split()[1]) >= MIN_FREE_KB
    except (OSError, ValueError):
        pass
    return True


def cmd_check():
    STATE.mkdir(parents=True, exist_ok=True)
    lock = open(STATE / "lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("vigil: another check holds the lock; skipping")
        return 0
    try:
        replay_pending_alerts()
        reconcile()
        entries_src, errors = open_entries()
        notified = read_json(STATE / "notified.json", {})
        for name, err in errors:
            key = "_source:%s" % name
            if notified.get(key) != "error":
                alert("Can't read the work list",
                      "I can't read the '%s' ledger, so I can't see what work "
                      "is open until it's fixed. (%s)" % (name, err))
                notified[key] = "error"
        if not errors:
            for k in [k for k in notified if k.startswith("_source:")]:
                del notified[k]
        claims = load_claims()
        strikes, _ = parse_incidents()
        starts = count_starts()
        entries = [e for e, _ in entries_src]
        workdirs = {e: s.get("workdir") for e, s in entries_src}
        live = {e: liveness(claims[e]) for e in entries if e in claims}
        d = decide(entries, claims, live, strikes, notified, time.time(), mem_ok(),
                   starts=starts)
        titles = {"unclaimed": "%s has no one on it",
                  "unknown": "Can't check on %s",
                  "quarantined": "%s needs you",
                  "memory-low": "%s is waiting"}
        for entry, state, msg in d["alerts"]:
            if state != "orphaned":  # recovery announces itself with ack inside recover()
                alert(titles.get(state, "%s: " + state) % entry, msg)
        if d["start"]:
            start_work(d["start"], workdirs.get(d["start"]), starts)
        if d["recover"]:
            claim = dict(claims[d["recover"]])
            claim.setdefault("workdir", workdirs.get(d["recover"]))
            recover(d["recover"], claim, strikes)
        write_json(STATE / "notified.json", d["notified"])
        (STATE / "last-check").write_text(now_iso())
        maybe_heartbeat(d["states"])
        return 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def maybe_heartbeat(states):
    """Once a day, prove the quiet is deliberate: send an all-clear."""
    hours = float(os.environ.get("VIGIL_HEARTBEAT_H", "24"))
    if hours <= 0:
        return
    stamp = STATE / "last-heartbeat"
    try:
        if time.time() - stamp.stat().st_mtime < hours * 3600:
            return
    except OSError:
        pass
    if not states:
        body = "Nothing is open in the watched ledgers right now."
    else:
        healthy = sorted(e for e, s in states.items() if s == "healthy")
        other = sorted((e, s) for e, s in states.items() if s != "healthy")
        parts = []
        if healthy:
            parts.append("%s healthy" % ", ".join(healthy))
        parts += ["%s %s" % (e, s) for e, s in other]
        body = ("Daily check-in — watching %d %s: %s. Quiet in between means "
                "all is well." % (len(states),
                                  "entry" if len(states) == 1 else "entries",
                                  "; ".join(parts)))
    if alert("All quiet" if all(s == "healthy" for s in states.values())
             else "Daily check-in", body):
        stamp.touch()


def cmd_selfcheck():
    try:
        age = time.time() - (STATE / "last-check").stat().st_mtime
    except OSError:
        age = float("inf")
    if age > 2 * CYCLE_S + 600:
        notified = read_json(STATE / "notified.json", {})
        if notified.get("_selfcheck") != "stale":
            alert("The watchdog stopped",
                  "No checks have completed for %d hours — the watchdog itself "
                  "needs attention." % int(age // 3600))
            notified["_selfcheck"] = "stale"
            write_json(STATE / "notified.json", notified)
    else:
        notified = read_json(STATE / "notified.json", {})
        if notified.pop("_selfcheck", None):
            write_json(STATE / "notified.json", notified)
    return 0


def _agent_vendor(argv):
    if not argv or not argv[0]:
        return None
    base = os.path.basename(argv[0])
    if base in ("claude", "claude.exe"):
        return "claude"
    if base in ("codex", "codex.exe"):
        return "codex"
    return None


def _find_agent_process():
    pid = os.getppid()
    for _ in range(15):
        if pid <= 1:
            break
        try:
            argv = Path("/proc/%d/cmdline" % pid).read_bytes().decode(
                "utf-8", "replace").split("\0")
        except OSError:
            break
        vendor = _agent_vendor(argv)
        if vendor:
            return pid, proc_starttime(pid), vendor
        try:
            stat = Path("/proc/%d/stat" % pid).read_text()
            pid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return None


def _find_agent_pid():
    found = _find_agent_process()
    return found[0] if found else None


def cmd_guard(argv):
    """Run a consumer with the locked, current claim in VIGIL_CLAIM_JSON."""
    import argparse
    if "--" not in argv:
        print("vigil: guard requires `-- <consumer argv>`", file=sys.stderr)
        return 2
    split = argv.index("--")
    guard_argv, consumer = argv[:split], argv[split + 1:]
    if not consumer:
        print("vigil: guard requires a consumer command", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(prog="vigil guard")
    ap.add_argument("entry")
    ap.add_argument("--session", required=True)
    try:
        args = ap.parse_args(guard_argv)
    except SystemExit as exc:
        return int(exc.code)
    if not ENTRY_RE.fullmatch(args.entry):
        print("vigil: invalid entry id", file=sys.stderr)
        return 2
    try:
        with entry_lock(args.entry):
            actor = _find_agent_process()
            if actor is None:
                raise ValueError("cannot locate Codex or Claude ancestor")
            pid, starttime, vendor = actor
            claim = load_claim_strict(args.entry, args.session)
            if claim["vendor"] != vendor or claim["pid"] != pid or \
                    claim["starttime"] != starttime:
                raise ValueError("claim does not own invoking agent generation")
            env = os.environ.copy()
            env["VIGIL_CLAIM_JSON"] = json.dumps(
                claim, sort_keys=True, separators=(",", ":"))
            result = subprocess.run(consumer, env=env)
    except (OSError, ValueError) as exc:
        print("vigil: guard refused — %s" % exc, file=sys.stderr)
        return 2
    if result.returncode < 0:
        os.kill(os.getpid(), -result.returncode)
        return 128 + (-result.returncode)
    return result.returncode


def cmd_claim(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="vigil claim")
    ap.add_argument("entry")
    ap.add_argument("--session", required=True)
    ap.add_argument("--vendor", required=True, choices=["claude", "codex"])
    ap.add_argument("--pid", type=int)
    ap.add_argument("--workdir")
    ap.add_argument("--policy", action="append", default=[],
                    help="k=v, e.g. permission-mode=bypassPermissions")
    a = ap.parse_args(argv)
    if not ENTRY_RE.fullmatch(a.entry):
        print("vigil: invalid entry id", file=sys.stderr)
        return 2
    pid = a.pid or _find_agent_pid()
    if pid is None:
        print("vigil: cannot locate agent process; pass --pid", file=sys.stderr)
        return 2
    st = proc_starttime(pid)
    if st is None:
        print("vigil: pid %d not alive" % pid, file=sys.stderr)
        return 2
    with entry_lock(a.entry):
        old = read_json(claim_path(a.entry), {})
        claim = {"entry": a.entry, "session": a.session, "vendor": a.vendor,
                 "pid": pid, "starttime": st,
                 "generation": old.get("generation", 0) + 1,
                 "policy": dict(kv.split("=", 1) for kv in a.policy if "=" in kv),
                 "workdir": a.workdir or os.getcwd(),
                 "created": now_iso(), "created_epoch": time.time()}
        write_json(claim_path(a.entry), claim)
    print("vigil: claimed %s (pid %d gen %d)" % (a.entry, pid, claim["generation"]))
    return 0


def cmd_beat(argv):
    entry = argv[0] if argv else ""
    p = claims_dir() / ("%s.json" % entry)
    if not ENTRY_RE.match(entry) or not p.exists():
        print("vigil: no claim for %r" % entry, file=sys.stderr)
        return 2
    os.utime(p)
    return 0


def cmd_blocked(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="vigil blocked")
    ap.add_argument("entry")
    ap.add_argument("ask", nargs="?", default="")
    ap.add_argument("--recommend", default="")
    ap.add_argument("--by", default="", help="deadline, e.g. 18:00 or 2026-08-09T18:00")
    ap.add_argument("--clear", action="store_true")
    a = ap.parse_args(argv)
    if not ENTRY_RE.fullmatch(a.entry):
        print("vigil: no claim for %r — claim it first" % a.entry, file=sys.stderr)
        return 2
    path = claim_path(a.entry)
    with entry_lock(a.entry):
        claim = read_json(path, None)
        if claim is None:
            print("vigil: no claim for %r — claim it first" % a.entry, file=sys.stderr)
            return 2
        if a.clear:
            claim.pop("blocked", None)
            write_json(path, claim)
        elif not a.ask:
            print("vigil: an ask is required (what decision do you need?)",
                  file=sys.stderr)
            return 2
        else:
            claim["blocked"] = {"ask": a.ask, "recommend": a.recommend, "by": a.by,
                                "created": now_iso()}
            write_json(path, claim)
    notified = read_json(STATE / "notified.json", {})
    if a.clear:
        notified.pop(a.entry, None)
        write_json(STATE / "notified.json", notified)
        append_incident(event="unblocked", entry=a.entry)
        print("vigil: %s unblocked" % a.entry)
        return 0
    append_incident(event="blocked", entry=a.entry)
    body = "%s is blocked on you: %s" % (a.entry, a.ask)
    if a.recommend:
        body += " Recommended: %s." % a.recommend
    if a.by:
        body += (" If there's no answer by %s, the session proceeds with the "
                 "recommendation." % a.by)
    alert("%s needs a decision" % a.entry, body)
    notified[a.entry] = "blocked"
    write_json(STATE / "notified.json", notified)
    print("vigil: %s marked blocked; owner alerted" % a.entry)
    return 0


def cmd_ask(argv):
    """A sanctioned channel for any session to put one question on the owner's phone."""
    text = " ".join(argv).strip()
    if not text:
        print("vigil: usage: vigil ask \"<question for the owner>\"", file=sys.stderr)
        return 2
    append_incident(event="ask", entry="-", note=text[:120])
    ok = alert("A session has a question", text)
    print("vigil: ask %s" % ("delivered" if ok else "recorded (delivery pending)"))
    return 0


def cmd_reset(argv):
    entry = argv[0] if argv else ""
    if not ENTRY_RE.match(entry):
        print("vigil: invalid entry id", file=sys.stderr)
        return 2
    append_incident(event="reset", entry=entry)
    notified = read_json(STATE / "notified.json", {})
    if notified.pop(entry, None) is not None:
        write_json(STATE / "notified.json", notified)
    print("vigil: reset %s (strikes back to 0)" % entry)
    return 0


def cmd_vendor(argv):
    path = CONFIG / "start-vendor"
    if not argv:
        print(selected_start_vendor() or "unset")
        return 0
    if len(argv) != 1 or argv[0] not in ("claude", "codex"):
        print("vigil: usage: vigil vendor [claude|codex]", file=sys.stderr)
        return 2
    CONFIG.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(argv[0] + "\n")
    tmp.replace(path)
    print("vigil: new unclaimed work will start with %s" % argv[0])
    return 0


def cmd_status():
    entries_src, errors = open_entries()
    claims = load_claims()
    strikes, dangling = parse_incidents()
    print("open entries: %d   claims: %d   dangling intents: %d"
          % (len(entries_src), len(claims), len(dangling)))
    for e, _src in entries_src:
        c = claims.get(e)
        lv = liveness(c) if c else "-"
        print("  %-12s claim=%-5s live=%-7s strikes=%d"
              % (e, "yes" if c else "no", lv, strikes.get(e, 0)))
        if c and c.get("blocked"):
            b = c["blocked"]
            print("      blocked on you: %s%s%s" % (
                b["ask"],
                " — recommended: %s" % b["recommend"] if b.get("recommend") else "",
                " — deadline: %s" % b["by"] if b.get("by") else ""))
    for name, err in errors:
        print("  SOURCE ERROR %s: %s" % (name, err))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    rest = sys.argv[2:]
    if cmd == "check":
        return cmd_check()
    if cmd == "selfcheck":
        return cmd_selfcheck()
    if cmd == "claim":
        return cmd_claim(rest)
    if cmd == "guard":
        return cmd_guard(rest)
    if cmd == "beat":
        return cmd_beat(rest)
    if cmd == "blocked":
        return cmd_blocked(rest)
    if cmd == "ask":
        return cmd_ask(rest)
    if cmd == "reset":
        return cmd_reset(rest)
    if cmd == "vendor":
        return cmd_vendor(rest)
    if cmd == "status":
        return cmd_status()
    print("usage: vigil [check|selfcheck|claim|guard|beat|blocked|ask|reset|vendor|status]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
