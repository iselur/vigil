#!/usr/bin/env python3
"""Mutation campaign for vigil.decide() and its helpers.

Rules honored (owner's global CLAUDE.md):
- backup + restore in finally AND on SIGTERM/SIGINT
- every mutant asserted to match exactly once before applying
- __pycache__ purged before each mutant and on restore
- digest verified after restore
"""

import hashlib
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "vigil.py"
BACKUP = ROOT / "vigil.py.grillbak"

MUTANTS = [
    ("cold-start boundary", "< COLD_START_S", "<= COLD_START_S"),
    ("strike budget boundary", ">= MAX_STRIKES", "> MAX_STRIKES"),
    ("alive inverted", "if lv == ALIVE:", "if lv != ALIVE:"),
    ("alert dedupe deleted",
     'if state != notified.get(entry, "healthy") and state != "healthy":',
     'if state != "healthy":'),
    ("one-recovery cap deleted",
     'if state == "orphaned" and recover is None:',
     'if state == "orphaned":'),
    ("memory gate deleted", "if mem_ok:\n                recover = entry",
     "if True:\n                recover = entry"),
    ("healthy no longer clears notified",
     'new_notified.pop(entry, None)', 'pass'),
    ("recovery never selected", "recover = entry", "recover = entry if False else None"),
    ("deterministic order dropped", "for entry in sorted(entries):",
     "for entry in entries:"),
    ("quarantine collapses to orphaned",
     'state = "quarantined"', 'state = "orphaned"'),
    ("blocked collapses to healthy",
     'state = "blocked" if claim.get("blocked") else "healthy"',
     'state = "healthy"'),
]


def purge_pycache():
    for d in ROOT.rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def digest(p):
    return hashlib.md5(Path(p).read_bytes()).hexdigest()


def restore(*_a):
    if BACKUP.exists():
        shutil.copyfile(BACKUP, TARGET)
    purge_pycache()


def main():
    canon = digest(TARGET)
    shutil.copyfile(TARGET, BACKUP)
    signal.signal(signal.SIGTERM, lambda *a: (restore(), sys.exit(143)))
    signal.signal(signal.SIGINT, lambda *a: (restore(), sys.exit(130)))
    survivors = []
    try:
        src = TARGET.read_text()
        for name, old, new in MUTANTS:
            n = src.count(old)
            if n != 1:
                print("SKIP (pattern x%d): %s" % (n, name))
                survivors.append(("PATTERN-ERROR", name))
                continue
            purge_pycache()
            TARGET.write_text(src.replace(old, new))
            r = subprocess.run([sys.executable, "-u", "-m", "unittest",
                                "discover", "-s", str(ROOT / "tests")],
                               capture_output=True, text=True, timeout=600,
                               cwd=str(ROOT))
            caught = r.returncode != 0
            print("%s: %s" % ("CAUGHT" if caught else "SURVIVED", name))
            if not caught:
                survivors.append(("SURVIVED", name))
            TARGET.write_text(src)
            purge_pycache()
    finally:
        restore()
        BACKUP.unlink(missing_ok=True)
    assert digest(TARGET) == canon, "RESTORE FAILED — tree is dirty!"
    print("restore verified (md5 %s)" % canon[:12])
    print("survivors: %d" % len(survivors))
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
