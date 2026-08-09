# vigil

The outer loop for agent sessions. Your worker→reviewer harness corrects the *work*;
vigil corrects the *workers*: it detects open ledger entries whose owning Claude Code or
Codex CLI session died, alerts your phone, and resumes the session — twice, then it
quarantines and waits for you.

One Python file, stdlib only. One hourly timer. No daemon.

## How it works

- **Claim**: a session takes a work entry with `vigil claim R122 --session <id> --vendor
  claude` — recording pid + `/proc` start-time (exact process generation, immune to PID
  reuse) and its launch policy, which a resume replays verbatim (never elevated).
- **Check** (hourly + on session start): level-triggered — re-derives the world from
  files and acts on the diff. Death requires the process generation AND the vendor
  signal (`claude agents --json` / codex proc scan) to agree; observation failure is
  UNKNOWN, which alerts and never resumes.
- **Recover**: write-ahead intent → continuity preflight (transcript/thread must prove
  resumable) → alert (server-acked) → argv-vector launch in tmux → verify the new
  process → commit the new claim generation. A crashed recovery reconciles on the next
  check instead of double-launching. Strikes are spent at intent time, so failed
  launches consume the budget too. Two strikes, then quarantine until `vigil reset`.
- **Watched watchdog**: `vigil selfcheck` on an independent cron alerts if checks stop.
- **Daily heartbeat**: once a day, one "all quiet" note listing what's watched — so
  silence is provably deliberate. `VIGIL_HEARTBEAT_H=0` disables, or set another cadence.

## Commands

    vigil check | selfcheck | claim | beat | reset | status

## Enforcement

19-test suite: effect-level kill-test against fake vendor binaries and a fake ntfy
server, crash injection at every intent/launch/commit boundary, lock contention,
UNKNOWN-vs-DEAD separation. Mutation campaign on the pure decision core: 10/10 mutants
caught. Live kill/resume verified against real Claude Code and Codex CLI sessions.

## Setup

- `~/.config/vigil/sources.json` — work lists to watch (markdown-table ledgers).
- `~/.config/vigil/alert.env` — `NTFY_TOPIC=<topic>`; subscribe in the ntfy app.
  **The topic name is a secret** — anyone who knows it can read and send your
  notifications. Generate a long random one and keep it out of your repos.
- systemd user timer runs `vigil check` hourly; a cron line runs `vigil selfcheck`.

Recovery is at-least-once: a resumed session is told to reconcile observed state before
repeating anything unconfirmed. Alert delivery is best-effort (server-acked, retried,
persisted on failure); the record in `incidents.log` is the guarantee.
