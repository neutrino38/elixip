# DESIGN-ELIXIPP.md — the elixipp test tool

The as-built design of **elixipp**, the standalone SIP test tool: a sipp
replacement that runs FSL scenarios, drives a media server, and can act as a
client or as a server. It is one of the two artifacts built from this repo — the
other is [kelixip](DESIGN-KELIXIP.md).

The tool is `apps/elixipp` (the escript and its CLI) plus the scenario-engine
support that stays in the shared library because the language needs it —
`apps/elixip2/lib/elixipp/` (the live monitor and the UAS factory).

Using the tool — options, examples, certificates — is
[ELIXIPP.md](../../ELIXIPP.md). Below it,
[DESIGN-FSL.md](DESIGN-FSL.md), [DESIGN-FRAMEWORK.md](DESIGN-FRAMEWORK.md) and
[DESIGN-SIPSTACK.md](DESIGN-SIPSTACK.md).

---

## 1. What the tool adds to the engine

The FSL engine runs one scenario instance in one process and knows nothing about
terminals, quotas or call rates. Everything elixipp adds is around that:

| Concern | Where |
|---|---|
| parse the command line, bootstrap the stack, pick client or server mode | `Elixipp.CLI` |
| bind the listeners a server scenario needs | `Elixipp.CLI` → the framework listeners |
| run N instances in parallel, at a rate, up to a total | `Elixipp.CLI` (client mode) |
| accept inbound dialogs, enforce a quota, spawn one instance each | `Elixip.ScenarioUAS` |
| show what is happening, live | `SIP.Scenario.Monitor` + the CLI's renderer |
| stop without cutting calls | the cooperative-shutdown contract |

The split of the last three is deliberate: the **monitor** and the **factory**
live in the shared library (`apps/elixip2`), because a scenario reports to the
monitor through the session macros and because kelixip reuses the same factory
shape. The **rendering** lives in the tool, which is the only place that may
depend on a terminal UI library.

---

## 2. Two modes, decided by the scenario

`SIP.Scenario.Loader.scenario_type/1` answers `:uac` (the default) or
`:uas_register` / `:uas_invite`, and the CLI branches on it. The user does not
choose the mode: a scenario that declares `uas :register` *is* a server, and
running it as a client would be meaningless.

### 2.1 Client mode

One instance for a bare run; `--limit N` runs N concurrently, `--rate N` starts
them at N per second (default 2, hard ceiling 100), `--max-run N` stops after N
total. The slot machinery is a small scheduler: a free slot spawns the next
instance if the rate allows it, an instance's exit frees its slot and updates the
verdict counters.

A client run without `--local-port` binds a **random free UDP port ≥ 5000**
rather than the transport's default 5060, so two instances — a UAC and a UAS
loopback test on one host — do not fight over the port.

With `--config`, accounts are picked **round-robin across runs**: a 200-call run
over 10 accounts exercises all ten.

### 2.2 Server mode

`--listen PROTO:PORT` binds listeners (`udp`, `tcp`, `tls`, `wss`; a bare `PROTO`
picks a random free port ≥ 5000), and `Elixip.ScenarioUAS` is registered as the
processing module for both the registrar and the call behaviours.

The factory is one GenServer implementing `SIP.Session.Registrar` **and**
`SIP.Session.Call`, so one quota, one set of counters and one monitoring path
serve a registrar and a call server alike. Per inbound request it:

- rejects an INVITE whose R-URI domain is not among the configured ones with
  **604 Does Not Exist Anywhere** (`:any` disables the check);
- rejects with **503** when `max_instances` are already running or `max_run` has
  been reached;
- otherwise spawns one instance bound to the new dialog and answers
  `{:accept, pid}`.

Instances are monitored; a slot is freed when its instance terminates, and the
outcome increments the success / aborted / failed counters — the same three
outcomes the engine reports (`:aborted` exists precisely so a graceful stop is
not counted as a failure).

**The default concurrency differs by mode**: 1 in client mode, **50** in server
mode. They were shared once, and a registrar then refused every phone but the
first with a 503.

In server mode there is no run counter to cycle on, so the external config's
header and its **first** account are shared by every instance.

---

## 3. The live monitor

`SIP.Scenario.Monitor` is an in-memory registry of the instances currently
running: one row per call, keyed by the CLI slot id — or by `{parent_slot, name}`
for a `spawn_fsm` child, so a sub-FSM appears as its own row right under its
parent. Each row holds the scenario name, the account, the last command sent, the
current FSM state and the event that caused the last transition.

Two producers report into it: the **runner**, on every transition (including a
`stay`, so a scenario whose whole activity is answering in-dialog requests never
looks frozen), and the **session macros**, on every command sent. Both report
through helpers that are **no-ops when the monitor is not started**, so a
non-interactive run pays nothing.

The renderer is a fixed-column table (scenario, account, command, state, event)
with a counter line and a status bar, scrollable when the call list exceeds the
terminal height.

Keys: `q` for a graceful shutdown, `Ctrl+D` for an immediate stop with the
summary, `↑`/`↓` to scroll.

---

## 4. Stopping

`q` broadcasts the FSL cooperative-shutdown message
(`{:scenario_ctl, :shutdown, …}`) to every running instance — the same contract a
parent FSM and a kelixip node use ([DESIGN-FSL.md](DESIGN-FSL.md) §4.3). No new
calls are started; the tool waits for the active ones, and hard-kills after a 5 s
grace period whatever did not honour the request.

This is why the injected `on_events` clause exists: a scenario is stoppable
whether or not its author thought about it, so `q` works on every scenario ever
written.

---

## 5. Diagnostics

- `--log-file` / `--log-level` — the file log, separate from the console.
- `--log-sequence` — one PlantUML sequence diagram per instance, rendered from
  the per-process journal at teardown ([DESIGN-FSL.md](DESIGN-FSL.md) §7).
  Rejected together with `--limit > 1`: N interleaved diagrams answer no
  question, and the option is meant for the single call being debugged.

A bind failure names the posix reason in plain words rather than an atom
(`eaddrinuse`, `eacces`, `eaddrnotavail`, `enoent`), because a tool that cannot
bind gives its user exactly one line to act on.

---

## 6. Built-in scenarios

`UAC.Invite` and `UAC.Register` are compiled **into** the escript, so
`elixipp UAC.Register` needs no file on the host — which is what makes the
standalone binary useful on a machine that has nothing else. They are not
duplicates of `apps/elixip2/scenarios/`: those are editable `.exs` copies loaded
by path, deliberately under different module names (`UAC.InviteExample`,
`UAC.RegisterExample`) so both can coexist.

---

## 7. Invariants

1. The mode comes from the scenario, never from a flag (§2).
2. The monitor and the factory belong to the shared library; only the rendering
   belongs to the tool (§1).
3. Reporting is a no-op when the monitor is off (§3).
4. Stopping is cooperative first, forced only after the grace period (§4).
5. Server-mode rejections are SIP answers with a meaning — 604 for the wrong
   domain, 503 for a full quota — never a dropped request (§2.2).
