# Conferencing module evolutions (controller side)

**Status: designed, not built.** What is built is
[`DESIGN-MCU.md`](DESIGN-MCU.md). What the media server still owes the module is
[`mcu_server_evolutions.md`](mcu_server_evolutions.md), and every change below is
on **this** side of the wire: `apps/kelix_modules`, the reference scripts, the
block layer of [`DESIGN-SBB.md`](DESIGN-SBB.md).

## 1. `Mcu.SBB.conference()` — the leg's life in the mix, as a block

### 1.1 What it replaces

`mcu.exs` spends 230 of its 519 lines on three states — `in_call`,
`in_conference`, `hanging_up` — that carry **no conference policy at all**. They
carry SIP: which ACK is the first one, that an INFO is answered whether or not it
is an RFC 5168 request, that a BYE is answered before the slot is released, that
our own BYE is followed by a wait for its 200, that a leg gone silent is a leg to
hang up.

The scripts are already two, and they have already drifted. `mcu_adhoc.exs` holds
the same three states minus three clauses:
`{:mcu_event, :media_timeout, media}`, `{:mcu_event, :media_connected, _}` and
the 3-tuple catch-all `{:mcu_event, _, _}`. The consequence is not a missing
feature. `on_events` compiles to a `receive`, and the runner injects no
catch-all, so a `{:mcu_event, :media_connected, :audio}` sent to an ad-hoc leg
**matches no clause and stays in the mailbox for the whole call**; a leg whose
media dies is never torn down and holds its slot until the 2 h idle backstop.
Nothing reports it. That is [`DESIGN-SBB.md`](DESIGN-SBB.md) §1 in one file pair:
the copy rots one script at a time.

### 1.2 The name

| | |
|---|---|
| Face | `Kelix.Mod.Mcu.SBB`, macro `conference/1` |
| FSM | `Kelix.Mod.Mcu.SBB.Conference` (`apps/kelix_modules/lib/kelix/mod/mcu/sbb/conference.ex`) |
| Namespace | `:conference` — the leaf's default, no `@sbb_namespace` line |
| Call site | `Mcu.SBB.conference()`, returns matched as `{:conference, outcome, data}` |

`run_conference()` is the shape to avoid. The verb of a block is what the
scenario writes, and `run_` is not a verb, it is a prefix over one — `call()` and
`bridge()` set the tone, and neither says `place_call()` or `run_bridge()`. It
also costs the free namespace: the leaf `RunConference` derives
`:run_conference`, which reads badly enough that it gets overridden by hand, and
`@sbb_namespace` is then one more line that can be forgotten
([`DESIGN-SBB.md`](DESIGN-SBB.md) §7.4 names that exact hole).

`conference()` has one neighbour worth naming: `Kelix.Mod.Mcu.conference/1`, the
lookup that returns a conference row. They do not collide — one is
`Mcu.conference(uid)`, the other `Mcu.SBB.conference()`, and the `SBB.` segment
is what tells a reader that the second enters an FSM. The pair is the reason the
macro is **not** published on `Kelix.Mod.Mcu` itself.

### 1.3 The seam: `bridge()` for a conference leg

This block is to a conference leg what `bridge()` is to a B2BUA call: it takes
over **once the call is answered** and runs until something happens that the
script has a policy for.

So the answer stays with the script. `answering` keeps its
`reply_invite_with_sdp(200, …)`, its media set, its `on_media_error` mapping and
whatever else a deployment wants in that 200 — extra headers, a body of its own.
The block never composes a response to an offer, which is why it takes no
`media:` and no `webrtc:` argument. It is entered on the line the scripts write
`goto(in_call)` today, and it replaces `in_call`, `in_conference` and
`hanging_up`, nothing else.

```elixir
state answering do
  reply_invite_with_sdp(200,
    media: :tc,
    webrtc: :if_offered,
    on_media_error: &__MODULE__.media_error/1
  )

  case sip_ctx.lasterr do
    {:media_error, reason} ->
      {code, _text} = media_error(reason)
      media_cleanup_ressources()
      leave({:no_media, code})
      scenario_success("media refused: #{code} (#{inspect(reason)})")

    _ ->
      goto(in_conference)
  end
end

state in_conference do
  Mcu.SBB.conference()

  on_events do
    # Renegotiation: the block hands the request back UNANSWERED. Answer it the
    # way this deployment wants — or refuse it — then go back into the mix.
    {:conference, :renegotiation, %{method: method}} ->
      reply_invite_with_sdp(200,
        media: :tc,
        webrtc: :if_offered,
        on_media_error: &__MODULE__.media_error/1
      )

      goto(loop, "#{method} renegotiated")

    {:conference, :message, %{envelope: envelope}} ->
      Logger.info(module: __MODULE__, message: "#{envelope.kind} from #{envelope.from.part_id}")
      goto(loop, "collaboration message")

    {:conference, :caller_hung_up, %{reason: reason}} -> scenario_success("BYE (#{inspect(reason)})")
    {:conference, :cancelled, _}                      -> scenario_success("cancelled")
    {:conference, :mcu_lost, _}                       -> scenario_success("mcu lost")
    {:conference, :media_timeout, %{media: media}}    -> scenario_success("media timeout on #{media}")
    {:conference, :attach_refused, %{reason: reason}} -> scenario_failure("not mixed: #{inspect(reason)}")
    {:conference, :idle_timeout, _}                   -> scenario_failure("idle timeout")
  end
end
```

`goto(loop, …)` re-runs the body, which calls `conference()` again: the block
resumes in the mix. That is the whole re-entry mechanism, and §1.6 is what makes
it safe.

### 1.4 What it takes

One argument, and the BYE's own 10 s wait is not one — it has a single caller and
a single right value.

* `:idle_timeout` — 7_200_000 ms. **Idle**, not a budget: every event re-arms it
  (`goto loop`), so it is the G3 backstop against a leg that goes silent, not a
  maximum call duration. The name differs from `bridge`'s `:max_duration` on
  purpose — same shape, opposite meaning.

### 1.5 What it answers

Two families, and the difference is what state the leg is left in.

**The block hands the call back and keeps it whole.** Nothing is answered,
nothing is released; the script acts and re-enters with `goto(loop, …)`.

| Outcome | Data | What happened |
|---|---|---|
| `:renegotiation` | `%{method: :INVITE \| :UPDATE, req, transaction, dialog}` | a re-INVITE or an UPDATE arrived, **unanswered** |
| `:message` | `%{envelope}` | a peer's script said something (§20.5) |

**The leg is out.** The media connection is released and `Kelix.Mod.Mcu.leave/2`
has run with the reason named, in that order. The script names the verdict; it
frees nothing.

| Outcome | Data | What happened |
|---|---|---|
| `:caller_hung_up` | `%{reason: :bye \| term}` | a BYE, answered; or the dialog went away on its own |
| `:cancelled` | `%{}` | a CANCEL around the answer — the IST sent the 487, the teardown was ours |
| `:mcu_lost` | `%{via: :mcu_event \| :ms_event, bye_answered: boolean}` | the media server went away; our BYE is out |
| `:media_timeout` | `%{media, bye_answered: boolean}` | every media of this leg went silent (P7/S1); our BYE is out |
| `:idle_timeout` | `%{bye_answered: boolean}` | the G3 backstop fired; our BYE is out |
| `:attach_refused` | `%{reason}` | the mix refused the leg at ACK time (`:jsr309_media_already_in_use`) |

`bye_answered: false` is what the script's `scenario_failure("BYE not answered")`
reads today; a key rather than an outcome, because whether a hang-up was
acknowledged is a detail of an outcome, not a different one.

No `:timeout`: `@sbb_timeout :infinity`. A conference leg lasts as long as the
dialog, and `:idle_timeout` is the bound.

### 1.6 Handing a request back, and coming back in

A renegotiation is a **policy** decision — a deployment may refuse an added
media, cap a resolution, or answer with a different media set than it accepted at
the start — so the block does not answer it. What it does instead needs stating
precisely, because the obvious reading of "re-post the event" does not work.

**The returned event carries the request; the raw SIP event is not re-posted.**
`sbb_return/1` posts one event and ends the block, and whatever the block did not
consume is still ahead of it in the mailbox
([`DESIGN-SBB.md`](DESIGN-SBB.md) §2). A block that did
`send(self(), {:INVITE, req, trans, dlg})` **and** returned would leave two
events: the host would match its `{:INVITE, …}` clause first, re-enter the block
on `goto loop`, and the block would then find `{:conference, :renegotiation, …}`
in its own mailbox with no clause for it — the §1.1 failure, rebuilt on purpose.
So the request travels inside the outcome, and the host's arm destructures it:
`%{req: req, dialog: dialog_pid}` are the same two values its own `{:INVITE, …}`
clause would have bound.

Most arms will not read them. The block matched the request in an `on_events` of
its own, and that is what stores it in the **shared** context, so the script's
`reply_invite_with_sdp/2` and `last_uas_req/0` find the handed-back request
without being given it. The keys are there for an arm that wants to look at the
offer before deciding.

**The block remembers where it was, in the shared appdata.** The sandbox is
cleared on every entry, so a block keyed on it would re-run the ACK-time sequence
each time the host came back. The phase therefore lives next to the participant
handle it belongs to, under `:mcu_leg_phase`:

| Value | Meaning on entry | Set when |
|---|---|---|
| absent / `:awaiting_ack` | the next ACK is the first one: **attach** | the script answered a 200 and entered the block; a re-INVITE was handed back |
| `:attach_pending` | **attach now**, before waiting for anything | an UPDATE was handed back (RFC 3311: its 200 concludes the offer/answer, no ACK follows) |
| `:in_mix` | an ACK is a retransmission: ignore it | the leg attached |

That makes re-entry correct without the host having to say anything, which is the
point: `resume:` is a flag a script can forget, and forgetting it here would
re-attach a leg on every collaboration message.

Two consequences to accept rather than to engineer around:

* a script that **refuses** a re-INVITE (488) leaves the phase at
  `:awaiting_ack`. No ACK ever comes — the server transaction absorbs the ACK of
  a non-2xx (RFC 3261 §17.2.1) — so nothing re-attaches and the leg stays in the
  mix with the media it had. Which is right;
* a script that refuses an **UPDATE** costs one redundant `attach`, since the
  block cannot see which code the script chose. `attach` re-applies the codecs
  the leg already has; the scripts already call it on every ACK and every UPDATE,
  so it is the exercised path, not a new one.

**The window is `bridge`'s** ([`DESIGN-SBB.md`](DESIGN-SBB.md) §8.3): between two
entries the call is up and nothing answers it. For a message that is a log line.
For a renegotiation the script owes a response inside timer B, which is what its
arm is for — so that arm answers first and does its bookkeeping after.

`{:mcu_message, envelope}` reaches only a leg that called
`mcu_accept_messages()`, and `docs/kelixip/modules/mcu.md` documents handling it
**inside `in_call`** — the state this block absorbs. Handing it back is what
keeps that documented feature possible.

### 1.7 The FSM: three states, one steady

```
initial_state ──▶ in_conference ──(our BYE)──▶ hanging_up
                       │
                       └──(hand-back, BYE, CANCEL, dialog gone)──▶ sbb_return
```

* **`initial_state`** — no `on_events`. Reads `:mcu_leg_phase` and runs the
  pending `attach` of the `:attach_pending` case, then jumps to the loop;
* **`in_conference`** — the loop, `goto loop` on everything it consumes so the
  idle deadline is re-armed. The first ACK attaches, later ones do not; the guard
  is the phase, an `if` in one clause, where the scripts use two whole states.
  Two states inside the block would buy one monitor label and cost the forty
  duplicated lines this block exists to delete — the phase stays visible in the
  transition description and in the `mcu_attach` monitor note;
* **`hanging_up`** — our BYE is out. The 200 answers `bye_answered: true`, the
  10 s `after` answers `false`. The pending outcome is written to the sandbox
  before the jump, since three clauses lead here.

`attach` keeps the reference policy: a transient failure is logged and the call
**kept** — the caller can hear the problem and hang up, and tearing down a
confirmed dialog on an RPC hiccup is worse — while `:jsr309_media_already_in_use`
ends the leg through `:attach_refused`.

### 1.8 What moves out of the scripts

`do_admit/4` stays: `admit` runs before the block, and mapping a module verdict
onto 404 / 486 / 503 is the deployment's business. `media_error/1` stays too,
since the script owns every answer it is used for. What moves is what
[`CLAUDE.md`](../../CLAUDE.md) says a scenario should never have held — a
scenario states a call flow, it does not implement one:

| Script helper today | Where it goes |
|---|---|
| `do_attach/1` | the block calls `Kelix.Mod.Mcu.attach/1` and owns the keep-the-call rule |
| `do_leave/2` | the block calls `Kelix.Mod.Mcu.leave/2` with the reason its own outcome names |
| `picture_fast_update/0` | `SIP.MsgTemplate` — an RFC 5168 body is a SIP message, not conference logic |
| `request_fpu/2`, `media_control?/1`, `body_of/1` | the block, on top of a `SIP.Msg.Ops.picture_fast_update?/1` predicate |

`media_control?/1` and `body_of/1` read meaning out of a SIP message, so the
reading itself goes to the message layer and the block layers its policy on top.
It is not MCU-specific: any video leg answers the same question.

The `Kelix.Mod.Mcu.Script` mixin keeps its `attach` and `leave` macros even
though the reference scripts stop calling them — a copied script that does not
take the block still needs them.

A script then takes one `use`. `Kelix.Mod.Mcu` gains a `__using__` that aliases
the module, `require`s the face, registers the `:conference` namespace and pulls
in `Kelix.Mod.Mcu.Script`, exactly as `Kelix.Mod.AuthDb` does:

```elixir
use Kelix.Mod.Mcu          # Mcu.admit/2, Mcu.SBB.conference/1, and the rest
config(uses_modules: [:mcu])
```

### 1.9 A cooperative shutdown leaves the block and reaches the script

The block declares **no** `{:scenario_ctl, :shutdown, _}` clause, and it does not
need to re-post anything: the engine already does exactly that, better than a
`send/2` could. The clause `on_events` injects into every block state jumps to
`:__shutdown__`; the block has no `on_shutdown`, so `sbb_loop/5` throws
`{:sbb_shutdown, …}`, and the root `run_state/3` re-applies it **as the
transition the host state would have written**. The script's `on_shutdown` runs,
with the block unwound and the BEAM stack unwound with it. A literal re-post
would be strictly worse: it would put a control message behind whatever the block
had left in the mailbox and still owe the mandatory return (§1.6).

`on_shutdown` compiles to an ordinary state function, so the graceful ending the
scripts have today moves there whole — including the wait:

```elixir
on_shutdown do
  send_BYE()

  on_events do
    {200, _rsp, _trans, _dlg} ->
      media_cleanup_ressources()
      leave(:bye)
      scenario_aborted("MCU call stopped gracefully")
  after
    10_000 ->
      media_cleanup_ressources()
      leave(:bye)
      scenario_aborted("stopped, BYE unanswered")
  end
end
```

One behaviour changes and it is a fix. A kick
(`Kelix.Mod.Mcu.kick/2` sends `{:scenario_ctl, :shutdown, :kicked}`), a drain and
a node shutdown are three ways to stop a leg from outside; today the first two
are counted as `:success` by the scripts' own arm and the third as `:aborted`.
They become one path with one verdict.

**One framework gap this exposes.** `shutdown_clause/0` builds
`{:goto, :__shutdown__, "shutdown", :control, sip_ctx}` and drops the reason, so
`on_shutdown` cannot tell a kick from a drain and leaves with `:bye` either way.
Nothing regresses — the scripts' current arm ignores the reason too — but the
information exists and is wanted here: carrying it into the context in that one
line is what would let a kicked leg `leave(:kick)`.

### 1.10 The trap to write a test around

Inside a block, `goto` still aborts the scenario as a **failure** when
`sip_ctx.lasterr` is not `:ok`, and a terminal inside a block throws through the
host. So every module call the block makes must leave `lasterr` deliberately —
`Kelix.Mod.Mcu.attach/1` returning `{:error, :timeout}` and a `goto loop` on the
next line kills a call that the reference policy says to keep. The scripts get
this right today inside `do_attach/1`; moving it into the block moves the trap
with it.

### 1.11 Tests

In `apps/kelix_modules/test`, where both halves are present:

1. the first ACK attaches, the retransmitted one does not — one
   `participant.joined`, not two;
2. a re-INVITE comes back as `:renegotiation` **unanswered**, and the host's 200
   plus `goto loop` puts the phase back to `:awaiting_ack`, so the re-INVITE's own
   ACK re-attaches;
3. an UPDATE comes back the same way and re-attaches **on re-entry**, with no ACK
   involved;
4. a re-INVITE refused with a 488 re-enters the block and stays in the mix, no
   attach, no leftover event in the mailbox;
5. an INFO with an RFC 5168 body answered 200 **and** turned into `SendFPU`; an
   INFO without one answered 200 and nothing else;
6. `{:mcu_event, :media_timeout, media}` → BYE, `leave(:media_timeout)`,
   `{:conference, :media_timeout, …}`;
7. both routes of a dead media server (`{:mcu_event, :server_disconnected}` and
   `{:ms_event, _, :server_disconnected}`), each ending the call once;
8. a `{:mcu_message, …}` handed back, the host's `goto loop` resuming **without**
   a second attach — the §1.6 rule, which is the one that fails silently if it
   regresses;
9. a cooperative shutdown reaching the block runs the script's `on_shutdown`
   ([`DESIGN-SBB.md`](DESIGN-SBB.md) invariant 8).

### 1.12 Rollout: both scripts, and the drift closed

`mcu.exs` and `mcu_adhoc.exs` convert in the same change. This is the point of
doing it: `mcu_adhoc.exs`'s three missing clauses (§1.1) do not get *fixed*, they
stop existing — there is one copy of that loop and it is the block's. What is
left in the two scripts is what actually differs between them, which is the
admission policy and the verdicts, and the diff between the two files becomes
readable for the first time.

The reference scripts are shipped in `script_dir` and a deployment is expected to
copy them, so the conversion is also what tells copied scripts what to do: the
block is the supported way to hold a leg, and the old three states keep working
for a copy that has not moved.

### 1.13 Scope

`play.exs` and `record.exs` carry an `in_call` / `in_conference` pair of the same
shape. They are JSR-309 media scripts, not conference legs: this block does not
cover them and no attempt is made to generalise it into one that would.
