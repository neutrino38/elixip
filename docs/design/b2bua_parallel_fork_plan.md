# P4 — parallel forking: work plan, and what it took

Branch `b2bua-phase4`. Companion to [b2bua_module.md](b2bua_module.md) §3.2 (q
groups), §3.3 (the kamailio TM model) and the §11 phasing table, in the shape of
[b2bua_media_impl_plan.md](b2bua_media_impl_plan.md): what P4 is, in the order it
was built.

**Delivered 2026-08-10.** The four steps below all landed; the notes under each
say what the plan got right and what writing it changed. The design document is
the reference — this one records the route.

## Scope, decided 2026-08-10

- **Parallel forking only.** The §11 row also lists trunk processes
  (`trunk_pid`: OPTIONS pinging, reachability, blacklisting). They are
  independent of forking and much larger; `trunk_pid` stays reserved and
  ignored, as today, and gets its own phase.
- **q groups are nested `uris`.** An element of `%Peer{uris:}` is either a URI
  (as today) or a **list** of URIs forming one parallel group: parallel within
  an element, serial across elements. No second field to keep consistent with
  the first, and the existing serial hunt becomes the degenerate case — a list
  of one-URI groups.

```elixir
%Peer{fork: :parallel,
      uris: [[c_q1a, c_q1b],   # q = 1.0 — rung, both at once
             [c_q05]]}         # then q = 0.5
```

- `{:rtpengine, …}` stays out of scope (deferred to the borderline work).

## What already exists (P2b), and what it buys

`SIP.DialogImpl` already carries the branch machinery: the `branches`
(`trans_pid => target`) table, `forking`, `SIP.Dialog.fork_branch/2` →
`start_branch/2` (same Call-ID/from-tag/CSeq off `state.msg`, one fresh client
transaction per branch, exempt from the four-transaction cap), `adopts_totag?/2`
(a forked dialog adopts only a 2xx's tag), `adopt_winning_branch/2` (CANCEL the
losers, pin the winner's target onto `state.msg.ruri`), and the branch failure
that ends the *branch* rather than the dialog.

`start_branch/2` does not require the previous branch to be over, so **firing N
branches at once already works**. What is missing is everything about how their
responses come back.

## P4-1 — the dialog layer

Today `handle_info({:response, …})` surfaces **every** response to the app
unconditionally, before `handle_UAS_response/3` even looks at it. That is right
for one branch and wrong for N.

**The unifying rule** (found while reading the serial path — it is why this
needs no mode flag): *withhold a non-2xx final while another branch is still
pending; surface the aggregate when the last branch ends*. Serial mode never has
more than one live branch, so it surfaces immediately, exactly as it does today
— the serial behaviour of §3.2 ("the last branch's final") falls out instead of
being special-cased.

Concretely, a decision function evaluated **before** `send_to_app`, applying only
when `transact_pid` is one of `state.branches`:

| Response | Action |
|---|---|
| provisional | surface unchanged — this is the §3.2 collapsing (all branches' 18x go out in the single inbound UAS dialog) |
| 2xx | the winner: `fork_done`, surface; `adopt_winning_branch/2` as today |
| 6xx | ends the hunt (RFC 3261 §16.7): CANCEL the pending branches, `fork_done`, surface immediately |
| other final, branches left | withhold; fold into `fork_best` |
| other final, last branch | surface `best_of(fork_best, rsp)`; `fork_done` |
| anything, `fork_done` already set | dialog-internal — see below |

New state: `fork_best` (the best withheld final) and `fork_done` (a final answer
for this fork has been delivered). **`start_branch/2` must reset `fork_done`** —
in serial mode the app arms the next target precisely after a final was
delivered, so without the reset the second rung would be swallowed.

`best_of/2` = RFC 3261 §16.7 step 6: a 6xx wins; otherwise the lowest code, with
the 401/407/415/420/484 preference inside 4xx. (503 → 500 is in the same step;
decide whether a B2BUA owes it, a proxy does.)

Once `fork_done` is set, responses still arriving on branch transactions are
**ours to clean up, never the scenario's**:

- **non-2xx** (the 487s our own CANCELs provoke, a slow failure after a 6xx):
  drop, log at debug;
- **late 2xx** — a loser answering after, or crossing, our CANCEL: the dialog
  ACKs it and BYEs it, built from *that response's* own to-tag / Contact /
  Record-Route (`SIP.Msg.Ops.ack_request/4` + a BYE). A proxy cannot do this
  (the caller's UAC does, §16.7); a B2BUA must, and it stays invisible above.
  **Open**: the BYE belongs to a dialog we deliberately do not create — likely a
  bare NICT whose response is discarded. Check what `ack_request/4` needs (it
  copies the INVITE's top Via — the 2xx ACK needs a *fresh* branch, the trap
  already found and fixed once for the three-party test).

Tests: `sip_dialog_parallel_fork_test.exs`, seven of them, on real named mockup
peers.

**As built.** The rule held, and `fork_done` turned out to be unnecessary: the
branches we CANCEL are remembered in a `fork_losers` set, and membership of that
set is exactly the question "is this response ours to absorb?" — so there is one
piece of state, not two. Three things the plan did not know:

- **the transaction layer had to change after all.** A client transaction in
  `:cancelling` dropped every final response, so the CANCELled branch was never
  ACKed, the dialog never learned the branch had ended, and the late 2xx — the
  case §16.7 exists for — was discarded before reaching any of this. Two guards
  in `SIP.Transac.Common.handle_UAS_sip_response/2`, and the fix is a bug fix,
  not forking machinery: only a final ends a transaction, cancelling merely asks;
- **a rung must be armed atomically**, or it races its own first branch (see
  §3.3 as built). Hence `fork: [uris]` on `start_dialog/5` and a list-taking
  `fork_branch/2`, rather than the plan's "arm them from the session";
- **the synthetic 408** of a branch dying on timer B had its own path to the
  application (`notify_transaction_timeout/4`), which would have bypassed the
  aggregation entirely. Both paths now leave by the same door,
  `deliver_response/3`.

The late-2xx BYE is sent as a bare client transaction whose response is
swallowed (`internal_trans`), deliberately not as a dialog: nothing above knows
that callee, and a second dialog process would exist only to be torn down. It is
addressed to the Contact of the late 2xx, stamped with the flow the branch used —
the Contact carries an identity, the branch's request carries the address that
actually works.

## P4-2 — the session layer

`SIP.Session.B2bua` is written for one live branch at a time and that shows in
three places:

- `%Leg{initial_trans:}` and `put_last_invite/3` are **single-slot**; a parallel
  rung needs the set of live branch transactions on the leg;
- `%Pending{}` is keyed by client-transaction pid, and `move_correlation/3`
  *moves* the caller's pending from the old branch to the new one. With N
  branches, N pendings share one `orig_req`; the dialog guarantees a single
  final, so the relay still fires once, but the bookkeeping must tolerate the
  fan-out (and purge the rung when it ends);
- `expand_targets/1` flattens; it must now yield **rungs**. `use_srv: true`
  expansion stays serial *within* a rung (SRV multiplicity is a failover list,
  §3.1) — a group of one URI expands to a serial sub-list, not a wider rung.

Then: `create_leg/5` dials the whole first rung (first target with the dialog,
the rest through `fork_branch/2`), `next_target/3` becomes "next **rung**" and
arms all of it, `b2bua_hunting?/0` and `b2bua_cancel_forward/0` count live
branches rather than one attempt, and the per-attempt ring timeout applies to
the rung.

The provider path (§3.4) stays serial by construction — it hands out one target
at a time. Nothing to do, but assert it.

Media mode should mostly fall out of P3: the outbound offer is generated once
and reused by every branch, 18x SDP is stripped, and only the winner's 2xx is
ever answered. To verify, not to assume.

**As built.** `%Leg{branches: [{tid, uri}]}` holds the rung in flight and
`untried` became a list of rungs; `%Pending{}` did **not** fan out. One request
is relayed, a rung is only several ways of asking it, so the correlation stays
single and `pending_key/2` maps any branch back to it — which left the whole
response path (media step, hunt, relay, teardown) reading one pending as before.
The winner is adopted twice for two different reasons: the dialog adopts its
to-tag and pins its target (§3.3), the session repoints `initial_trans`,
`target` and `last_invite` at it — the last one being what sends the caller's ACK
to the branch that actually answered.

Two fixes fell out on the way, both pre-existing and both in the same place:
every branch after the first ignored the peer's `ruri: :keep` policy (the dialog
puts what it is handed straight into the R-URI, so a trunk peer had its second
branch rewritten to the gateway's URI) and its `outbound_proxy`. `branch_uri/3`
now composes every branch the way `apply_target/3` composes the first.

`expand_targets/1` splits on `fork`: `:parallel` gives one rung per entry of
`uris`, anything else gives rungs of one — so SRV multiplicity stays the failover
list it is (§3.1) instead of silently becoming a group to ring together.

## P4-3 — the registrar

`Kelix.Mod.Registrar.targets/2` returns a flat q-sorted list and `fork: :serial`.
It becomes q **groups** and `fork: :parallel` — which is the RFC 3261 §16.6
semantics the design has been promising since P2a. `q`/`expires` must keep being
stripped from the composable URI (they are binding parameters the parser mixes
into the URI params). `apps/kelixip/scripts/b2bua.exs` does not change shape:
that was the point of returning a peer.

## P4-4 — reference scenario and end-to-end tests

Named mockup peers (delivered 2026-08-09) make a real three-party test possible;
parallel needs a **four**-party one: caller, B2BUA, two callees ringing at once.
Assert: both ring, the first 2xx wins, the loser gets a CANCEL, the caller sees
one final; then the loser answering 2xx anyway and being ACK+BYEd; then
all-branches-fail with the aggregate the caller receives. Plus the doc: §3.3 and
the §11 table as built.

**As built.** No new reference scenario: parallel forking is a property of the
**peer**, not of the script, so `b2bua_basic.exs` rings a rung unchanged — which
is the clearest statement of what the leg abstraction bought, and the reason the
four-party test lives in `b2bua_three_party_test.exs` next to the three-party one.
Its closing assertion is the caller's ACK: relayed onto the winning transaction,
so no second 200 comes back. `b2bua_script_test.exs` covers the same thing from
the registrar's side — two devices of equal q ringing together, one going busy,
the caller hearing nothing.

Coverage, four levels: the dialog on its own (7), the session with a real dialog
(5), the full stack through the scenario (1), and the registrar-driven script (1).

## Test traps to respect (they have bitten three times on this work)

Nothing added to the **shared** UDP mockup, `:sip_timer_T1` never touched (it is
global), every test closes what it opens (legs released, media connections
unbound), and any test asserting on `:BYE` gets its **own** mockup instance — the
mockup announces it as a bare atom with no identity, so another test's BYE lands
in the one that is running.
