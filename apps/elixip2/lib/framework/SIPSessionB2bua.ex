# B2BUA session layer: two call legs driven by one scenario FSM.
# Design: docs/design/b2bua_module.md. Part of the SIP.Session namespace; see
# SIPSession.ex for the common core.

defmodule SIP.B2bua.Peer do
  @moduledoc """
  A SIP peer: where an outbound leg is sent, and how.

  `uris` is an ordered target list (binaries or `%SIP.Uri{}`, possibly already
  carrying their destination — the registrar case, §3.2). The three sources of
  fork targets converge here: a single URI resolved through DNS SRV, an explicit
  list, or the live contacts of an AOR.

    * `use_srv`  — resolve each target through SRV (RFC 3263). SRV multiplicity
      is a failover list, always serial, whatever `fork` says.
    * `fork`     — `:none` | `:serial` | `:parallel`. Forking creates branches
      *inside* the leg dialog, never extra legs (§3.3). `:parallel` reads each
      entry of `uris` as a **rung**: a bare URI is rung alone, a nested list is
      rung all at once (equal q for a registrar peer — RFC 3261 §16.6: parallel
      within a group, serial across groups in descending q). The first 2xx wins
      the rung and the losers are CANCELled; if a whole rung fails, `retry_on`
      decides whether the next one is tried, and the caller is handed the best
      response the rung produced (§16.7).
    * `ruri`     — `:peer` rewrites the forwarded R-URI to the target (kamailio
      `$ru`; mandatory to reach a registered contact), `:keep` preserves the
      original R-URI and only routes to the target (kamailio `$du`; the
      trunk/SBC case).
    * `provider` — `{module, server}` (or a bare `module` registered under its
      own name) handing out targets one at a time instead of a static `uris`
      list: the call-queue case, see `SIP.B2bua.TargetProvider`. Exclusive with
      `uris`.
    * `retry_on` — which final responses make a `:serial` hunt move on to the
      next target: a list of codes and/or ranges, or `nil` for the default.
    * `profile` — the media profile the outbound offer is carried in, and the
      ladder walked when the callee refuses it (§7.5, `SIP.B2bua.Profile`):
      `:webrtc_required` | `:webrtc_if_supported` | `:avpf_required` |
      `:avpf_if_supported` | `:avp`. `nil` (the default) leaves the offer to the
      `{:mediaserver, outbound: …}` options, unchanged. Only meaningful with a
      media server: without one the offer relayed is the caller's.
    * `fallback_on` — which final responses walk the profile ladder down a rung
      instead of ending the attempt. `[488]` by default; some equipment says
      `415` or `606` for the same thing, which is why it is a list. A code here
      never ends the attempt while a rung is left — the hunt only sees it once
      the ladder has bottomed out.
    * `notify_progress` — surface `{:outbound, {:serial_*, …}}` events as the
      hunt walks its targets (design §3.6). Off by default: a hunt is otherwise
      silent, and a scenario that did not ask should not receive framework
      bookkeeping it might relay.
    * `outbound_proxy` — per-peer next hop; `nil` falls back to the global
      `:proxyuri` application env. (P2b-3 — the global one is honoured today.)
    * `trunk_pid` — reserved for the future trunk process holding reachability
      state. Ignored in v1.
  """
  defstruct uris: [],
            use_srv: false,
            fork: :none,
            ruri: :peer,
            provider: nil,
            retry_on: nil,
            profile: nil,
            fallback_on: nil,
            notify_progress: false,
            outbound_proxy: nil,
            trunk_pid: nil
end

defmodule SIP.B2bua.Hunt do
  @moduledoc """
  A search for a target driven by a `SIP.B2bua.TargetProvider` (design §3.4).

  It outlives the leg in both directions: it exists before one, because a
  provider may answer `{:wait, ms}` to the very first ask — the caller is queued
  and nothing has been dialled yet — and it carries what creating that leg will
  need when a target finally comes.

  `call_ref` is the identity the provider holds its reservation against, stable
  for the whole search.
  """
  defstruct provider: nil,
            call_ref: nil,
            peer: nil,
            orig_req: nil,
            media: false,
            opts: [],
            waiting: false,
            ring_timeout: nil
end

defmodule SIP.B2bua.Leg do
  @moduledoc "One call leg of a B2BUA scenario (the outbound one; see SIP.B2bua.State)."
  # `target` is the one currently being tried and `untried` the **rungs** left
  # after it, in the order the peer gave them (for a registrar peer, descending
  # q). A hunt walks that list of rungs; each attempt is a branch of the SAME
  # dialog, so the leg — and everything keyed on it — never changes, whether a
  # rung holds one target or five.
  #
  # `branches` is the rung in flight: `[{transaction_pid, target_uri}]`, dialled
  # together. `initial_trans` is the one of them the caller's `%Pending{}` is
  # filed under (the first dialled, until a winner replaces it) and `target` the
  # one being spoken about — the branch that answered, once one has.
  defstruct tag: nil,
            dialogpid: nil,
            peer: nil,
            target: nil,
            branches: [],
            # The Request-URI of the forwarded request as first composed, kept as
            # the template every later branch is composed from (`ruri: :keep`
            # preserves an identity, and it lives nowhere else once the dialog
            # has been created).
            fwd_ruri: nil,
            untried: [],
            method: nil,
            initial_trans: nil,
            # Set by b2bua_cancel_forward/0: the search was told to stop, as
            # opposed to having run out of targets. It is what keeps
            # `hunting?/1` from reading the attempt still being cancelled as a
            # hunt in progress.
            cancelled: false,
            media: false,
            # The offer profile the rung in flight was dialled with, and what is
            # left under it (§7.5). Both are `nil`/`[]` unless the peer named a
            # `profile:`, which is what keeps every pre-P5 leg identical.
            profile: nil,
            profiles_left: []
end

defmodule SIP.B2bua.Pending do
  @moduledoc """
  A request relayed onto another leg, awaiting its response. Keyed by the
  **client transaction pid** of the forwarded request — the correlation the
  design settles on (§5): the transaction pid is known at forward time and comes
  back on every response event, so nothing has to be re-derived from the message.

  `held_answer` is set on a relayed **re-offer** in media mode: the answer the
  leg that re-offered is owed, computed the moment its offer was read and held
  back until the far end answers — the same choreography as the initial INVITE
  (§7.2), one exchange later.
  """
  defstruct orig_req: nil, orig_leg: :inbound, method: nil, held_answer: nil
end

defmodule SIP.B2bua.MediaPlan do
  @moduledoc """
  The media plane of a `{:mediaserver, …}` call (design §7), which is
  call-scoped and not leg-scoped: one media server connection, two endpoints.

  `inbound_answer` is the caller's answer, produced the moment their offer was
  read and held back until the callee answers. It does not depend on WHICH target
  answers — it comes from the media server, not from the callee — and that is what
  lets a hunt keep running behind an established early dialog (§7.4): no 1xx ever
  carries this body, so nothing is committed until the 2xx.

  It is not immutable, though. `bridge/3` may hand back a rebuilt answer once both
  legs are known — a relayed media narrowed to what both can carry, or its codecs
  reordered — and that one supersedes this. It is written back here, so the field
  must be READ from the context at the moment of answering, never captured
  beforehand (see `complete_media/4`, where doing so cost the rebuilt answer).

  `outbound_offer` is ours, generated once and reused by every branch: it does
  not depend on which target is being tried.
  """
  defstruct opts: [],
            policy: %{},
            inbound_answer: nil,
            outbound_offer: nil,
            bridged: false,
            # Why the media plane failed, when it did. NOT `lasterr`: a bridge
            # that cannot be built is converted into a failed attempt and the
            # relay that follows SUCCEEDS, so `lasterr` — the outcome of the last
            # operation — says `:ok`, truthfully. The reason the call went that
            # way is a different question, and this is where a scenario reads it.
            error: nil
end

defmodule SIP.B2bua.State do
  @moduledoc """
  B2BUA bookkeeping, stored in the scenario context appdata under `:__b2bua__`.

  `last_invite` is keyed by the leg an INVITE was **sent to** and holds that
  request's client transaction: what an ACK arriving on the *other* leg acts
  upon. It is not the same thing as `%Leg{initial_trans}` — that one is the
  attempt a hunt is walking, and it stops being the right target the moment a
  re-INVITE is relayed on an established call (§6).

  `remote_sdp` is the last description each leg gave us — its offer, or its
  answer. What `b2bua_reoffer_kind/1` compares the next one against (§R4.1b);
  kept per leg because that is the granularity the question is asked at.

  `local_ack` marks a leg whose re-INVITE **we** answered: the far end never saw
  that INVITE, so the ACK confirming it must not be relayed onto a transaction
  that has nothing to do with it.
  """
  defstruct legs: %{},
            pending: %{},
            hunt: nil,
            last_invite: %{},
            media: nil,
            remote_sdp: %{},
            local_ack: %{}
end

defmodule SIP.Session.B2bua do
  @moduledoc """
  B2BUA primitives for FSL: create a second (outbound) call leg,
  relay requests and responses between the legs, and answer locally.

  Pulled in by `use SIP.Scenario`, so every scenario has the `b2bua_*` macros.
  The inbound leg stays `sip_ctx.dialogpid` — every existing macro
  (`reply_invite*`, `send_BYE`, …) keeps its inbound meaning; the outbound leg
  is tagged, so its events arrive wrapped as `{:outbound, evt}` and are told
  apart syntactically in `on_events` patterns.

  What is framework here: rewriting (through `SIP.Msg.Ops`), correlation, and
  the leg bookkeeping the automatic teardown reads. What stays the scenario's:
  the relay **policy** — what to relay, when, and what to answer locally.

  Design: docs/design/b2bua_module.md §3-§6.
  """
  require Logger

  alias SIP.B2bua.{Hunt, Leg, MediaPlan, Peer, Pending, Profile, State}
  alias SIP.Session.Media

  @appdata_key :__b2bua__
  @outbound_tag :outbound

  # Dialog lifetime (seconds) of an outbound leg, by method. Mirrors the inbound
  # values SIP.Dialog.start_new_dialog_for/3 uses.
  @default_timeouts %{INVITE: 1800, MESSAGE: 60, REGISTER: 600, SUBSCRIBE: 600, PUBLISH: 600}

  defmacro __using__(_opts) do
    quote do
      use SIP.Context

      @doc """
      Create the outbound leg: forward `req` to `peer`, attaching the resulting
      dialog to this scenario. `media` is `false` (pure signaling relay, P1) —
      `{:mediaserver, opts}` and `{:rtpengine, opts}` are P3/P4.

      Options: `:timeout` (dialog lifetime, seconds), `:useragent`.
      """
      defmacro b2bua_forward(req, peer, media, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_create_leg(
              var!(sip_ctx),
              unquote(req),
              unquote(peer),
              unquote(media),
              unquote(opts)
            )
        end
      end

      @doc """
      Relay `req` to the *other* leg. The direction is inferred from the event
      the enclosing `on_events` clause matched: a request received untagged
      (inbound) goes out on the outbound leg and vice versa. ACK and CANCEL are
      translated onto the correlated INVITE transaction rather than re-sent.
      """
      defmacro b2bua_forward(req) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward")

          var!(sip_ctx) = SIP.Session.B2bua.do_relay_request(var!(sip_ctx), unquote(req))
        end
      end

      @doc """
      Relay `resp` back onto the leg its request came from, found through the
      correlation established when that request was forwarded.
      """
      defmacro b2bua_forward_reply(resp) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_forward_reply #{unquote(resp).response}")

          var!(sip_ctx) = SIP.Session.B2bua.do_relay_reply(var!(sip_ctx), unquote(resp))
        end
      end

      @doc """
      Answer `req` locally — without relaying it — on the leg the current event
      came from (inbound when there is none, e.g. in an `after` clause).
      """
      defmacro b2bua_reply(req, code, reason \\ nil, upd_fields \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_reply #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_local_reply(
              var!(sip_ctx),
              unquote(req),
              unquote(code),
              unquote(reason),
              unquote(upd_fields)
            )
        end
      end

      @doc """
      Challenge `req` on the leg the current event came from, with the digest
      `params` the application built — a **407 Proxy Authentication Required** by
      default, a 401 when `code` says so.

      The application-composed form, and the counterpart of
      `SIP.Session.Registrar.challenge_registration/3` for a call: the
      authentication backend decides *that* a challenge is owed, the scenario
      composes it (`Kelix.Auth.challenge_params/2` and its like mint the nonce,
      `qop` and `stale`), and this verb puts it in the header the code calls for
      (`SIP.Msg.Ops.challenge_header/1`).

      407 rather than 401 as the default because that is what deployed UAs expect
      of the server that routes their calls; a B2BUA is formally a UAS, and both
      codes are accepted here for that reason.
      """
      defmacro b2bua_challenge(req, params, code \\ 407) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_challenge #{unquote(code)}")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_local_challenge(
              var!(sip_ctx),
              unquote(req),
              unquote(params),
              unquote(code)
            )
        end
      end

      @doc """
      Hang up the outbound leg on our own initiative — not a relay: no BYE was
      received. For the policies where the B2BUA decides the call is over
      (no ACK from the caller, a session timer, an administrative hangup).
      """
      defmacro b2bua_send_BYE() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_send_BYE")

          var!(sip_ctx) = SIP.Session.B2bua.do_send_bye(var!(sip_ctx))
        end
      end

      @doc """
      Give up on the target being tried and ask for the next one.

      What a ring timeout acts on — "ring this agent 15 s, then take the next" —
      and what resumes a search a provider parked with `{:wait, ms}`. The
      attempt in flight, if any, is CANCELled and reported to the provider as
      `:no_answer`.

      Only meaningful with a `%Peer{provider:}`: a static list needs nothing,
      its failures already walk it.
      """
      defmacro b2bua_try_next() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_try_next")

          var!(sip_ctx) = SIP.Session.B2bua.do_try_next(var!(sip_ctx))
        end
      end

      @doc """
      How long the provider asked for this target to be rung, in milliseconds,
      or nil when it said nothing. Meant to be read straight into an `after`:

          after
            b2bua_ring_timeout() || 20_000 -> b2bua_try_next(); goto loop
      """
      defmacro b2bua_ring_timeout() do
        quote do
          SIP.Session.B2bua.ring_timeout(var!(sip_ctx))
        end
      end

      @doc """
      Stop hunting. CANCELs the attempt in flight if one is ringing, drops the
      targets not yet tried, and arms nothing more.

      Distinct from relaying the caller's CANCEL, and both are usually wanted:
      `b2bua_forward(req)` tells the *callee* to stop ringing,
      `b2bua_cancel_forward()` tells the *search* to stop looking. Relaying alone
      leaves it running.
      """
      defmacro b2bua_cancel_forward() do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_cancel_forward")

          var!(sip_ctx) = SIP.Session.B2bua.do_cancel_forward(var!(sip_ctx))
        end
      end

      @doc """
      True while a serial hunt is still running: the target that just answered
      refused, and the next one is being tried. What tells "this device said no"
      from "the call is over" after a `b2bua_forward_reply/1`.
      """
      defmacro b2bua_hunting?() do
        quote do
          SIP.Session.B2bua.hunting?(var!(sip_ctx))
        end
      end

      @doc """
      Wire the two legs' media together, ahead of the 2xx that would do it.

      For the policies that want the callee's media through during ringing: the
      callee answered 183 with SDP and the scenario relays its own answer to the
      caller. Idempotent with the automatic bridge — `b2bua_forward_reply/1` on
      the 2xx will not attach a second time.

      `opts` overrides the call's transcoding policy for this bridge
      (`[audio: :force]`).
      """
      defmacro b2bua_bridge(opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "b2bua_bridge")
          var!(sip_ctx) = SIP.Session.B2bua.do_bridge_legs(var!(sip_ctx), unquote(opts))
        end
      end

      @doc """
      Take the media path down without ending the call: putting the caller on
      hold to play an announcement, re-pointing a hunt at another target. Both
      connections stay up and can be bridged again.
      """
      defmacro b2bua_unbridge() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "b2bua_unbridge")
          var!(sip_ctx) = SIP.Session.B2bua.do_unbridge_legs(var!(sip_ctx))
        end
      end

      @doc """
      Why the media plane failed, or nil — for the scenario that wants its own
      policy where the default one turned a 2xx into a failed attempt.
      """
      defmacro b2bua_media_error() do
        quote do
          SIP.Session.B2bua.media_error(var!(sip_ctx))
        end
      end

      @doc """
      Was the media failure ours — no media plane at all — rather than a
      statement about what the peer offered? Asked when `lasterr` says the media
      failed, to answer the right thing:

          cond do
            ctx_get(:lasterr) == :ok -> goto(proceeding, "call forwarded")
            b2bua_media_unavailable?() -> b2bua_reply(req, 503, "Service Unavailable")
            true -> b2bua_reply(req, 488, "Not Acceptable Here")
          end

      A `503` is what lets an upstream proxy try another route; a `488` says the
      caller asked for something it cannot have, and blaming the offer for our
      own missing media server sends the call nowhere.
      """
      defmacro b2bua_media_unavailable?() do
        quote do
          SIP.Session.B2bua.media_unavailable?(var!(sip_ctx))
        end
      end

      @doc """
      What a re-INVITE or an UPDATE just received asks for, compared with the
      last description the same leg gave us: `:hold`, `:resume`,
      `:media_change`, `:address_change`, `:no_sdp`, `:no_change` or `:unknown`
      (`SIP.Msg.Ops.reoffer_kind/2` — the reading itself is message layer).

      What it is for: with a media server in the middle, a peer that merely
      MOVED has changed nothing the far end can see, because our endpoint did
      not move. The scenario writes the policy on top:

          case b2bua_reoffer_kind(req) do
            kind when kind in [:address_change, :no_sdp, :no_change] ->
              b2bua_reply_reoffer(req)
            _kind ->
              b2bua_forward(req)
          end

      Relaying is the safe default: everything this does not name explicitly —
      `:unknown` included — concerns the far end.
      """
      defmacro b2bua_reoffer_kind(req) do
        quote do
          SIP.Session.B2bua.reoffer_kind(var!(sip_ctx), unquote(req))
        end
      end

      @doc """
      Answer a re-offer here instead of relaying it: the media server takes the
      new description of that leg and its answer goes back in the 200.

      Needs a `{:mediaserver, …}` call — a signalling B2BUA has no media of its
      own to answer with, and fails with `lasterr` saying so. An offerless
      re-INVITE (a session-timer refresh) is answered with OUR offer, whose
      answer arrives in the ACK; that ACK is absorbed too, since the far end
      never saw the INVITE it confirms.

      A media server that refuses the new description leaves the call exactly as
      it was, and the re-offer gets a 488 (RFC 3261 §14.1).
      """
      defmacro b2bua_reply_reoffer(req, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:sip, "b2bua_reply_reoffer")

          var!(sip_ctx) =
            SIP.Session.B2bua.do_reply_reoffer(var!(sip_ctx), unquote(req), unquote(opts))
        end
      end

      @doc "The outbound leg (a `%SIP.B2bua.Leg{}`), or nil when none was created."
      defmacro b2bua_outbound_leg() do
        quote do
          SIP.Session.B2bua.outbound_leg(var!(sip_ctx))
        end
      end
    end
  end

  # ── Current-event bookkeeping (set by the on_events instrumentation) ────────

  @doc """
  Record which leg the matched event came from and which transaction it carries,
  so `b2bua_forward/1` / `b2bua_forward_reply/1` / `b2bua_reply/3` need no
  direction argument. Called for every `on_events` clause, next to the event-type
  inference it mirrors (process dictionary, same lifetime).
  """
  @spec note_event(term()) :: :ok
  def note_event(evt) do
    {leg, inner} = split_tag(evt)
    Process.put(:scenario_event_leg, leg)
    Process.put(:scenario_event_tid, event_transaction(inner))
    :ok
  end

  @doc "Forget the current event (called when a state is entered)."
  @spec forget_event() :: :ok
  def forget_event do
    Process.delete(:scenario_event_leg)
    Process.delete(:scenario_event_tid)
    :ok
  end

  @doc """
  Split a possibly tagged event into `{leg, event}`. A tagged event is the
  nested 2-tuple the dialog layer produces (`{:outbound, {…}}`); everything else
  belongs to the untagged inbound leg. Public because `auto_store/2` needs the
  same reading.
  """
  @spec split_tag(term()) :: {atom(), term()}
  def split_tag({tag, inner}) when is_atom(tag) and is_tuple(inner), do: {tag, inner}
  def split_tag(evt), do: {:inbound, evt}

  # The transaction pid an event carries: 3rd element of a request/response
  # event. Media, scenario and lifecycle events carry none.
  defp event_transaction({_first, _msg, tid, _dlg}) when is_pid(tid), do: tid
  defp event_transaction(_evt), do: nil

  defp current_leg, do: Process.get(:scenario_event_leg, :inbound)
  defp current_tid, do: Process.get(:scenario_event_tid)

  @doc """
  Act on a leg that has just died, before the scenario's own clause runs (design
  §14.4, R6). Called for every `on_events` clause next to `note_event/1`.

  A dialog dying is not news the scenario has to translate: whatever it decides to
  do next, the requests that leg was going to answer will now never be answered,
  and someone is waiting for each of them. So they are answered here, at once, on
  the leg they came from — 487 for an INVITE whose attempt is over, 408 otherwise
  — instead of at `release_legs/1`, which runs only when the scenario ends. A
  caller whose B2BUA lost its callee used to hold a ringing INVITE until then.

  Symmetric between the legs: when leg L dies, what is lost is every request
  relayed ONTO it, i.e. every `%Pending{}` whose `orig_leg` is the OTHER one —
  the correlation records where a request came from, and its answer was owed by
  the opposite side.

  What it deliberately does not do is decide the call's fate. Hanging up the
  surviving leg, failing, or reconnecting somewhere else is policy, and policy is
  the scenario's (§1).

  Limit worth knowing: this runs when the scenario MATCHES the event. One that
  ignores leg death entirely still falls back on the §8 teardown — later, but not
  never.
  """
  @spec note_leg_event(%SIP.Context{}, term()) :: %SIP.Context{}
  def note_leg_event(sip_ctx = %SIP.Context{}, evt) do
    case split_tag(evt) do
      {leg, {:dialog_terminated, _dialog_pid, reason}} -> on_leg_down(sip_ctx, leg, reason)
      _ -> sip_ctx
    end
  end

  def note_leg_event(sip_ctx, _evt), do: sip_ctx

  defp on_leg_down(sip_ctx, dead_leg, reason) do
    state = state(sip_ctx)

    # Everything relayed onto the dead leg — its `orig_leg` is the other one.
    orphans = Enum.filter(state.pending, fn {_tid, p} -> p.orig_leg != dead_leg end)

    if orphans != [] do
      Logger.info(
        module: __MODULE__,
        message:
          "b2bua: the #{dead_leg} leg is gone (#{inspect(reason)}); answering " <>
            "#{length(orphans)} request(s) it will never answer"
      )
    end

    Enum.each(orphans, fn {_tid, pending} -> answer_orphan(sip_ctx, pending) end)

    sip_ctx = Enum.reduce(orphans, sip_ctx, fn {tid, _p}, ctx -> drop_pending(ctx, tid) end)

    if dead_leg == :inbound do
      # The inbound leg is the scenario's own dialog, not ours to forget; the
      # outbound one is still there and still the scenario's to wind down.
      sip_ctx
    else
      # Release whatever a provider is holding for this call BEFORE forgetting the
      # hunt — an agent reserved for a leg that no longer exists is an agent the
      # queue believes is busy for good (§3.4). This is also what narrows open
      # question 8: it now happens in a live scenario process, not in a teardown
      # running inside one that is already terminating.
      report_outcome(sip_ctx, :abandoned)

      state = state(sip_ctx)

      put_state(sip_ctx, %State{
        state
        | legs: Map.delete(state.legs, dead_leg),
          hunt: nil,
          last_invite: Map.delete(state.last_invite, dead_leg)
      })
    end
  end

  # ── Leg creation ────────────────────────────────────────────────────────────

  @doc false
  @spec do_create_leg(%SIP.Context{}, map(), term(), term(), keyword()) :: %SIP.Context{}
  def do_create_leg(sip_ctx = %SIP.Context{}, req, peer, media, opts \\ []) do
    peer = normalize_peer(peer)

    cond do
      not dialog_forming?(req) ->
        fail(sip_ctx, {:b2bua, :not_dialog_forming, Map.get(req, :method)})

      leg_alive?(outbound_leg(sip_ctx)) ->
        fail(sip_ctx, {:b2bua, :outbound_leg_exists})

      not supported_media_mode?(media) ->
        # `{:rtpengine, _}` stays reserved and refused: it belongs to the
        # borderline product work, and pretending otherwise would produce a call
        # with no media path (§7.3).
        fail(sip_ctx, {:b2bua, :media_mode_not_implemented, media})

      # A peer names its targets one way or the other. With a provider `uris` is
      # empty by construction — the provider IS the list (§3.4).
      peer.uris == [] and provider_of(peer) == nil ->
        fail(sip_ctx, {:b2bua, :no_target})

      not Profile.valid?(peer.profile) ->
        fail(sip_ctx, {:b2bua, :unknown_offer_profile, peer.profile})

      # An offer profile means GENERATING an offer, which only a media server
      # does: a signalling relay forwards the caller's, and an AVP caller cannot
      # be turned into a WebRTC one (§7.5). Refused where it was written rather
      # than quietly ignored.
      peer.profile != nil and media == false ->
        fail(sip_ctx, {:b2bua, :profile_needs_media_server, peer.profile})

      true ->
        # What this leg said about its media, kept from the very first message:
        # it is what a re-offer from it will be read against (§R4.1b).
        sip_ctx = remember_remote_sdp(sip_ctx, current_leg(), SIP.Msg.Ops.sdp_body(req))

        # The media plane is set up BEFORE anything is dialled: the offer we
        # forward is ours, not the caller's, and there is no point creating a leg
        # we cannot give a body to.
        case setup_media(sip_ctx, req, media, first_rung(peer)) do
          {:error, sip_ctx} ->
            sip_ctx

          {:ok, sip_ctx} ->
            case provider_of(peer) do
              nil ->
                create_leg(sip_ctx, req, peer, media, opts)

              provider ->
                # The targets are not knowable up front: keep what creating the
                # leg will need, and ask. The leg itself waits for a target —
                # with a queue there may be none yet (§3.4).
                hunt = %Hunt{
                  provider: provider,
                  call_ref: make_ref(),
                  peer: peer,
                  orig_req: req,
                  media: media,
                  opts: opts
                }

                sip_ctx |> put_hunt(hunt) |> ask_provider_and_arm(hunt)
            end
        end
    end
  end

  # ── The media plane (§7, P3) ────────────────────────────────────────────────

  defp supported_media_mode?(false), do: true
  defp supported_media_mode?({:mediaserver, opts}) when is_list(opts), do: true
  defp supported_media_mode?(_), do: false

  @doc false
  @spec media_plan(%SIP.Context{}) :: %MediaPlan{} | nil
  def media_plan(sip_ctx), do: state(sip_ctx).media

  @doc """
  Why the media plane failed, or nil. Backs the `b2bua_media_error` macro.

  Read after `b2bua_forward_reply/1`, when the response it relayed was a 2xx
  turned into a failed attempt: `lasterr` describes the relay, which worked, and
  this describes the reason there was something to relay in the first place.
  """
  @spec media_error(%SIP.Context{}) :: term() | nil
  def media_error(sip_ctx) do
    case media_plan(sip_ctx) do
      %MediaPlan{error: reason} -> reason
      _ -> nil
    end
  end

  @doc """
  Was the media failure OURS — no media plane at all — rather than a statement
  about what the peer offered? Backs the `b2bua_media_unavailable?` macro.

  The distinction, and not the SIP code: a scenario answers `503` here and `488`
  otherwise (it is free to answer something else, and only it knows what the call
  is for), but *which of the two failures happened* is read in one place, because
  the reasons are the framework's own vocabulary and every scenario would
  otherwise re-derive them from a nested tuple.

  True for the three ways a media plane can be absent: it was never connected
  (`media_connect()` found none — `:no_media_server`), the adapter died under a
  call in progress (`{:media_down, _}`, a `GenServer` exit), or the server
  announced its own departure (`:server_disconnected`). Everything else — no
  common codec, a WebRTC offer refused, no offer at all — is about the offer and
  reads false.
  """
  @spec media_unavailable?(%SIP.Context{}) :: boolean()
  def media_unavailable?(sip_ctx = %SIP.Context{}) do
    no_media_plane?(sip_ctx.lasterr) or no_media_plane?(media_error(sip_ctx))
  end

  defp no_media_plane?({:b2bua, :media_setup_failed, reason}), do: no_media_plane?(reason)
  defp no_media_plane?({:b2bua, :reoffer_answer_failed, reason}), do: no_media_plane?(reason)
  defp no_media_plane?({:b2bua, :reoffer_relay_failed, reason}), do: no_media_plane?(reason)
  defp no_media_plane?({leg, reason}) when leg in [:inbound, :outbound], do: no_media_plane?(reason)
  defp no_media_plane?(:no_media_server), do: true
  defp no_media_plane?({:error, :no_media_server}), do: true
  defp no_media_plane?({:media_down, _reason}), do: true
  defp no_media_plane?(:server_disconnected), do: true
  defp no_media_plane?(_other), do: false

  defp put_media_plan(sip_ctx, plan) do
    put_state(sip_ctx, %State{state(sip_ctx) | media: plan})
  end

  # The profile the first offer is carried in, and `nil` when the peer named
  # none — in which case the `outbound:` options say it, as they did before P5.
  defp first_rung(%Peer{} = peer) do
    case Profile.ladder(peer.profile) do
      [rung | _] -> rung
      [] -> nil
    end
  end

  # Signalling relay: the SDP crosses verbatim and there is nothing to set up.
  defp setup_media(sip_ctx, _req, false, _rung), do: {:ok, sip_ctx}

  # `{:mediaserver, …}`: both legs terminate their media on the server, so the
  # bodies that cross are OURS in both directions. Two steps, in this order, and
  # neither leaves the box (§7.2):
  #
  #   1. read the caller's offer and answer it — but hold that answer back. The
  #      caller is not answered until the callee is, and by then the answer is
  #      already decided, which is exactly what makes early media and forking
  #      compatible here and mutually exclusive without a media server (§7.4);
  #   2. generate our offer for the outbound leg, inside the SAME media session
  #      as the inbound endpoint (`bridge_with:`), because that is the only place
  #      the two can later be attached.
  defp setup_media(sip_ctx, req, {:mediaserver, opts}, rung) do
    inbound_opts = Keyword.get(opts, :inbound, [])
    outbound_opts = profiled_outbound_opts(opts, rung)

    with {:ok, policy} <- MediaServer.transcoding_policy(Keyword.get(opts, :transcode, [])),
         :ok <- media_plane(sip_ctx),
         {:ok, offer_a} <- caller_offer(req),
         # The policy travels with the connection options, not only with
         # `bridge/3`: our OFFER to the callee is shaped by it too — under
         # `:avoid` the codecs the caller carries lead the format list, under
         # `:forbid` they are the whole of it — and that offer is built long
         # before there is anything to bridge.
         {sip_ctx, {:ok, answer_a}} <-
           media_answer(sip_ctx, offer_a, [leg: :inbound, transcode: policy] ++ inbound_opts),
         {:ok, sip_ctx, offer_b} <-
           media_offer(sip_ctx, [transcode: policy] ++ outbound_opts) do
      plan = %MediaPlan{
        opts: opts,
        policy: policy,
        inbound_answer: answer_a,
        outbound_offer: offer_b
      }

      {:ok, put_media_plan(sip_ctx, plan)}
    else
      {sip_ctx = %SIP.Context{}, {:error, reason}} ->
        {:error, fail(sip_ctx, {:b2bua, :media_setup_failed, {:inbound, reason}})}

      {:error, sip_ctx = %SIP.Context{}, reason} ->
        {:error, fail(sip_ctx, {:b2bua, :media_setup_failed, {:outbound, reason}})}

      {:error, reason} ->
        {:error, fail(sip_ctx, {:b2bua, :media_setup_failed, reason})}
    end
  end

  # Nothing is attempted without a media plane to attempt it on. `media_connect()`
  # may have found none — `Kelix.MediaPool` reporting `:unavailable`, see
  # `SIP.Session.Media.use_mediaserver/1` — and the media layer answers a missing
  # server by RAISING: rescued below, that came out as
  # `{:media_raised, "No media server connected…"}`, a sentence no caller can
  # match, which every scenario's else-branch then answered with a 488. The
  # caller's offer was never at fault. Asked here, once, the answer is the same
  # `:no_media_server` that `media_connect()` itself reports (2026-08-13).
  defp media_plane(%SIP.Context{mediaserverpid: server}) when is_pid(server), do: :ok
  defp media_plane(_sip_ctx), do: {:error, :no_media_server}

  # A delayed-offer INVITE has no media to terminate yet. Answering it means
  # putting an offer of ours in the 200 and reading the answer from the ACK,
  # which is a call flow of its own — refused plainly rather than half-built.
  defp caller_offer(req) do
    case SIP.Session.extract_sdp(req) do
      sdp when is_binary(sdp) and sdp != "" -> {:ok, sdp}
      _ -> {:error, :no_offer_in_invite}
    end
  end

  defp media_answer(sip_ctx, offer, opts) do
    Media.get_sdp_answer(sip_ctx, offer, opts)
  rescue
    err -> {sip_ctx, {:error, {:media_raised, Exception.message(err)}}}
  catch
    :exit, reason -> {sip_ctx, {:error, {:media_down, reason}}}
  end

  # The outbound media options for a given rung of the ladder: the scenario's
  # own, with the profile's on top. The scenario says WHICH medias and codecs it
  # wants; the profile says how they are carried, and it is the one thing that
  # changes between two attempts at the same target (§7.5). No rung — no profile
  # named — leaves the options exactly as written.
  defp profiled_outbound_opts(opts, nil), do: Keyword.get(opts, :outbound, [])

  defp profiled_outbound_opts(opts, rung) do
    Keyword.merge(Keyword.get(opts, :outbound, []), Profile.conn_opts(rung))
  end

  # Our offer for the callee. `bridge_with: :inbound` puts this endpoint in the
  # inbound leg's media session — a placement decision, made here because it can
  # only be made at creation time (docs/design/mediagw_b2bua_jsr309.md §2).
  defp media_offer(sip_ctx, outbound_opts) do
    webrtc = Keyword.get(outbound_opts, :webrtc, :no)
    medias = Keyword.get(outbound_opts, :media, :audio_video)
    opts = [leg: :outbound, bridge_with: :inbound] ++ outbound_opts

    {sip_ctx, offer} = Media.get_sdp_offer(sip_ctx, webrtc, medias, opts)
    {:ok, sip_ctx, offer}
  rescue
    err -> {:error, sip_ctx, {:media_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, sip_ctx, {:media_down, reason}}
  end

  # The body every branch of this leg carries: ours, not the caller's.
  defp apply_media_body(sip_ctx, fwd) do
    case media_plan(sip_ctx) do
      %MediaPlan{outbound_offer: sdp} when is_binary(sdp) ->
        SIP.Msg.Ops.update_sip_msg(
          fwd,
          {:body, [%{contenttype: "application/sdp", data: sdp}]}
        )

      _ ->
        fwd
    end
  end

  # ── Re-offers on an established call (§R4.1b) ───────────────────────────────

  @doc """
  What a re-offer just received on the current leg asks for. Backs the
  `b2bua_reoffer_kind` macro.

  The reading is `SIP.Msg.Ops.reoffer_kind/2` — message layer, one place. All
  this adds is *which* previous description to compare against, which is leg
  bookkeeping and therefore ours.
  """
  @spec reoffer_kind(%SIP.Context{}, map()) :: SIP.Msg.Ops.reoffer_kind()
  def reoffer_kind(sip_ctx = %SIP.Context{}, req) when is_map(req) do
    SIP.Msg.Ops.reoffer_kind(req, remote_sdp(sip_ctx, current_leg()))
  end

  @doc "The last SDP a leg described itself with — its offer, or its answer."
  @spec remote_sdp(%SIP.Context{}, atom()) :: binary() | nil
  def remote_sdp(sip_ctx = %SIP.Context{}, leg), do: Map.get(state(sip_ctx).remote_sdp, leg)

  defp remember_remote_sdp(sip_ctx, leg, sdp) when is_binary(sdp) and sdp != "" do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | remote_sdp: Map.put(state.remote_sdp, leg, sdp)})
  end

  defp remember_remote_sdp(sip_ctx, _leg, _no_sdp), do: sip_ctx

  @doc false
  @spec do_reply_reoffer(%SIP.Context{}, map(), keyword()) :: %SIP.Context{}
  def do_reply_reoffer(sip_ctx = %SIP.Context{}, req, opts \\ []) when is_map(req) do
    leg = current_leg()

    cond do
      is_nil(media_plan(sip_ctx)) ->
        # A signalling B2BUA has no media of its own: the only honest answer to a
        # re-offer is the far end's.
        fail(sip_ctx, {:b2bua, :no_media_to_answer_reoffer_with})

      is_nil(leg_pid(sip_ctx, leg)) ->
        fail(sip_ctx, {:b2bua, :no_leg_to_reply_on, leg})

      true ->
        case local_reoffer_body(sip_ctx, req, leg, opts) do
          {:ok, sip_ctx, sdp} ->
            # Answered here, so the far end never renegotiates — but THIS leg's
            # description just changed, and the selection was taken on the old
            # one. The answer needs nothing back (it was already shaped by what
            # the far end carries, `set_remote_offer` does that now); what this
            # call is for is the media server's side of it — the transcoders that
            # must now produce what this leg settled on. An offerless re-INVITE
            # is answered with an OFFER of ours and has changed nothing to
            # re-select on, so it is left alone.
            sip_ctx = rebridge_after_local_answer(sip_ctx, req, leg)

            sip_ctx
            |> remember_remote_sdp(leg, SIP.Msg.Ops.sdp_body(req))
            |> expect_local_ack(leg, req)
            |> do_local_reply(req, 200, "OK", [
              {:body, [%{contenttype: "application/sdp", data: sdp}]},
              {:contact, local_contact(sip_ctx)}
            ])

          {:error, sip_ctx, reason} ->
            # RFC 3261 §14.1: a re-INVITE that fails leaves the session exactly
            # as it was. The far end never heard about this one and does not
            # have to; the scenario reads why in `lasterr`.
            sip_ctx
            |> do_local_reply(req, 488, "Not Acceptable Here", [])
            |> fail({:b2bua, :reoffer_answer_failed, reason})
        end
    end
  end

  # What the 200 carries. A re-offer is answered with the answer to it; an
  # offerless re-INVITE is answered with an offer of OURS (RFC 3261 §14.2 — a 2xx
  # to an offerless INVITE must contain one), which is precisely the thing a
  # media-terminating B2BUA has and a signalling one does not.
  defp local_reoffer_body(sip_ctx, req, leg, opts) do
    leg_opts = Keyword.merge(leg_media_opts(sip_ctx, leg), opts)

    case SIP.Msg.Ops.sdp_body(req) do
      sdp when is_binary(sdp) and sdp != "" ->
        case media_answer(sip_ctx, sdp, [leg: leg] ++ leg_opts) do
          {sip_ctx, {:ok, answer}} -> {:ok, sip_ctx, answer}
          {sip_ctx, {:error, reason}} -> {:error, sip_ctx, reason}
        end

      _offerless ->
        media_offer_on(sip_ctx, leg, leg_opts)
    end
  end

  # The per-leg media options this call was created with (`inbound:`/`outbound:`
  # of the `{:mediaserver, …}` mode). The connection already exists by the time a
  # re-offer arrives, so only `:webrtc` and `:media` still have anything to say —
  # but reading them from the plan keeps one statement of how a leg terminates
  # its media instead of a second one written here.
  defp leg_media_opts(sip_ctx, leg) do
    case media_plan(sip_ctx) do
      %MediaPlan{opts: opts} -> Keyword.get(opts, plan_key(leg), [])
      _ -> []
    end
  end

  defp plan_key(:inbound), do: :inbound
  defp plan_key(_outbound), do: :outbound

  defp media_offer_on(sip_ctx, leg, leg_opts) do
    webrtc = Keyword.get(leg_opts, :webrtc, :no)
    medias = Keyword.get(leg_opts, :media, :audio_video)
    {sip_ctx, offer} = Media.get_sdp_offer(sip_ctx, webrtc, medias, [leg: leg] ++ leg_opts)
    {:ok, sip_ctx, offer}
  rescue
    err -> {:error, sip_ctx, {:media_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, sip_ctx, {:media_down, reason}}
  end

  defp process_answer(sip_ctx, leg, sdp) do
    Media.process_sdp_answer(sip_ctx, sdp, leg: leg)
  rescue
    err ->
      fail(sip_ctx, {:b2bua, :reoffer_answer_failed, {:media_raised, Exception.message(err)}})
  catch
    :exit, reason -> fail(sip_ctx, {:b2bua, :reoffer_answer_failed, {:media_down, reason}})
  end

  # A re-INVITE answered here will be ACKed here. An UPDATE will not — RFC 3311
  # has no ACK — so only the INVITE arms it.
  defp expect_local_ack(sip_ctx, leg, %{method: :INVITE}) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | local_ack: Map.put(state.local_ack, leg, true)})
  end

  defp expect_local_ack(sip_ctx, _leg, _req), do: sip_ctx

  defp local_ack?(sip_ctx, leg), do: Map.get(state(sip_ctx).local_ack, leg, false)

  defp forget_local_ack(sip_ctx, leg) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | local_ack: Map.delete(state.local_ack, leg)})
  end

  # The ACK of a re-INVITE we answered ourselves. It confirms a 200 the far end
  # never sent, so relaying it would post an ACK on whatever INVITE transaction
  # was last opened on the other leg — one answered minutes ago. That is the same
  # trap `last_invite` exists to avoid, arrived at from the other side.
  #
  # When our 200 carried an offer (the offerless case), this ACK carries its
  # answer: the last thing this leg says about its media, and the media server
  # has to hear it.
  defp absorb_local_ack(sip_ctx, leg, req) do
    sip_ctx = forget_local_ack(sip_ctx, leg)

    case SIP.Msg.Ops.sdp_body(req) do
      sdp when is_binary(sdp) and sdp != "" -> process_answer(sip_ctx, leg, sdp)
      _no_answer -> SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  # ── The provider (§3.4) ─────────────────────────────────────────────────────

  # `{module, server}`, or a bare module registered under its own name — the
  # kelixip module pattern. A bare pid cannot work: the callbacks have to be
  # dispatched somewhere, and only the module says where.
  defp provider_of(%Peer{provider: nil}), do: nil
  defp provider_of(%Peer{provider: {mod, server}}) when is_atom(mod), do: {mod, server}
  defp provider_of(%Peer{provider: mod}) when is_atom(mod), do: {mod, mod}
  defp provider_of(_peer), do: nil

  # Ask for a target and act on the answer. The one place that decides what each
  # reply means, so `b2bua_forward/3` and `b2bua_try_next/0` cannot drift.
  defp ask_provider_and_arm(sip_ctx, hunt, on_exhausted \\ &Function.identity/1)

  defp ask_provider_and_arm(sip_ctx, %Hunt{} = hunt, on_exhausted) do
    case ask(hunt.provider, hunt.call_ref, hunt.orig_req) do
      {:ok, uri} ->
        arm_target(sip_ctx, hunt, normalize_uri(uri), [])

      {:ok, uri, opts} when is_list(opts) ->
        arm_target(sip_ctx, hunt, normalize_uri(uri), opts)

      {:wait, ms} when is_integer(ms) and ms >= 0 ->
        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: true})
        |> note_progress({:serial_waiting, ms, now()})
        |> SIP.Context.set(:lasterr, :ok)

      :exhausted ->
        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()

      {:error, reason} ->
        Logger.warning(module: __MODULE__, message: "b2bua: provider failed: #{inspect(reason)}")

        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()

      other ->
        Logger.error(
          module: __MODULE__,
          message: "b2bua: provider returned #{inspect(other)}; treating it as exhausted"
        )

        sip_ctx
        |> put_hunt(%Hunt{hunt | waiting: false})
        |> note_progress({:serial_exhausted, now()})
        |> SIP.Context.set(:lasterr, :ok)
        |> on_exhausted.()
    end
  end

  # The first target creates the leg; every later one is another branch of it.
  defp arm_target(sip_ctx, %Hunt{} = hunt, uri, opts) do
    hunt = %Hunt{hunt | waiting: false, ring_timeout: Keyword.get(opts, :ring_timeout)}
    sip_ctx = put_hunt(sip_ctx, hunt)

    case outbound_leg(sip_ctx) do
      nil ->
        # A peer of one target, so the static machinery below builds the leg;
        # the provider stays on it, which is what later asks read.
        sip_ctx
        |> create_leg(hunt.orig_req, %Peer{hunt.peer | uris: [uri]}, hunt.media, hunt.opts)
        |> note_progress({:serial_attempting, uri, now()})

      %Leg{} = leg ->
        {sip_ctx, fork_opts, profile, profiles_left} = restart_ladder(sip_ctx, leg)

        case call_leg(fn -> SIP.Dialog.fork_branch(leg.dialogpid, uri, fork_opts) end) do
          {:ok, new_trans} ->
            sip_ctx
            |> move_correlation(leg.initial_trans, new_trans)
            |> put_leg(@outbound_tag, %Leg{
              leg
              | target: uri,
                initial_trans: new_trans,
                branches: [{new_trans, uri}],
                profile: profile,
                profiles_left: profiles_left
            })
            |> put_last_invite(@outbound_tag, leg.method, new_trans)
            |> note_progress({:serial_attempting, uri, now()})
            |> SIP.Context.set(:lasterr, :ok)

          {:error, reason} ->
            Logger.warning(
              module: __MODULE__,
              message: "b2bua: cannot try #{uri} (#{inspect(reason)}); the search stops"
            )

            sip_ctx
            |> note_progress({:serial_not_reachable, uri, :transport_error, now()})
            |> note_progress({:serial_exhausted, now()})
            |> SIP.Context.set(:lasterr, :ok)
        end
    end
  end

  # The caller is still waiting for an answer to the SAME request; only the
  # branch that will provide it changed.
  defp move_correlation(sip_ctx, from_tid, to_tid) do
    case Map.get(state(sip_ctx).pending, from_tid) do
      %Pending{} = pending ->
        sip_ctx
        |> drop_pending(from_tid)
        |> add_pending(to_tid, pending.orig_req, pending.orig_leg, pending.method)

      nil ->
        sip_ctx
    end
  end

  defp ask({mod, server}, call_ref, req) do
    mod.next_target(server, call_ref, req)
  rescue
    err -> {:error, {:provider_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, {:provider_down, reason}}
  end

  # Tell the provider how the attempt it handed out ended, so the reservation it
  # is holding is released. Never lets the provider's trouble become the call's.
  defp report_outcome(sip_ctx, outcome) do
    case hunt(sip_ctx) do
      %Hunt{provider: {mod, server}, call_ref: ref} ->
        protect("report #{inspect(outcome)} to the provider", fn ->
          mod.attempt_ended(server, ref, outcome)
        end)

      _ ->
        :ok
    end

    sip_ctx
  end

  defp create_leg(sip_ctx, req, peer, media, opts) do
    case SIP.Msg.Ops.prepare_forwarded_request(req, opts) do
      {:error, reason} ->
        fail(sip_ctx, {:b2bua, reason})

      {:ok, fwd} ->
        fwd = apply_media_body(sip_ctx, fwd)

        # The first RUNG is dialled now; the rest are kept on the leg for the
        # hunt to walk (§3.1). `fork: :none` keeps them unused.
        [[target | siblings] | rest] = expand_targets(peer)
        untried = if peer.fork in [:serial, :parallel], do: rest, else: []

        case apply_target(fwd, target, peer) do
          {:error, reason} ->
            fail(sip_ctx, {:b2bua, reason})

          {:ok, fwd} ->
            start_outbound_dialog(sip_ctx, req, fwd, peer, target, siblings, untried, media, opts)
        end
    end
  end

  defp start_outbound_dialog(sip_ctx, orig_req, fwd, peer, target, siblings, untried, media, opts) do
    timeout = Keyword.get(opts, :timeout, Map.get(@default_timeouts, fwd.method, 60))

    # NOT SIP.Session.send_sip_request/3: that one routes through
    # sip_ctx.dialogpid, which is the INBOUND leg.
    #
    # `fork:` is declared here, not on the first fork_branch/2: this very request
    # is the first branch, and with more targets behind it its failure must end
    # the branch rather than the dialog. The siblings of a parallel rung go the
    # same way — armed inside the dialog's init, before any of their responses
    # can be processed (SIP.Dialog.start_dialog/5).
    # A ladder with a rung left counts as forking for the same reason a hunt
    # does: this attempt's failure must end the BRANCH and not the dialog, or
    # there is nothing left to offer the next profile on (§7.5). A `_required`
    # profile has one rung and therefore changes nothing.
    forking =
      untried != [] or provider_of(peer) != nil or
        length(Profile.ladder(peer.profile)) > 1

    sibling_uris = Enum.map(siblings, &branch_uri(fwd, &1, peer))

    dialog_opts = [
      tag: @outbound_tag,
      fork: if(sibling_uris == [], do: forking, else: sibling_uris)
    ]

    case SIP.Dialog.start_dialog(fwd, timeout, :outbound, sip_ctx.debug, dialog_opts) do
      {:ok, dialog_pid, _dialog_id} ->
        trans_pid = await_initial_transaction()
        sibling_tids = await_rung_branches(length(siblings))

        leg = %Leg{
          tag: @outbound_tag,
          dialogpid: dialog_pid,
          peer: peer,
          target: target,
          fwd_ruri: fwd.ruri,
          branches: [{trans_pid, target} | Enum.zip(sibling_tids, siblings)],
          untried: untried,
          method: fwd.method,
          initial_trans: trans_pid,
          media: media,
          profile: first_rung(peer),
          profiles_left: Enum.drop(Profile.ladder(peer.profile), 1)
        }

        sip_ctx
        |> put_leg(@outbound_tag, leg)
        |> add_pending(trans_pid, orig_req, :inbound, fwd.method)
        |> put_last_invite(@outbound_tag, fwd.method, trans_pid)
        |> note_rung([target | siblings])
        |> SIP.Context.set(:lasterr, :ok)

      {:error, reason} ->
        fail(sip_ctx, {:b2bua, :leg_creation_failed, reason})

      other ->
        fail(sip_ctx, {:b2bua, :leg_creation_failed, other})
    end
  end

  # The dialog publishes its initial UAC transaction as {:onnewdialog, :ok, tid}
  # — tagged, like everything else it sends us. Delivered during dialog creation,
  # so it is already in the mailbox; the timeout is only a safety net (same
  # contract as SIP.Session.register_initial_transaction/2).
  defp await_initial_transaction do
    receive do
      {@outbound_tag, {:onnewdialog, :ok, trans_pid}} ->
        trans_pid
    after
      500 ->
        Logger.warning(
          module: __MODULE__,
          message: "No :onnewdialog from the outbound leg; its initial transaction is unknown"
        )

        nil
    end
  end

  # The extra branches of the first rung, announced one `{:onnewbranch, …}` each
  # by the dialog's init. Already in the mailbox by the time we ask, like
  # `:onnewdialog` above; a branch that could not be armed answers `:error` and
  # is dropped, since the rest of the rung is still ringing.
  defp await_rung_branches(0), do: []

  defp await_rung_branches(count) do
    Enum.flat_map(1..count, fn _ ->
      receive do
        {@outbound_tag, {:onnewbranch, :ok, trans_pid}} ->
          [trans_pid]

        {@outbound_tag, {:onnewbranch, :error, reason}} ->
          Logger.warning(
            module: __MODULE__,
            message: "b2bua: branch not armed: #{inspect(reason)}"
          )

          []
      after
        500 ->
          Logger.warning(module: __MODULE__, message: "b2bua: a rung branch was never announced")
          []
      end
    end)
  end

  # What a branch toward `target` must carry as its Request-URI. The dialog puts
  # whatever it is handed straight into the R-URI, so the two questions of
  # `apply_target/3` have to be answered HERE for every branch after the first —
  # otherwise a `ruri: :keep` peer (the trunk case: route to the gateway, leave
  # the R-URI alone) has its second branch rewritten to the gateway's URI, and a
  # per-peer outbound proxy applies to the first target only.
  defp branch_uri(%{ruri: _} = fwd, target, %Peer{} = peer) do
    case apply_target(fwd, target, peer) do
      {:ok, %{ruri: uri}} ->
        uri

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "b2bua: cannot compose a branch toward #{target} (#{inspect(reason)})"
        )

        target
    end
  end

  # One `:serial_attempting` per target of the rung: a rung of one reads exactly
  # as a serial hunt always did, and a group says which devices are ringing.
  defp note_rung(sip_ctx, targets) do
    Enum.reduce(targets, sip_ctx, &note_progress(&2, {:serial_attempting, &1, now()}))
  end

  # Two separate questions, answered in order: WHAT the forwarded request asks
  # for (the R-URI policy) and WHERE it is sent (the peer's outbound proxy, when
  # it has one). They are orthogonal, which is the whole reason %SIP.Uri{} keeps
  # its routing next to its identity.
  defp apply_target(req, target, %Peer{} = peer) do
    with {:ok, req} <- apply_ruri_policy(req, target, peer.ruri) do
      route_via(req, peer.outbound_proxy)
    end
  end

  # `:peer` — the forwarded request asks for the target itself (kamailio $ru).
  # `:keep` — the request keeps asking for what it asked for, and is merely SENT
  # to the target (kamailio $du): resolve the target and copy its routing onto
  # the original R-URI, which prepare_forwarded_request/2 has already stripped of
  # the inbound leg's routing.
  defp apply_ruri_policy(req, target, :peer), do: {:ok, %{req | ruri: target}}

  defp apply_ruri_policy(req, target, :keep) do
    case resolve(target) do
      %SIP.Uri{} = resolved ->
        {:ok, %{req | ruri: stamp_destination(req.ruri, resolved)}}

      err ->
        {:error, {:cannot_route_to, target, err}}
    end
  end

  defp apply_ruri_policy(_req, _target, other), do: {:error, {:bad_ruri_policy, other}}

  # This peer's own next hop. The global `:proxyuri` application env is still
  # honoured underneath (SIP.Resolver.resolve_and_add_dest/1 applies it when
  # nothing here does), but it is process-global: one next hop for the whole
  # node, which is fine for elixipp and wrong for a server whose peers sit behind
  # different gateways. Set here, it wins — including over the destination a
  # `:keep` policy just stamped, since the proxy IS where the request goes.
  defp route_via(req, nil), do: {:ok, req}

  defp route_via(req, proxy) do
    case resolve(normalize_uri(proxy)) do
      %SIP.Uri{} = resolved ->
        {:ok, %{req | ruri: stamp_destination(req.ruri, resolved)}}

      err ->
        {:error, {:cannot_route_via_proxy, proxy, err}}
    end
  end

  # Copy the routing of `from` onto `uri`, leaving what the URI *says* alone.
  defp stamp_destination(%SIP.Uri{} = uri, %SIP.Uri{} = from) do
    %SIP.Uri{
      uri
      | destip: from.destip,
        destport: from.destport,
        destproto: from.destproto,
        tp_module: from.tp_module,
        tp_pid: from.tp_pid
    }
  end

  # The peer's URIs, each expanded into one target per SRV destination when
  # `use_srv` asks for it (§3.1 case 1).
  #
  # Flattening is all it takes: a %SIP.Uri{} carries its own destination, so "the
  # same URI at another address" is just another target, and the serial hunt
  # walks the result without knowing SRV exists. Nothing two-level is needed.
  #
  # RFC 2782 order comes from SIP.Resolver.order_srv/1: priorities ascending,
  # weighted draw within each. A domain that publishes no SRV keeps its URI as
  # given, so `use_srv: true` is safe to leave on.
  # The result is a list of **rungs**: a rung is dialled all at once, the rungs
  # are walked in order.
  #
  # A `:parallel` peer gets one rung per entry of `uris` — a nested entry is a
  # group to ring together (equal q for a registrar peer, RFC 3261 §16.6:
  # parallel within a group, serial across groups in descending q).
  defp expand_targets(%Peer{fork: :parallel} = peer) do
    Enum.map(peer.uris, fn entry ->
      entry |> List.wrap() |> Enum.flat_map(&srv_expand(&1, peer))
    end)
  end

  # Anything else is rungs of one, which is the flat list a serial hunt has
  # always walked — including SRV multiplicity, which is a failover list and
  # never a group (§3.1): the same service reached at another address is one
  # target tried twice, and ringing both would double every call to that domain.
  defp expand_targets(%Peer{} = peer) do
    peer.uris
    |> Enum.flat_map(fn entry -> entry |> List.wrap() |> Enum.flat_map(&srv_expand(&1, peer)) end)
    |> Enum.map(&[&1])
  end

  defp srv_expand(uri, %Peer{use_srv: false}), do: [normalize_uri(uri)]

  defp srv_expand(uri, %Peer{}) do
    uri = normalize_uri(uri)

    case SIP.Resolver.srv_targets(uri) do
      {:ok, [_ | _] = targets} -> targets
      _ -> [uri]
    end
  end

  # A target that already carries its destination (a registrar contact, §3.2) is
  # taken as is — that is the whole point of storing the registration flow.
  defp resolve(%SIP.Uri{} = uri) do
    if SIP.Uri.has_tp_info(uri), do: uri, else: SIP.Transport.Selector.select_transport(uri)
  end

  # ── Relaying requests ───────────────────────────────────────────────────────

  @doc false
  @spec do_relay_request(%SIP.Context{}, map()) :: %SIP.Context{}
  def do_relay_request(sip_ctx = %SIP.Context{}, req) when is_map(req) do
    from_leg = current_leg()
    sip_ctx = remember_remote_sdp(sip_ctx, from_leg, SIP.Msg.Ops.sdp_body(req))

    cond do
      # An ACK for a 200 WE sent (b2bua_reply_reoffer/1) confirms nothing on the
      # other leg. It is consumed here, so a scenario keeps its one ACK clause.
      Map.get(req, :method) == :ACK and local_ack?(sip_ctx, from_leg) ->
        absorb_local_ack(sip_ctx, from_leg, req)

      true ->
        # Any other request from this leg supersedes an ACK we are still waiting
        # for: without this, a peer that never acknowledged our 200 would have
        # the NEXT relayed re-INVITE's ACK absorbed instead of relayed.
        sip_ctx = forget_local_ack(sip_ctx, from_leg)

        case other_leg_pid(sip_ctx, from_leg) do
          nil ->
            fail(sip_ctx, {:b2bua, :no_leg_to_relay_to, from_leg})

          target_pid ->
            relay_request(sip_ctx, req, from_leg, target_pid)
        end
    end
  end

  # An ACK matches no transaction of its own (RFC 3261 §17.2.3): it confirms the
  # 2xx of the INVITE we forwarded, so it is translated onto that transaction
  # rather than re-sent as a request.
  defp relay_request(sip_ctx, %{method: :ACK}, from_leg, _target_pid) do
    case correlated_invite(sip_ctx, from_leg) do
      {dialog_pid, trans_pid} when is_pid(trans_pid) ->
        case call_leg(fn -> SIP.Dialog.ack(dialog_pid, trans_pid) end) do
          :leg_dead -> fail(sip_ctx, {:b2bua, :leg_dead, :ACK})
          rc -> SIP.Context.set(sip_ctx, :lasterr, ack_lasterr(rc))
        end

      _ ->
        Logger.warning(
          module: __MODULE__,
          message: "Nothing to ACK on the other leg (no correlated INVITE transaction)"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  # Likewise a CANCEL cancels the INVITE we forwarded. The inbound dialog has
  # already auto-answered the CANCEL and is tearing down; all we owe the callee
  # is the CANCEL of its own INVITE.
  defp relay_request(sip_ctx, %{method: :CANCEL}, from_leg, _target_pid) do
    case correlated_invite(sip_ctx, from_leg) do
      {dialog_pid, trans_pid} when is_pid(trans_pid) ->
        case call_leg(fn -> SIP.Dialog.cancel(dialog_pid, trans_pid) end) do
          :leg_dead -> fail(sip_ctx, {:b2bua, :leg_dead, :CANCEL})
          rc -> SIP.Context.set(sip_ctx, :lasterr, ack_lasterr(rc))
        end

      _ ->
        Logger.warning(
          module: __MODULE__,
          message: "Nothing to CANCEL on the other leg (no correlated INVITE transaction)"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  defp relay_request(sip_ctx, req, from_leg, target_pid) do
    case SIP.Msg.Ops.prepare_forwarded_request(req) do
      {:error, reason} ->
        fail(sip_ctx, {:b2bua, reason})

      {:ok, fwd} ->
        case media_reoffer(sip_ctx, req, from_leg) do
          {:pass, sip_ctx} ->
            send_relayed(sip_ctx, req, fwd, from_leg, target_pid, nil)

          {:ok, sip_ctx, held_answer, our_offer} ->
            fwd = with_sdp(fwd, our_offer)
            send_relayed(sip_ctx, req, fwd, from_leg, target_pid, held_answer)

          {:error, sip_ctx, reason} ->
            refuse_reoffer(sip_ctx, req, reason)
        end
    end
  end

  defp send_relayed(sip_ctx, req, fwd, from_leg, target_pid, held_answer) do
    # The dialog layer re-addresses the request wholesale (Call-ID, CSeq,
    # tags, route set, remote target — fix_outbound_request/3), so what the
    # purge above contributes is dropping the hop-scoped headers and the
    # inbound leg's routing.
    case call_leg(fn -> SIP.Dialog.new_request(target_pid, fwd) end) do
      {:ok, trans_pid} ->
        # WHICH WAY it went, named rather than deduced. The transaction layer logs
        # "Sent BYE <ruri>", which says where the request landed but not which leg
        # asked for it — and reading the direction back from a Request-URI means
        # knowing both peers' Contacts by heart. A B2BUA relaying a hangup to the
        # side that just hung up and one relaying it correctly produce logs that
        # differ by one URI; this line is what tells them apart (traffic of
        # 2026-08-14, an hour spent on exactly that question).
        Logger.info(
          dialogpid: sip_ctx.dialogpid,
          module: __MODULE__,
          message: "relayed #{req.method} from the #{from_leg} leg to the #{other_leg(from_leg)}"
        )

        sip_ctx
        |> add_pending(trans_pid, req, from_leg, req.method, held_answer)
        |> put_last_invite(other_leg(from_leg), req.method, trans_pid)
        |> SIP.Context.set(:lasterr, :ok)

      :leg_dead ->
        fail(sip_ctx, {:b2bua, :leg_dead, req.method})

      # Both ends hung up at once: the BYE this one is relaying meets a dialog
      # already closing on the other side's own BYE. Nothing to relay — what the
      # BYE asks for is already happening — and nothing failed either: the local
      # 200 to the sender goes out through the ordinary path.
      :already_closing when req.method == :BYE ->
        Logger.info(
          dialogpid: sip_ctx.dialogpid,
          module: __MODULE__,
          message: "BYE from the #{from_leg} leg not relayed: the #{other_leg(from_leg)} is already closing"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)

      err ->
        fail(sip_ctx, {:b2bua, :relay_failed, req.method, err})
    end
  end

  # In media mode a relayed re-offer carries OURS, exactly like the initial
  # INVITE did (§7.2): the peer's new description goes to its own endpoint, and
  # the far end is offered ours. Without this the two peers would read each
  # other's SDP on every re-INVITE — the one thing terminating the media promises
  # they never do.
  defp media_reoffer(sip_ctx, req, from_leg) do
    cond do
      is_nil(media_plan(sip_ctx)) -> {:pass, sip_ctx}
      Map.get(req, :method) not in [:INVITE, :UPDATE] -> {:pass, sip_ctx}
      true -> media_reoffer_bodies(sip_ctx, req, from_leg)
    end
  end

  defp media_reoffer_bodies(sip_ctx, req, from_leg) do
    to_leg = other_leg(from_leg)

    case SIP.Msg.Ops.sdp_body(req) do
      sdp when is_binary(sdp) and sdp != "" ->
        with {sip_ctx, {:ok, held}} <-
               media_answer(sip_ctx, sdp, [leg: from_leg] ++ leg_media_opts(sip_ctx, from_leg)),
             {:ok, sip_ctx, offer} <-
               media_offer_on(sip_ctx, to_leg, leg_media_opts(sip_ctx, to_leg)) do
          {:ok, sip_ctx, held, offer}
        else
          {sip_ctx = %SIP.Context{}, {:error, reason}} -> {:error, sip_ctx, reason}
          {:error, sip_ctx = %SIP.Context{}, reason} -> {:error, sip_ctx, reason}
        end

      _offerless ->
        # Relaying this would mean answering it with an offer of ours (RFC 3261
        # §14.2) while asking the far end for one of its own — two offer/answer
        # exchanges we did not start, on a change neither peer made. It is what
        # `:no_sdp` is classified for: `b2bua_reply_reoffer/1` answers it here.
        {:error, sip_ctx, :offerless_reoffer_not_relayable}
    end
  end

  # The media plane could not take the re-offer, so nothing crosses and the leg
  # that sent it is told. Same conversion as the 2xx case (R4.2): a media failure
  # the scenario reads in `lasterr`, rather than a relay that silently did
  # nothing and a peer left waiting for a response.
  defp refuse_reoffer(sip_ctx, req, reason) do
    sip_ctx
    |> do_local_reply(req, 488, "Not Acceptable Here", [])
    |> fail({:b2bua, :reoffer_relay_failed, reason})
  end

  defp with_sdp(msg, sdp) do
    SIP.Msg.Ops.update_sip_msg(msg, {:body, [%{contenttype: "application/sdp", data: sdp}]})
  end

  # The INVITE transaction of the leg opposite `from_leg`: what an ACK or a
  # CANCEL arriving on `from_leg` acts upon.
  #
  # `last_invite` and not `%Leg{initial_trans}`, because the two stop agreeing as
  # soon as the call is established: a re-INVITE relayed onto a leg opens a NEW
  # client transaction, and the 2xx that answers it is acknowledged on that one
  # (RFC 3261 §13.2.2.4 — the ACK of a 2xx is a transaction of its own). Posting
  # it on `initial_trans` acknowledges an INVITE that was answered minutes ago,
  # which the far end reads as "no ACK": it retransmits its 200 until timer H and
  # then gives up on a call that is up.
  #
  # Symmetric, and that is the point: a re-INVITE from the CALLEE is relayed onto
  # the inbound leg, where we are the UAC for it — so the callee's ACK has an
  # inbound client transaction to act on, which the previous nil-returning clause
  # made unreachable. The initial INVITE keeps its old behaviour: nothing was
  # ever sent toward the inbound leg, so `last_invite[:inbound]` is nil and the
  # caller's ACK still finds nothing to translate there.
  defp correlated_invite(sip_ctx, from_leg) do
    target = other_leg(from_leg)

    case {leg_pid(sip_ctx, target), Map.get(state(sip_ctx).last_invite, target)} do
      {dialog_pid, trans_pid} when is_pid(dialog_pid) and is_pid(trans_pid) ->
        {dialog_pid, trans_pid}

      _ ->
        nil
    end
  end

  # ── Relaying responses ──────────────────────────────────────────────────────

  @doc false
  @spec do_relay_reply(%SIP.Context{}, map()) :: %SIP.Context{}
  def do_relay_reply(sip_ctx = %SIP.Context{}, resp) when is_map(resp) do
    # A rung's branches are N transactions attempting ONE relayed request, so
    # everything downstream works on the branch the correlation is filed under —
    # and, once a branch answers 2xx, on that branch, which is the one the leg
    # keeps (its ACK, its BYE and every later in-dialog request go to it).
    sip_ctx = adopt_winning_branch(sip_ctx, resp, current_tid())
    tid = pending_key(sip_ctx, current_tid())

    # Whatever else it is, a response carrying SDP is this leg describing itself:
    # the callee's answer to the initial INVITE, or its answer to a re-offer we
    # relayed. Either way it is what the NEXT re-offer from that leg is read
    # against (§R4.1b).
    sip_ctx = remember_remote_sdp(sip_ctx, current_leg(), SIP.Msg.Ops.sdp_body(resp))
    state = state(sip_ctx)

    case Map.get(state.pending, tid) do
      %Pending{} = pending ->
        # With a media server the response is not relayed as it stands: its SDP
        # is the callee's, and what the caller must receive is ours.
        {sip_ctx, resp} = media_step(sip_ctx, resp, tid)

        # A refusal from one target of a serial hunt is not the answer to the
        # call — it is the answer of one device. Try the next one instead of
        # telling the caller the call failed.
        # Before the hunt: a refusal of the OFFER is not a refusal by the device,
        # and the same targets get another profile before the next ones get
        # anything (§7.5).
        if fallback?(sip_ctx, resp, tid) do
          fall_back_one_rung(sip_ctx, resp, pending, tid)
        else
          hunt_or_relay(sip_ctx, resp, pending, tid)
        end

      nil ->
        # A retransmitted final, or a response to something this scenario never
        # forwarded. Neither is fatal: say so and carry on.
        Logger.warning(
          module: __MODULE__,
          message:
            "No forwarded request correlates with the #{resp.response} on transaction " <>
              "#{inspect(tid)}; not relaying it"
        )

        SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  # What a `{:mediaserver, …}` call does to a response before it is relayed —
  # nothing at all in signalling mode, and nothing to any response that is not
  # the answer to the attempt in flight.
  defp media_step(sip_ctx, resp, tid) do
    plan = media_plan(sip_ctx)
    pending = Map.get(state(sip_ctx).pending, tid)

    cond do
      is_nil(plan) ->
        {sip_ctx, resp}

      match?(%Pending{held_answer: held} when is_binary(held), pending) ->
        reoffer_step(sip_ctx, resp, pending)

      not attempt_response?(sip_ctx, tid) ->
        {sip_ctx, resp}

      resp.response in 200..299 ->
        complete_media(sip_ctx, resp, plan, tid)

      resp.response in 101..199 ->
        {sip_ctx, strip_early_sdp(resp)}

      true ->
        {sip_ctx, resp}
    end
  end

  # The far end answered a re-offer we relayed: same choreography as the initial
  # INVITE, one exchange later. Its answer goes to ITS endpoint, and the leg that
  # re-offered receives the answer we have been holding since it did.
  defp reoffer_step(sip_ctx, resp, %Pending{held_answer: held, orig_leg: from_leg}) do
    cond do
      resp.response in 200..299 ->
        sip_ctx =
          case SIP.Msg.Ops.sdp_body(resp) do
            sdp when is_binary(sdp) and sdp != "" -> process_answer(sip_ctx, current_leg(), sdp)
            _no_answer -> sip_ctx
          end

        # Both legs are known again: the selection is re-taken and the held
        # answer superseded by the one built against it (§2.6). Holding it was
        # never enough on its own — the answer we were holding was decided when
        # the re-offer ARRIVED, one exchange before the far end said what it
        # would carry, and sending it unchanged is what answered a re-INVITE
        # AV1-first to a peer that only ever carried VP8 (2026-08-13).
        {sip_ctx, held} = rebridge(sip_ctx, from_leg, held)

        {sip_ctx, with_sdp(resp, held)}

      # A provisional to a re-INVITE is not an offer/answer event any more than
      # it was on the initial one.
      resp.response in 101..199 ->
        {sip_ctx, strip_early_sdp(resp)}

      # Refused at the far end. RFC 3261 §14.1 leaves that session as it was and
      # the refusal crosses untouched — our own endpoint has already moved to the
      # new description, which is the one place the two disagree until the peer
      # re-offers again.
      true ->
        {sip_ctx, resp}
    end
  end

  defp attempt_response?(sip_ctx, tid) do
    match?(%Leg{initial_trans: ^tid}, outbound_leg(sip_ctx))
  end

  # The branch a response arrived on, mapped back to the branch the caller's
  # `%Pending{}` is filed under. One request was relayed; a rung is only several
  # ways of asking it, and nothing downstream should have to know which one
  # answered.
  defp pending_key(sip_ctx, tid) do
    case outbound_leg(sip_ctx) do
      %Leg{initial_trans: rep, branches: branches} when is_pid(rep) ->
        if List.keymember?(branches, tid, 0), do: rep, else: tid

      _ ->
        tid
    end
  end

  # A branch answered 2xx: it is the leg now. The dialog has already CANCELled
  # its siblings and adopted its to-tag (§3.3); what the session owes is to point
  # everything keyed on "the attempt" at the branch that won — `last_invite`
  # above all, since the ACK of that 2xx is sent on the transaction that carried
  # it, and the rest of the rung is gone.
  defp adopt_winning_branch(sip_ctx, resp, tid) do
    with true <- resp.response in 200..299,
         %Leg{initial_trans: rep, branches: branches} = leg <- outbound_leg(sip_ctx),
         true <- rep != tid,
         {^tid, target} <- List.keyfind(branches, tid, 0) do
      pending = Map.get(state(sip_ctx).pending, rep)

      sip_ctx
      |> put_leg(@outbound_tag, %Leg{
        leg
        | target: target,
          initial_trans: tid,
          branches: [{tid, target}],
          untried: []
      })
      |> put_last_invite(@outbound_tag, leg.method, tid)
      |> move_pending(rep, tid, pending)
    else
      _ -> sip_ctx
    end
  end

  # The branches of the rung in flight. A leg created before this field existed —
  # or one whose branches were never announced — still has its initial
  # transaction, which is what the single-branch code always cancelled.
  defp live_branches(%Leg{branches: [_ | _] = branches}), do: branches

  defp live_branches(%Leg{initial_trans: tid, target: target}) when is_pid(tid),
    do: [{tid, target}]

  defp live_branches(_leg), do: []

  defp move_pending(sip_ctx, _from, _to, nil), do: sip_ctx

  defp move_pending(sip_ctx, from, to, %Pending{} = pending) do
    sip_ctx
    |> drop_pending(from)
    |> add_pending(to, pending.orig_req, pending.orig_leg, pending.method, pending.held_answer)
  end

  # A 18x carrying the callee's SDP. Without a media server relaying it would
  # pin the leg to that target and end the hunt (§7.4); WITH one it is not even
  # an offer/answer event — the caller's answer comes from the media server and
  # was decided when their INVITE arrived. So the body is dropped and the
  # provisional relayed without it, which is what keeps the hunt open.
  defp strip_early_sdp(resp) do
    case SIP.Session.extract_sdp(resp) do
      sdp when is_binary(sdp) and sdp != "" -> SIP.Msg.Ops.update_sip_msg(resp, {:body, []})
      _ -> resp
    end
  end

  # The callee answered: feed its answer to the outbound endpoint, attach the two
  # endpoints, and hand the caller the answer we have been holding since their
  # INVITE. This is the `buildBridge` moment — the first instant at which both
  # sides of the media are known.
  defp complete_media(sip_ctx, resp, %MediaPlan{} = plan, tid) do
    with {:ok, answer_b} <- callee_answer(resp),
         :ok <- ms_set_remote_answer(sip_ctx, answer_b),
         {sip_ctx, :ok} <- attach_legs(sip_ctx, plan, []),
         # BOTH legs are up at this one instant: the callee is sending (it
         # answered 2xx) and the caller will be as soon as the 200 this function
         # returns reaches it. That is what the media layer needs to know before
         # it may watch either leg for silence — the caller's leg was negotiated
         # when its INVITE arrived, tens of seconds of ringing ago (see
         # `MediaServer.Behaviour.call_answered/1`).
         sip_ctx = Media.call_answered(sip_ctx) do
      # `media_plan(sip_ctx)`, NOT `plan`. `attach_legs` rebinds only `sip_ctx`;
      # `plan` is still the struct bound as this function's parameter, so reading
      # it here would send the answer held since the INVITE and silently discard
      # the one the media server rebuilt now that both legs are known. The plan
      # travels in the context precisely because it is written there.
      {SIP.Context.set(sip_ctx, :lasterr, :ok), with_our_answer(resp, media_plan(sip_ctx))}
    else
      {_sip_ctx, {:error, reason}} -> media_answer_failed(sip_ctx, resp, tid, reason)
      {:error, reason} -> media_answer_failed(sip_ctx, resp, tid, reason)
    end
  end

  defp callee_answer(resp) do
    case SIP.Session.extract_sdp(resp) do
      sdp when is_binary(sdp) and sdp != "" -> {:ok, sdp}
      _ -> {:error, :no_answer_in_2xx}
    end
  end

  defp ms_set_remote_answer(sip_ctx, answer) do
    case Media.peer_connection(sip_ctx, :outbound) do
      nil -> {:error, :no_outbound_peer_connection}
      cnx -> apply(sip_ctx.mediaservermodule, :set_remote_answer, [cnx, answer])
    end
  rescue
    err -> {:error, {:media_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, {:media_down, reason}}
  end

  # `bridge/3`, done once. Returns the context so the plan can record it: a
  # scenario that bridged early (b2bua_bridge/0..1 on a 183) must not have the
  # 2xx attach a second time.
  defp attach_legs(sip_ctx, %MediaPlan{bridged: true} = _plan, _overrides), do: {sip_ctx, :ok}

  defp attach_legs(sip_ctx, %MediaPlan{} = plan, overrides) do
    pc_in = Media.peer_connection(sip_ctx, :inbound)
    pc_out = Media.peer_connection(sip_ctx, :outbound)

    if is_nil(pc_in) or is_nil(pc_out) do
      {sip_ctx, {:error, :media_legs_incomplete}}
    else
      opts = Keyword.merge(Map.to_list(plan.policy), overrides)

      case protected_bridge(sip_ctx, pc_in, pc_out, opts) do
        :ok ->
          {put_media_plan(sip_ctx, %MediaPlan{plan | bridged: true}), :ok}

        # The media server rebuilt the caller's answer now that both legs are
        # known — a relayed media narrowed to what both can carry. It supersedes
        # the one held since the INVITE, which is still unsent (§7.4): the caller
        # is answered from `complete_media`, and no 1xx carries this body.
        {:ok, %{inbound_answer: sdp}} when is_binary(sdp) ->
          {put_media_plan(sip_ctx, %MediaPlan{plan | bridged: true, inbound_answer: sdp}), :ok}

        err ->
          {sip_ctx, err}
      end
    end
  end

  defp rebridge_after_local_answer(sip_ctx, req, leg) do
    case SIP.Msg.Ops.sdp_body(req) do
      sdp when is_binary(sdp) and sdp != "" ->
        {sip_ctx, _held} = rebridge(sip_ctx, leg, nil)
        sip_ctx

      _offerless ->
        sip_ctx
    end
  end

  # The cross-leg selection, taken again after a renegotiation. `bridge/3` is
  # idempotent by contract and keeps the wiring it can, so this is not a rebuild:
  # it is the one call that lets the media server notice that a leg now carries
  # something else. Without it the transcoders keep producing the codec chosen at
  # the first bridge, and SDP has no way to say so — the far end decodes the
  # wrong codec believing it decoded the right one (§2.3).
  #
  # Returns the answer owed to `answered_leg`: the rebuilt one when the media
  # server produced it, the held one otherwise. A media server that cannot
  # re-bridge leaves the call exactly as it was — the signalling still completes,
  # which is better than tearing down a call that is up over a preference.
  defp rebridge(sip_ctx, answered_leg, held) do
    plan = media_plan(sip_ctx)
    pc_in = Media.peer_connection(sip_ctx, :inbound)
    pc_out = Media.peer_connection(sip_ctx, :outbound)

    if is_nil(plan) or is_nil(pc_in) or is_nil(pc_out) do
      {sip_ctx, held}
    else
      case protected_bridge(sip_ctx, pc_in, pc_out, Map.to_list(plan.policy)) do
        {:ok, %{answers: answers}} ->
          {sip_ctx, Map.get(answers, answered_leg, held)}

        :ok ->
          {sip_ctx, held}

        {:ok, _other} ->
          {sip_ctx, held}

        {:error, reason} ->
          Logger.warning(
            module: __MODULE__,
            message:
              "b2bua: the media could not be re-bridged after the renegotiation " <>
                "(#{inspect(reason)}); the call keeps the previous selection"
          )

          {sip_ctx, held}
      end
    end
  end

  defp protected_bridge(sip_ctx, pc_in, pc_out, opts) do
    apply(sip_ctx.mediaservermodule, :bridge, [pc_in, pc_out, opts])
  rescue
    err -> {:error, {:media_raised, Exception.message(err)}}
  catch
    :exit, reason -> {:error, {:media_down, reason}}
  end

  defp with_our_answer(resp, %MediaPlan{inbound_answer: sdp}) when is_binary(sdp) do
    SIP.Msg.Ops.update_sip_msg(resp, {:body, [%{contenttype: "application/sdp", data: sdp}]})
  end

  defp with_our_answer(resp, _plan), do: resp

  # The bridge could not be built, and the callee has already answered 200: it
  # believes the call is up. Three things are owed, in this order (§R4.2):
  #
  #   1. ACK its 2xx — RFC 3261 §13.2.2.4, or it retransmits into a dialog
  #      nobody ends — and then BYE the dialog that ACK established. The
  #      framework does this itself: it is an obligation, not a policy;
  #   2. say what happened, in `lasterr`, so a scenario with its own policy has
  #      something to read;
  #   3. hand the hunt a 488 instead of the 200. Not a fabrication for its own
  #      sake: a callee whose media we cannot bridge IS "this device did not
  #      work, try the next", so the existing retry machinery applies unchanged,
  #      and the caller ends up with a 488 only if nothing else answers.
  defp media_answer_failed(sip_ctx, resp, tid, reason) do
    Logger.warning(
      module: __MODULE__,
      message:
        "b2bua: the callee answered #{resp.response} but its media cannot be bridged " <>
          "(#{inspect(reason)}); ending that leg and treating it as a failed attempt"
    )

    end_unbridgeable_leg(sip_ctx, tid)

    sip_ctx =
      case media_plan(sip_ctx) do
        %MediaPlan{} = plan ->
          put_media_plan(sip_ctx, %MediaPlan{plan | error: reason, bridged: false})

        _ ->
          sip_ctx
      end

    {sip_ctx, media_failed_response(resp)}
  end

  defp end_unbridgeable_leg(sip_ctx, tid) do
    case outbound_leg(sip_ctx) do
      %Leg{dialogpid: dialog_pid} when is_pid(dialog_pid) ->
        protect("ACK the 2xx of a leg we cannot bridge", fn ->
          SIP.Dialog.ack(dialog_pid, tid)
        end)

        protect("BYE the leg we cannot bridge", fn ->
          SIP.Dialog.new_request(dialog_pid, bye_request())
        end)

      _ ->
        :ok
    end
  end

  defp media_failed_response(resp) do
    %{resp | response: 488, reason: "Not Acceptable Here"}
    |> SIP.Msg.Ops.update_sip_msg({:body, []})
  end

  @doc false
  @spec do_bridge_legs(%SIP.Context{}, keyword()) :: %SIP.Context{}
  def do_bridge_legs(sip_ctx = %SIP.Context{}, overrides \\ []) do
    case media_plan(sip_ctx) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_media_plan})

      %MediaPlan{} = plan ->
        case attach_legs(sip_ctx, plan, overrides) do
          {sip_ctx, :ok} -> SIP.Context.set(sip_ctx, :lasterr, :ok)
          {sip_ctx, {:error, reason}} -> fail(sip_ctx, {:b2bua, :media_bridge_failed, reason})
        end
    end
  end

  @doc false
  @spec do_unbridge_legs(%SIP.Context{}) :: %SIP.Context{}
  def do_unbridge_legs(sip_ctx = %SIP.Context{}) do
    pc_in = Media.peer_connection(sip_ctx, :inbound)
    pc_out = Media.peer_connection(sip_ctx, :outbound)

    if is_nil(pc_in) or is_nil(pc_out) do
      fail(sip_ctx, {:b2bua, :media_legs_incomplete})
    else
      protect("unbridge the legs", fn ->
        apply(sip_ctx.mediaservermodule, :unbridge, [pc_in, pc_out])
      end)

      sip_ctx =
        case media_plan(sip_ctx) do
          %MediaPlan{} = plan -> put_media_plan(sip_ctx, %MediaPlan{plan | bridged: false})
          _ -> sip_ctx
        end

      SIP.Context.set(sip_ctx, :lasterr, :ok)
    end
  end

  # ── Serial hunt (§3.1, §3.3) ────────────────────────────────────────────────

  # Which final responses make a hunt move on. The default is any 4xx or 5xx:
  # the device refused, timed out or broke, and another one may still answer.
  #
  # NOT 6xx — a 6xx is a global refusal ("Decline", "Does Not Exist Anywhere")
  # and RFC 3261 §16.7 stops the search on it; ringing the user's other phones
  # after they pressed Decline is exactly what they asked not to happen.
  # NOT 3xx — a redirect names new targets, which is its own handling (P4).
  # NOT 487 either, whatever the peer asks for — see @never_retry.
  @default_retry_on [400..599]

  # Is this final one the PROVIDER should be asked about, rather than the end of
  # the call? Same test as the static hunt, minus the untried list — the provider
  # is the list.
  defp provider_hunt?(sip_ctx, resp, tid) do
    with %Leg{initial_trans: ^tid, cancelled: false, peer: peer} <- outbound_leg(sip_ctx),
         %Hunt{} <- hunt(sip_ctx),
         :serial <- peer.fork,
         true <- resp.response >= 300 and retryable?(peer, resp.response) do
      true
    else
      _ -> false
    end
  end

  # Report the refusal, then ask for another target. If the provider has none
  # left, the response the caller has been waiting for is relayed after all —
  # that is what `on_exhausted` carries.
  defp ask_provider_next(sip_ctx, resp, %Pending{} = pending, tid) do
    leg = outbound_leg(sip_ctx)

    sip_ctx
    |> note_progress({:serial_not_reachable, leg.target, resp.response, now()})
    |> report_outcome({:rejected, leg.target, resp.response})
    |> ask_provider_and_arm(hunt(sip_ctx), &relay_reply(&1, resp, pending, tid))
  end

  # Is there another rung to try, this response being the one the rung in flight
  # produced? Only the leg's *current* attempt is a hunt candidate: a response to
  # some in-dialog request relayed later has nothing to do with it.
  #
  # The dialog answers for the whole rung — it withholds every branch failure
  # until the last one falls and surfaces the best (§16.7) — so getting here at
  # all means the rung is over, whatever its size.
  defp next_rung?(sip_ctx, resp, tid) do
    with %Leg{initial_trans: ^tid, untried: [_next | _], peer: peer} <- outbound_leg(sip_ctx),
         true <- peer.fork in [:serial, :parallel],
         true <- resp.response >= 300 and retryable?(peer, resp.response) do
      true
    else
      _ -> false
    end
  end

  defp try_next_rung(sip_ctx, resp, %Pending{} = pending, tid) do
    leg = outbound_leg(sip_ctx)
    [rung | rest] = leg.untried
    uris = Enum.map(rung, &branch_uri(%{ruri: leg.fwd_ruri}, &1, leg.peer))
    {sip_ctx, fork_opts, profile, profiles_left} = restart_ladder(sip_ctx, leg)

    case call_leg(fn -> SIP.Dialog.fork_branch(leg.dialogpid, uris, fork_opts) end) do
      {:ok, new_trans} ->
        new_trans = List.wrap(new_trans)

        Logger.info(
          module: __MODULE__,
          message:
            "b2bua: #{leg.target} answered #{resp.response}; trying " <>
              "#{Enum.map_join(rung, ", ", &to_string/1)} (#{length(rest)} rung(s) left)"
        )

        # The correlation moves with the hunt: the caller is still waiting for an
        # answer to the SAME request, it is just other branches that will provide
        # it now. It is filed under the first of them, which is what
        # `pending_key/2` maps the whole rung back to.
        [rep | _] = new_trans

        sip_ctx
        |> drop_pending(tid)
        |> add_pending(rep, pending.orig_req, pending.orig_leg, pending.method)
        |> put_leg(@outbound_tag, %Leg{
          leg
          | target: hd(rung),
            branches: Enum.zip(new_trans, rung),
            untried: rest,
            initial_trans: rep,
            profile: profile,
            profiles_left: profiles_left
        })
        |> put_last_invite(@outbound_tag, leg.method, rep)
        |> note_progress({:serial_not_reachable, leg.target, resp.response, now()})
        |> note_rung(rung)
        |> SIP.Context.set(:lasterr, :ok)

      {:error, reason} ->
        # The hunt cannot go on (the dialog is gone, the transport failed…).
        # Relay what we have: the caller learns something rather than waiting
        # for an answer that will never come. Clearing `untried` first stops
        # this from being retried on the next response.
        Logger.warning(
          module: __MODULE__,
          message: "b2bua: cannot try #{hd(rung)} (#{inspect(reason)}); relaying #{resp.response}"
        )

        sip_ctx
        |> put_leg(@outbound_tag, %Leg{leg | untried: []})
        |> note_progress({:serial_not_reachable, hd(rung), :transport_error, now()})
        |> relay_reply(resp, pending, tid)
    end
  end

  # A refusal of one target is not the answer to the call: try the next one
  # instead of telling the caller it failed. Shared by the ordinary path and by
  # the ladder that has run out of rungs — after which a fallback code IS an
  # ordinary refusal and `retry_on` gets its usual say.
  defp hunt_or_relay(sip_ctx, resp, %Pending{} = pending, tid) do
    cond do
      provider_hunt?(sip_ctx, resp, tid) -> ask_provider_next(sip_ctx, resp, pending, tid)
      next_rung?(sip_ctx, resp, tid) -> try_next_rung(sip_ctx, resp, pending, tid)
      true -> relay_reply(sip_ctx, resp, pending, tid)
    end
  end

  # ── The offer-profile ladder (§7.5) ─────────────────────────────────────────

  # "This offer, not this device": the codes that walk the ladder down instead of
  # ending the attempt. 488 is the RFC 3261 §21.4.26 answer to a body a UAS
  # cannot accept; `fallback_on` exists because some equipment says 415 or 606
  # for the same thing.
  @default_fallback_on [488]

  # Does this final response send the SAME targets one profile down? Only the
  # rung in flight can, and only while the ladder has a rung left — the dialog
  # having already aggregated the rung's branches (§16.7), getting here means
  # every one of them is done.
  defp fallback?(sip_ctx, resp, tid) do
    with %Leg{initial_trans: ^tid, cancelled: false, profiles_left: [_ | _], peer: peer} <-
           outbound_leg(sip_ctx),
         true <- resp.response >= 300 and fallback_code?(peer, resp.response) do
      true
    else
      _ -> false
    end
  end

  defp fallback_code?(%Peer{fallback_on: nil}, code), do: code in @default_fallback_on

  defp fallback_code?(%Peer{fallback_on: specs}, code) when is_list(specs),
    do: matches_any?(specs, code)

  defp fallback_code?(%Peer{fallback_on: %Range{} = r}, code), do: code in r
  defp fallback_code?(_peer, _code), do: false

  # Re-dial the rung that just refused, one profile down. Three steps, and the
  # first is the one that costs: a local description belongs to its endpoint, so
  # another profile means another endpoint (§7.5, R3).
  #
  # The caller is not part of this. Their answer was decided when their offer was
  # read and is still held; their leg's endpoint is untouched. What they will
  # eventually receive says nothing about how many profiles it took.
  defp fall_back_one_rung(sip_ctx, resp, %Pending{} = pending, tid) do
    leg = outbound_leg(sip_ctx)
    [profile | rest] = leg.profiles_left

    case regenerate_offer(sip_ctx, profile) do
      {:ok, sip_ctx, offer} ->
        uris =
          Enum.map(leg.branches, fn {_tid, target} ->
            branch_uri(%{ruri: leg.fwd_ruri}, target, leg.peer)
          end)

        case call_leg(fn -> SIP.Dialog.fork_branch(leg.dialogpid, uris, body: offer) end) do
          {:ok, new_trans} ->
            new_trans = List.wrap(new_trans)
            [rep | _] = new_trans

            Logger.info(
              module: __MODULE__,
              message:
                "b2bua: #{leg.target} answered #{resp.response} to a #{leg.profile} offer; " <>
                  "re-offering #{profile} (#{length(rest)} profile(s) left)"
            )

            sip_ctx
            |> drop_pending(tid)
            |> add_pending(rep, pending.orig_req, pending.orig_leg, pending.method)
            |> put_leg(@outbound_tag, %Leg{
              leg
              | branches: Enum.zip(new_trans, Enum.map(leg.branches, &elem(&1, 1))),
                initial_trans: rep,
                profile: profile,
                profiles_left: rest
            })
            |> put_last_invite(@outbound_tag, leg.method, rep)
            |> note_progress({:profile_fallback, leg.target, profile, now()})
            |> SIP.Context.set(:lasterr, :ok)

          other ->
            abandon_ladder(sip_ctx, resp, pending, tid, leg, {:fork_branch, other})
        end

      {:error, sip_ctx, reason} ->
        abandon_ladder(sip_ctx, resp, pending, tid, leg, reason)
    end
  end

  # The ladder cannot be walked (the media server refused the next profile, the
  # dialog is gone…). Clearing what is left is what makes this response an
  # ordinary refusal again, so the hunt decides — and the caller learns
  # something rather than waiting for an answer that will never come.
  defp abandon_ladder(sip_ctx, resp, pending, tid, %Leg{} = leg, reason) do
    Logger.warning(
      module: __MODULE__,
      message:
        "b2bua: cannot offer the next profile (#{inspect(reason)}); #{resp.response} stands"
    )

    sip_ctx
    |> put_leg(@outbound_tag, %Leg{leg | profiles_left: []})
    |> hunt_or_relay(resp, pending, tid)
  end

  # What the NEXT set of targets is offered, and where the ladder stands for
  # them. Every rung of targets starts at the top of it: a profile was refused by
  # one device, which says nothing about the next.
  #
  # Without this, one desk phone answering 488 would leave the browser contact
  # behind it an AVP offer — which it refuses too, with no rung left to recover
  # with. A contact would be unreachable because another contact of the same AOR
  # was tried first.
  #
  # Already at the top (the ordinary case: the previous rung simply did not
  # answer) nothing is rebuilt, and the offer generated once is reused by every
  # branch, exactly as before P5.
  defp restart_ladder(sip_ctx, %Leg{peer: peer} = leg) do
    case Profile.ladder(peer.profile) do
      [] ->
        {sip_ctx, [], nil, []}

      [top | rest] when top === leg.profile ->
        {sip_ctx, [], top, rest}

      [top | rest] ->
        case regenerate_offer(sip_ctx, top) do
          {:ok, sip_ctx, offer} ->
            {sip_ctx, [body: offer], top, rest}

          {:error, sip_ctx, reason} ->
            # The next targets are rung with the offer we have rather than not
            # rung at all: a hunt that stops because the media server hiccuped
            # would lose a call that had other places to go.
            Logger.warning(
              module: __MODULE__,
              message:
                "b2bua: cannot restart the offer ladder (#{inspect(reason)}); " <>
                  "the next targets keep the #{inspect(leg.profile)} offer"
            )

            {sip_ctx, [], leg.profile, leg.profiles_left}
        end
    end
  end

  # Our offer, built again for another profile. The endpoint that carried the
  # refused one is closed first: its ports, its DTLS material and the profile of
  # its m= lines were fixed when it was created, and none of them can be
  # re-negotiated in place.
  defp regenerate_offer(sip_ctx, profile) do
    case media_plan(sip_ctx) do
      %MediaPlan{opts: opts} = plan ->
        sip_ctx = Media.drop_peer_connection(sip_ctx, :outbound)

        case media_offer(sip_ctx, profiled_outbound_opts(opts, profile)) do
          {:ok, sip_ctx, offer} ->
            plan = %MediaPlan{plan | outbound_offer: offer, bridged: false}
            {:ok, put_media_plan(sip_ctx, plan), offer}

          {:error, sip_ctx, reason} ->
            {:error, sip_ctx, reason}
        end

      _ ->
        {:error, sip_ctx, :no_media_plan}
    end
  end

  # Codes that never continue a hunt, whatever `retry_on` says.
  #
  # 487 answers an INVITE *we* terminated — a branch we cancelled, and we cancel
  # a branch because the CALLER gave up or because a better target won. Reading
  # it as "this device refused" makes the caller's own CANCEL ring the next
  # agent: they hung up, and a second phone starts ringing.
  @never_retry [487]

  defp retryable?(_peer, code) when code in @never_retry, do: false
  defp retryable?(%Peer{retry_on: nil}, code), do: matches_any?(@default_retry_on, code)
  defp retryable?(%Peer{retry_on: specs}, code) when is_list(specs), do: matches_any?(specs, code)
  defp retryable?(%Peer{retry_on: %Range{} = r}, code), do: code in r
  defp retryable?(_peer, _code), do: false

  defp matches_any?(specs, code) do
    Enum.any?(specs, fn
      %Range{} = range -> code in range
      wanted when is_integer(wanted) -> wanted == code
      _ -> false
    end)
  end

  @doc """
  Is a hunt still running on the outbound leg — i.e. did the last final response
  send us to another target rather than end the call?

  What a scenario asks after relaying a failure, to tell "this device refused,
  another is ringing" from "the call is over".
  """
  @spec hunting?(%SIP.Context{}) :: boolean()
  def hunting?(sip_ctx = %SIP.Context{}) do
    cond do
      match?(%Leg{cancelled: true}, outbound_leg(sip_ctx)) -> false
      # Parked on {:wait, ms}: nothing is ringing, and the search is very much on.
      match?(%Hunt{waiting: true}, hunt(sip_ctx)) -> true
      true -> attempt_in_flight?(sip_ctx)
    end
  end

  defp attempt_in_flight?(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{initial_trans: tid} -> Map.has_key?(state(sip_ctx).pending, tid)
      _ -> false
    end
  end

  @doc "How long the provider asked for the current target to be rung, or nil."
  @spec ring_timeout(%SIP.Context{}) :: non_neg_integer() | nil
  def ring_timeout(sip_ctx) do
    case hunt(sip_ctx) do
      %Hunt{ring_timeout: ms} -> ms
      _ -> nil
    end
  end

  @doc """
  Give up on the target being tried and ask the provider for the next one.
  Backs the `b2bua_try_next` macro (design §3.4).

  The attempt in flight is CANCELled and reported as `:no_answer` — which is
  what it is, whether a ring timeout fired or the scenario simply moved on. With
  no provider there is nothing to ask, and the call is left alone.
  """
  @spec do_try_next(%SIP.Context{}) :: %SIP.Context{}
  def do_try_next(sip_ctx = %SIP.Context{}) do
    case hunt(sip_ctx) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_provider_to_ask})

      %Hunt{} = hunt ->
        sip_ctx
        |> cancel_attempt_in_flight()
        |> report_outcome(attempt_outcome(sip_ctx))
        |> ask_provider_and_arm(hunt)
    end
  end

  # What to tell the provider about the attempt we are abandoning. No leg yet
  # means the search was parked on `{:wait, ms}` and nothing was ever tried.
  defp attempt_outcome(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{target: target} when not is_nil(target) -> {:no_answer, target}
      _ -> :abandoned
    end
  end

  # CANCEL whatever branch is ringing, if one is. Silent when there is none —
  # the hunt may be parked, or the attempt already finished.
  defp cancel_attempt_in_flight(sip_ctx) do
    case outbound_leg(sip_ctx) do
      %Leg{} = leg ->
        if leg_alive?(leg) and Map.has_key?(state(sip_ctx).pending, leg.initial_trans) do
          # Every branch of the rung, not just the one the correlation is filed
          # under: they are all ringing a phone.
          for {tid, target} <- live_branches(leg) do
            protect("cancel the attempt toward #{target}", fn ->
              SIP.Dialog.cancel(leg.dialogpid, tid)
            end)
          end
        end

      _ ->
        :ok
    end

    sip_ctx
  end

  @doc """
  Stop the hunt: CANCEL the attempt in flight, drop the untried targets, arm
  nothing more. Backs the `b2bua_cancel_forward` macro (design §3.5).

  The correlation is deliberately **kept**. The caller's INVITE still owes a
  final response, and leaving the entry in place is what gets them one — the
  branch's 487 relayed through, or failing that the §8 teardown's. Dropping it
  would leave their server transaction to time out.
  """
  @spec do_cancel_forward(%SIP.Context{}) :: %SIP.Context{}
  def do_cancel_forward(sip_ctx = %SIP.Context{}) do
    case outbound_leg(sip_ctx) do
      nil ->
        # No leg — but there may be a search parked on {:wait, ms}, whose
        # reservation still has to be released. Otherwise a no-op: a scenario
        # may say this defensively.
        sip_ctx
        |> report_outcome(:abandoned)
        |> put_hunt(nil)
        |> SIP.Context.set(:lasterr, :ok)

      %Leg{} = leg ->
        sip_ctx
        |> cancel_attempt_in_flight()
        |> report_outcome(:abandoned)
        |> put_hunt(nil)
        |> put_leg(@outbound_tag, %Leg{leg | untried: [], cancelled: true})
        |> SIP.Context.set(:lasterr, :ok)
    end
  end

  # ── Progress events (§3.6) ──────────────────────────────────────────────────

  # A final that is about to be relayed rather than hunted on: the attempt the
  # caller is finally told about. Only for the leg's CURRENT initial transaction
  # — a 200 answering some relayed BYE is not a hunt outcome.
  defp note_attempt_outcome(sip_ctx, resp, tid) do
    case outbound_leg(sip_ctx) do
      %Leg{initial_trans: ^tid, target: target} when resp.response in 200..299 ->
        note_progress(sip_ctx, {:serial_connected, target, now()})

      %Leg{initial_trans: ^tid, target: target} when resp.response >= 300 ->
        sip_ctx
        |> note_progress({:serial_not_reachable, target, resp.response, now()})
        |> note_progress({:serial_exhausted, now()})

      _ ->
        sip_ctx
    end
  end

  # Put a progress event in our own mailbox, wrapped in the leg's tag like
  # everything else that leg produces — so a scenario matches it exactly where it
  # matches the traffic. Silent unless the peer asked (`notify_progress`).
  #
  # Ordering against the traffic of the next branch is not guaranteed: these come
  # from us, those from the dialog. What is exact is the timestamp, which is what
  # a record of the hunt is built from.
  defp note_progress(sip_ctx, event) do
    # From the leg, or from the hunt when there is not one yet — a provider can
    # park a caller on {:wait, ms} before anything has been dialled.
    peer =
      case outbound_leg(sip_ctx) do
        %Leg{peer: %Peer{} = peer} ->
          peer

        _ ->
          case hunt(sip_ctx) do
            %Hunt{peer: %Peer{} = peer} -> peer
            _ -> nil
          end
      end

    if match?(%Peer{notify_progress: true}, peer), do: send(self(), {@outbound_tag, event})

    sip_ctx
  end

  # Wall clock, because what these feed is a record of WHEN things happened. A
  # duration taken between two of them inherits the clock's jumps; somewhere
  # precise enough to care, use System.monotonic_time/0.
  defp now, do: DateTime.utc_now()

  defp relay_reply(sip_ctx, resp, %Pending{} = pending, tid) do
    sip_ctx = note_attempt_outcome(sip_ctx, resp, tid)

    case leg_pid(sip_ctx, pending.orig_leg) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_leg_to_reply_on, pending.orig_leg})

      dialog_pid ->
        fields = SIP.Msg.Ops.forwarded_reply_fields(resp)
        fields = maybe_add_contact(fields, sip_ctx, pending, resp)

        rc =
          call_leg(fn ->
            SIP.Dialog.reply(dialog_pid, pending.orig_req, resp.response, resp.reason, fields)
          end)

        # A final response closes the correlation; provisionals may be relayed
        # again (goto loop). The correlation is dropped either way: with the leg
        # that owed the answer gone, keeping it would only make the teardown try
        # again on the same dead dialog.
        sip_ctx =
          if resp.response >= 200 or rc == :leg_dead,
            do: drop_pending(sip_ctx, tid),
            else: sip_ctx

        if rc == :leg_dead do
          fail(sip_ctx, {:b2bua, :leg_dead, pending.orig_leg})
        else
          SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
        end
    end
  end

  # A 2xx/3xx answering an INVITE or UPDATE needs a Contact, and it must be OURS
  # — forwarded_reply_fields/1 deliberately left the far end's behind.
  defp maybe_add_contact(fields, sip_ctx, %Pending{method: method}, resp)
       when method in [:INVITE, :UPDATE] do
    if resp.response in 200..399 do
      Keyword.put_new(fields, :contact, local_contact(sip_ctx))
    else
      fields
    end
  end

  defp maybe_add_contact(fields, _sip_ctx, _pending, _resp), do: fields

  # Mirrors SIP.Session.CallUAS.local_contact/1: the transport layer rewrites the
  # placeholder host with the actual bound address.
  defp local_contact(sip_ctx) do
    %SIP.Uri{
      userpart: SIP.Context.get(sip_ctx, :username) || "b2bua",
      domain: "0.0.0.0",
      params: %{}
    }
  end

  # ── Originating on a leg ────────────────────────────────────────────────────

  @doc false
  @spec do_send_bye(%SIP.Context{}) :: %SIP.Context{}
  def do_send_bye(sip_ctx = %SIP.Context{}) do
    case outbound_leg(sip_ctx) do
      %Leg{} = leg ->
        if leg_alive?(leg) do
          # The 2xx first, if it is still owed one. Hanging up a call the far end
          # answered but never saw acknowledged is not lawful (RFC 3261 §15 ends an
          # *established* dialog) and not effective: it goes on retransmitting its
          # 200 to an INVITE it believes unanswered. `:none` is the ordinary
          # answer — the ACK was relayed from the other leg long ago — and costs a
          # call to a process this is about to call anyway.
          call_leg(fn -> SIP.Dialog.ack_pending_invite(leg.dialogpid) end)

          case call_leg(fn -> SIP.Dialog.new_request(leg.dialogpid, bye_request()) end) do
            {:ok, _trans_pid} -> SIP.Context.set(sip_ctx, :lasterr, :ok)
            # It died between the liveness check and the call, which is what we
            # wanted of it anyway.
            :leg_dead -> SIP.Context.set(sip_ctx, :lasterr, :ok)
            # A BYE is already in flight on this dialog (a relayed one, or the
            # far end's): the hangup asked for is the hangup happening.
            :already_closing -> SIP.Context.set(sip_ctx, :lasterr, :ok)
            err -> fail(sip_ctx, {:b2bua, :bye_failed, err})
          end
        else
          # Already gone: what we wanted has happened.
          SIP.Context.set(sip_ctx, :lasterr, :ok)
        end

      nil ->
        fail(sip_ctx, {:b2bua, :no_outbound_leg})
    end
  end

  # ── Local replies ───────────────────────────────────────────────────────────

  @doc false
  @spec do_local_reply(%SIP.Context{}, map(), integer(), binary() | nil, keyword()) ::
          %SIP.Context{}
  def do_local_reply(sip_ctx = %SIP.Context{}, req, code, reason, upd_fields)
      when is_integer(code) do
    case leg_pid(sip_ctx, current_leg()) do
      nil ->
        fail(sip_ctx, {:b2bua, :no_leg_to_reply_on, current_leg()})

      dialog_pid ->
        rc =
          call_leg(fn ->
            SIP.Session.reply(dialog_pid, req, code, reason, upd_fields, "b2bua_reply #{code}")
          end)

        case rc do
          :leg_dead -> fail(sip_ctx, {:b2bua, :leg_dead, current_leg()})
          _ -> SIP.Context.set(sip_ctx, :lasterr, reply_lasterr(rc))
        end
    end
  end

  @doc false
  @spec do_local_challenge(%SIP.Context{}, map(), map(), 401 | 407) :: %SIP.Context{}
  def do_local_challenge(sip_ctx = %SIP.Context{}, req, params, code)
      when code in [401, 407] and is_map(params) do
    # A plain local reply carrying the challenge header the code calls for. The
    # params are sent verbatim: the nonce is the application's (a stateless
    # SIP.Auth.Nonce it will validate itself), so nothing here mints or stores one.
    do_local_reply(sip_ctx, req, code, SIP.Msg.Ops.sip_reason(code), [
      {SIP.Msg.Ops.challenge_header(code), params}
    ])
  end

  # ── Teardown ────────────────────────────────────────────────────────────────

  @doc """
  Wind down every leg this scenario created, whatever the exit path (success,
  failure, abort, exception). Called by `SIP.Scenario.Runner.finalize/4` before
  the media is released — the media of a leg outlives nothing, but a leg left
  behind holds a call up at the far end for as long as its session timer runs.

  Three things are owed at this point (§8):

    * an initial request still awaiting its final response is CANCELled — the
      callee is ringing for a call nobody will take;
    * an established INVITE leg gets a BYE;
    * every request relayed onto a leg and still unanswered gets a final
      response on the leg it came from, so no transaction is left hanging
      (487 for an INVITE, whose attempt we just terminated; 408 otherwise).

  Returns the context with the leg bookkeeping cleared, so a second call is a
  no-op. Never raises: a leg that dies underneath us is exactly the state we
  were trying to reach.
  """
  @spec release_legs(%SIP.Context{}) :: %SIP.Context{}
  def release_legs(sip_ctx = %SIP.Context{}) do
    state = state(sip_ctx)

    if state.legs == %{} and state.pending == %{} and is_nil(state.hunt) do
      sip_ctx
    else
      # Release whatever a provider is holding for this call before anything
      # else: an agent reserved for a call that no longer exists is an agent the
      # queue believes is busy for good (§3.4).
      report_outcome(sip_ctx, :abandoned)
      Enum.each(Map.values(state.legs), &wind_down_leg(&1, state))
      Enum.each(state.pending, fn {_tid, pending} -> answer_orphan(sip_ctx, pending) end)
      put_state(sip_ctx, %State{})
    end
  end

  defp wind_down_leg(%Leg{} = leg, state) do
    cond do
      not leg_alive?(leg) ->
        :ok

      # The initial request is still in `pending`: it never got a final answer,
      # so the leg is an attempt in progress, not a session.
      Map.has_key?(state.pending, leg.initial_trans) ->
        for {tid, _target} <- live_branches(leg) do
          protect("CANCEL leg #{inspect(leg.dialogpid)}", fn ->
            SIP.Dialog.cancel(leg.dialogpid, tid)
          end)
        end

        :ok

      leg.method == :INVITE and established?(leg) ->
        # Said out loud AFTER the dialog agreed, because this BYE is nobody's
        # relay: it is the teardown hanging up a leg the scenario left
        # established. The dialog refuses it when a BYE is already in flight
        # (:already_closing), and logging beforehand claimed a teardown BYE on
        # every hangup the scenario had in fact already relayed (2026-08-14).
        protect("BYE leg #{inspect(leg.dialogpid)}", fn ->
          case SIP.Dialog.new_request(leg.dialogpid, bye_request()) do
            {:ok, _trans_pid} ->
              Logger.info(
                module: __MODULE__,
                message: "teardown: BYEing the #{leg.tag} leg (#{inspect(leg.dialogpid)})"
              )

            _already_closing_or_error ->
              :ok
          end
        end)

      # A leg carrying anything else (MESSAGE, SUBSCRIBE…) has no teardown
      # request of its own: it expires with its dialog.
      true ->
        :ok
    end
  end

  # Did this leg ever become a session? "Its initial transaction is over" does
  # NOT answer that: it is equally true of an INVITE answered 486 Busy, and
  # BYEing *that* dialog sends a BYE with no remote target (RFC 3261 §12.1
  # — a non-2xx final establishes no dialog, so nothing was learned from it).
  #
  # The dialog's remote tag is the honest signal: `add_totag/2` sets it only for
  # a dialog-establishing response (< 300). An early dialog has one too, but a
  # leg still ringing was already caught by the CANCEL branch above.
  defp established?(%Leg{dialogpid: pid}) do
    case protect("read dialog id", fn -> GenServer.call(pid, :getdialogid) end) do
      {_fromtag, _callid, totag} -> is_binary(totag)
      _ -> false
    end
  end

  defp answer_orphan(sip_ctx, %Pending{orig_req: req, orig_leg: leg, method: method}) do
    case leg_pid(sip_ctx, leg) do
      nil ->
        :ok

      dialog_pid ->
        {code, reason} =
          if method == :INVITE,
            do: {487, "Request Terminated"},
            else: {408, "Request Timeout"}

        protect("answer orphan #{method} with #{code}", fn ->
          SIP.Dialog.reply(dialog_pid, req, code, reason, [])
        end)
    end
  end

  # The teardown BYE. Every addressing field is a placeholder: the dialog layer
  # fills in Call-ID, CSeq, both identities, their tags, the route set and the
  # remote target (fix_outbound_request/3 -> address_in_dialog/2). Same shape
  # `SIP.Session.CallInDialog` builds for a scenario-sent BYE.
  defp bye_request do
    uri = %SIP.Uri{userpart: nil, domain: nil}

    %{
      "Max-Forwards" => "70",
      method: :BYE,
      ruri: uri,
      from: uri,
      to: uri,
      useragent: Application.get_env(:elixip2, :useragent, "Elixipp/0.1"),
      callid: nil,
      contentlength: 0
    }
  end

  # Call a leg's dialog, turning its death into a value instead of an exit
  # (design §14.4, R6).
  #
  # Every one of these is a `GenServer.call` on a pid the leg map has been holding
  # since the leg was created, and a dialog can stop at any moment between the
  # check and the call — its transport gone (R4), a transaction crashed (R1), the
  # far end hung up. `leg_alive?/1` narrows the window; it cannot close it.
  #
  # The exit would leave the scenario process. R2 catches it, but only to END the
  # scenario — which is the right last resort and the wrong ordinary answer: a
  # B2BUA whose callee has just gone should get to say 480 to its caller, or try
  # the next target. So it becomes `lasterr`, and the scenario decides through the
  # ordinary `goto` contract.
  defp call_leg(fun) do
    fun.()
  catch
    :exit, _reason -> :leg_dead
  end

  # Teardown runs on the way out, often while the far end is already gone: a
  # dialog that dies between the liveness check and the call must not turn a
  # finished scenario into a crash.
  defp protect(what, fun) do
    fun.()
  rescue
    err ->
      Logger.debug(
        module: __MODULE__,
        message: "b2bua teardown: #{what} — #{Exception.message(err)}"
      )

      :ok
  catch
    :exit, reason ->
      Logger.debug(module: __MODULE__, message: "b2bua teardown: #{what} — #{inspect(reason)}")
      :ok
  end

  # ── Leg / correlation state ─────────────────────────────────────────────────

  @doc "The B2BUA state of a scenario context (empty when it created no leg)."
  @spec state(%SIP.Context{}) :: %State{}
  def state(sip_ctx = %SIP.Context{}) do
    SIP.Context.appdata_get(sip_ctx, @appdata_key) || %State{}
  end

  @doc "The outbound leg, or nil."
  @spec outbound_leg(%SIP.Context{}) :: %Leg{} | nil
  def outbound_leg(sip_ctx), do: state(sip_ctx).legs |> Map.get(@outbound_tag)

  @doc "Every live leg of this scenario (the inbound one excluded — it is sip_ctx.dialogpid)."
  @spec legs(%SIP.Context{}) :: [%Leg{}]
  def legs(sip_ctx), do: state(sip_ctx).legs |> Map.values() |> Enum.filter(&leg_alive?/1)

  @doc "Requests relayed on a leg and still awaiting their response."
  @spec pending(%SIP.Context{}) :: [{pid(), %Pending{}}]
  def pending(sip_ctx), do: state(sip_ctx).pending |> Map.to_list()

  @doc false
  def leg_alive?(%Leg{dialogpid: pid}), do: is_pid(pid) and Process.alive?(pid)
  def leg_alive?(_), do: false

  defp put_state(sip_ctx, state), do: SIP.Context.appdata_set(sip_ctx, @appdata_key, state)

  @doc "The provider-driven search in progress, or nil."
  @spec hunt(%SIP.Context{}) :: %Hunt{} | nil
  def hunt(sip_ctx), do: state(sip_ctx).hunt

  defp put_hunt(sip_ctx, hunt) do
    put_state(sip_ctx, %State{state(sip_ctx) | hunt: hunt})
  end

  defp put_leg(sip_ctx, tag, leg) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | legs: Map.put(state.legs, tag, leg)})
  end

  defp add_pending(sip_ctx, trans_pid, req, leg, method, held_answer \\ nil)

  defp add_pending(sip_ctx, nil, _req, _leg, _method, _held), do: sip_ctx

  defp add_pending(sip_ctx, trans_pid, req, leg, method, held_answer) do
    state = state(sip_ctx)
    entry = %Pending{orig_req: req, orig_leg: leg, method: method, held_answer: held_answer}
    put_state(sip_ctx, %State{state | pending: Map.put(state.pending, trans_pid, entry)})
  end

  @doc false
  def drop_pending(sip_ctx, trans_pid) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | pending: Map.delete(state.pending, trans_pid)})
  end

  # Remember the client transaction of an INVITE sent toward `leg` — what the
  # far end's ACK will act upon (see correlated_invite/2). Only INVITE: nothing
  # else is acknowledged, and an UPDATE deliberately does not overwrite it
  # (RFC 3311 — an UPDATE has no ACK, and a call may carry both).
  defp put_last_invite(sip_ctx, _leg, _method, nil), do: sip_ctx

  defp put_last_invite(sip_ctx, leg, :INVITE, trans_pid) do
    state = state(sip_ctx)
    put_state(sip_ctx, %State{state | last_invite: Map.put(state.last_invite, leg, trans_pid)})
  end

  defp put_last_invite(sip_ctx, _leg, _method, _trans_pid), do: sip_ctx

  # The leg an event's counterpart lives on. Sole reading of "the other leg" in
  # this module, so it cannot drift from other_leg_pid/2.
  defp other_leg(:inbound), do: @outbound_tag
  defp other_leg(_outbound), do: :inbound

  # The dialog pid of a named leg: the inbound leg is the scenario's own dialog,
  # every other one lives in the leg map.
  defp leg_pid(sip_ctx, :inbound), do: sip_ctx.dialogpid

  defp leg_pid(sip_ctx, tag) do
    case Map.get(state(sip_ctx).legs, tag) do
      %Leg{dialogpid: pid} -> pid
      _ -> nil
    end
  end

  defp other_leg_pid(sip_ctx, from_leg), do: leg_pid(sip_ctx, other_leg(from_leg))

  # ── Helpers ─────────────────────────────────────────────────────────────────

  defp normalize_peer(%Peer{} = peer), do: peer
  defp normalize_peer(uri) when is_binary(uri), do: %Peer{uris: [uri]}
  defp normalize_peer(%SIP.Uri{} = uri), do: %Peer{uris: [uri]}
  defp normalize_peer(uris) when is_list(uris), do: %Peer{uris: uris}

  defp normalize_uri(%SIP.Uri{} = uri), do: uri

  defp normalize_uri(uri) when is_binary(uri) do
    case SIP.Uri.parse(uri) do
      {:ok, parsed} -> parsed
      err -> raise "b2bua_forward: invalid target URI #{inspect(uri)}: #{inspect(err)}"
    end
  end

  # Only a request that can create a dialog can create a leg (RFC 3261 §12.1).
  defp dialog_forming?(req) when is_map(req) do
    Map.get(req, :method) in [:INVITE, :MESSAGE, :REGISTER, :SUBSCRIBE, :PUBLISH, :NOTIFY]
  end

  defp dialog_forming?(_), do: false

  defp fail(sip_ctx, reason) do
    Logger.warning(module: __MODULE__, message: "b2bua: #{inspect(reason)}")
    SIP.Context.set(sip_ctx, :lasterr, reason)
  end

  defp reply_lasterr(:ok), do: :ok
  defp reply_lasterr(:ignore), do: :ok
  defp reply_lasterr(other), do: other

  defp ack_lasterr(:ok), do: :ok

  # Cancelling something already being cancelled is not a failure: what was asked
  # for is already happening. The transaction layer answers `:bad_state` there
  # (SIP.Transac.Common, "Cannot CANCEL transaction in cancelling state"), and it
  # is the ORDINARY outcome of the pair every B2BUA scenario writes —
  # `b2bua_cancel_forward()` stops the hunt and cancels the attempt in flight,
  # then `b2bua_forward(req)` relays the caller's own CANCEL onto the same
  # attempt. Reporting the second as an error only became visible when scenarios
  # stopped ending on the CANCEL and started waiting for the callee's final; the
  # duplicate itself is as old as the pair, and harmless.
  defp ack_lasterr(:bad_state), do: :ok

  # An ACK that lands on nothing does not end a call. This layer already says so
  # when there is no correlated INVITE at all (`relay_request/4` warns and carries
  # on); reporting a failure when the transaction merely ended is the same
  # situation, told two different ways. The retransmitted ACK a caller really
  # sends is handled where it belongs — the client transaction outlives the ACK by
  # 64*T1 and resends it (RFC 3261 §13.2.2.4) — so this is only the floor: past
  # that window the far end has stopped asking, and a dialog log line is the right
  # weight for it, not a hung-up call.
  defp ack_lasterr(:nosuchtransaction), do: :ok
  defp ack_lasterr(other), do: other
end
