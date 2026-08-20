defmodule SIP.B2bua.TargetProvider do
  @moduledoc """
  Where a hunt's targets come from when they cannot be known up front.

  `%SIP.B2bua.Peer{uris: […]}` is a snapshot, computed once when the leg is
  created. A call queue is a live thing: which agent to try next depends on the
  state of the world *at the moment the previous attempt failed* — who hung up
  since, who just logged in, whose wrap-up expired. So a peer may name a
  provider instead, and the hunt asks it each time it needs a target.

  Design: docs/design/DESIGN-FRAMEWORK.md#55-forking-the-kamailio-tm-model.

      %SIP.B2bua.Peer{provider: {Kelix.Mod.Queue, queue_pid}, fork: :serial}
      %SIP.B2bua.Peer{provider: Kelix.Mod.Queue}   # server registered under its own name

  The pair is `{module, server}` rather than a bare pid because the callbacks
  have to be dispatched somewhere: the module implements them, the server (a pid
  or a registered name) is the instance they act on.

  ## The two callbacks, and why neither is optional

  `next_target/3` answers **one** target at a time — this extends the *serial*
  hunt, so nothing here needs parallel forking.

  `attempt_ended/3` is the half that makes a queue work at all. Two calls asking
  at the same instant must not be handed the same agent, so a provider reserves;
  a reservation that is never released leaks, and after a few failed calls the
  queue believes every agent is busy. `call` — a reference the B2BUA mints with
  the hunt and passes on every call — is what the reservation is held against.

  ## What a provider must not do

  It is called from the scenario process, so a slow `next_target/3` holds up a
  call and a shared provider holds up every call routed through it. Answer
  quickly, or answer `{:wait, ms}` and do the work in between. A provider that
  raises does not take the call down — the hunt reports it and gives up — but it
  does end that call's search.
  """

  @typedoc "Identifies one call for the whole of its hunt; what a reservation is held against."
  @type call :: reference()

  @typedoc """
  How an attempt this provider handed out ended.

    * `{:answered, uri}` — that target took the call;
    * `{:rejected, uri, code}` — it answered `code`; a queue reads 486 and 603
      very differently (see §3.6);
    * `{:no_answer, uri}` — it rang out, or the scenario moved on
      (`b2bua_try_next/0`);
    * `:abandoned` — the caller gave up while queued, or the scenario was torn
      down. No target was ever tried, or the one in flight no longer matters.
  """
  @type outcome ::
          {:answered, SIP.Uri.t()}
          | {:rejected, SIP.Uri.t(), 100..699}
          | {:no_answer, SIP.Uri.t()}
          | :abandoned

  @doc """
  The next target for this call, or why there is none yet.

    * `{:ok, uri}` / `{:ok, uri, opts}` — try this one. `opts` may carry
      `ring_timeout: ms`, which the scenario reads back with
      `b2bua_ring_timeout/0`: how long to ring *this* target is the queue's to
      decide, when to act on it stays the scenario's.
    * `{:wait, ms}` — nobody is available; the caller **waits** and the scenario
      asks again in `ms`. This is what separates a queue from a list of
      fallbacks: without it an empty queue reads as exhausted and the call is
      refused, which is the one thing a queue exists to avoid.
    * `:exhausted` — stop looking; the caller is answered.
    * `{:error, reason}` — the same, and logged.
  """
  @callback next_target(server :: GenServer.server(), call, req :: map()) ::
              {:ok, SIP.Uri.t()}
              | {:ok, SIP.Uri.t(), opts :: keyword()}
              | {:wait, milliseconds :: non_neg_integer()}
              | :exhausted
              | {:error, term()}

  @doc """
  How the attempt this provider last handed out ended — including `:abandoned`
  when the call goes away without one. Its return value is ignored; what matters
  is that the reservation is released.
  """
  @callback attempt_ended(server :: GenServer.server(), call, outcome) :: any()
end
