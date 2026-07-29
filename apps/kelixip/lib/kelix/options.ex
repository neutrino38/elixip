defmodule Kelix.Options do
  @moduledoc """
  Answers out-of-dialog OPTIONS (RFC 3261 §11.2) — in practice the liveness ping an
  upstream proxy or load balancer sends to decide whether this node still takes
  traffic. Registered in `SIP.Session.ConfigRegistry` at boot by `Kelix.Router`.

  Two answers:

    * **200 OK** with the methods this server implements, in `Allow`;
    * **503 Service Unavailable** while the node is draining
      (`Kelix.Control.drain/0`), which is how a node leaves the upstream rotation
      without touching what is already in flight — see `Kelix.Control.graceful_shutdown/0`.

  This lives in the release rather than in a loadable module (design §8.3, "the core
  ships no SIP function"). Answering a liveness ping is not a SIP *function*: it is
  what makes the node visible to its infrastructure, and a server that cannot say "I
  am here" until an optional package is installed is a packaging trap.

  `Allow` is a fixed list on purpose. Deriving it from the loaded scripts would make
  the answer track the configuration, which is tempting — but it also makes a
  liveness answer depend on a code path that can be reloaded under our feet. It is
  updated by hand when a function lands (`calls` next).
  """
  @behaviour SIP.Session.Options
  require Logger

  # What kelixip implements today: the registrar, plus OPTIONS itself. INVITE joins
  # the list when the call function lands — advertising it earlier would be a lie a
  # tester catches in one probe.
  @allow "OPTIONS, REGISTER"

  @impl SIP.Session.Options
  def on_options(_req, _transaction_id) do
    if Kelix.Control.draining?() do
      # No Retry-After: we do not know when (or whether) this node comes back, and a
      # figure invented here is one upstream would honour.
      {:reply, 503, "Service Unavailable", []}
    else
      {:reply, 200, "OK", [{"Allow", @allow}]}
    end
  end

  @doc "The methods advertised in `Allow` (also reported by `kelictl status`)."
  @spec allow() :: String.t()
  def allow, do: @allow
end
