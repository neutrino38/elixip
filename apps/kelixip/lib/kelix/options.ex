defmodule Kelix.Options do
  @moduledoc """
  Answers out-of-dialog OPTIONS (RFC 3261 §11.2) — in practice the liveness ping an
  upstream proxy or load balancer sends to decide whether this node still takes
  traffic. Registered in `SIP.Session.ConfigRegistry` at boot by `Kelix.Router`.

  Three answers:

    * **200 OK** with the methods this server implements, in `Allow`;
    * **503 Service Unavailable** while the node is draining
      (`Kelix.Control.drain/0`), which is how a node leaves the upstream rotation
      without touching what is already in flight — see `Kelix.Control.graceful_shutdown/0`;
    * `:dispatch`, when a `[[domain.options]]` rule names a script for the request
      (`Kelix.Router.resolve_options/2`): the framework then opens the OPTIONS a
      short dialog and `on_new_options/3` routes it like a call, quota included.

  The drain is decided first, whatever the domains declare: leaving the upstream
  rotation must never depend on a script loading.

  This lives in the release rather than in a loadable module (design §8.3, "the core
  ships no SIP function"). Answering a liveness ping is not a SIP *function*: it is
  what makes the node visible to its infrastructure, and a server that cannot say "I
  am here" until an optional package is installed is a packaging trap.

  `Allow` is a fixed list on purpose. Deriving it from the loaded scripts would make
  the answer track the configuration, which is tempting — but it also makes a
  liveness answer depend on a code path that can be reloaded under our feet. It is
  updated by hand when a function lands.

  `Allow-Events` is NOT answered here, and that is the same rule seen from the other
  side: which event packages are served is a property of the **domain**, and this
  answer deliberately knows nothing of the configuration. It goes on the responses
  that already know their domain — the 2xx to a SUBSCRIBE, and the Router's 489.
  """
  @behaviour SIP.Session.Options
  require Logger

  # What kelixip implements today. SUBSCRIBE, PUBLISH and NOTIFY join the list with
  # the subscription layer: NOTIFY because a notifier answers the 200 to the one it
  # sent, and a UA reading this list decides from it whether to subscribe at all.
  @allow "OPTIONS, REGISTER, INVITE, ACK, CANCEL, BYE, SUBSCRIBE, PUBLISH, NOTIFY"

  @impl SIP.Session.Options
  def on_options(req, _transaction_id) do
    if Kelix.Control.draining?() do
      # No Retry-After: we do not know when (or whether) this node comes back, and a
      # figure invented here is one upstream would honour.
      {:reply, 503, "Service Unavailable", []}
    else
      case route(req) do
        :core -> core_answer()
        {:route, _route} -> :dispatch
        {:reject, code, reason} -> {:reply, code, reason, []}
      end
    end
  end

  @impl SIP.Session.Options
  def on_new_options(dialog_id, req, _transaction_id),
    do: Kelix.Router.dispatch(dialog_id, req)

  @doc "What the core answers an OPTIONS no script serves, drain aside."
  @spec core_answer() :: {:reply, 200, String.t(), list}
  def core_answer, do: {:reply, 200, "OK", [{"Allow", @allow}]}

  # No domains snapshot is no rule: the node still answers its liveness ping.
  defp route(req) do
    if Process.whereis(Kelix.Domains),
      do: Kelix.Router.resolve_options(Kelix.Domains.current(), req),
      else: :core
  end

  @doc "The methods advertised in `Allow` (also reported by `kelictl status`)."
  @spec allow() :: String.t()
  def allow, do: @allow
end
