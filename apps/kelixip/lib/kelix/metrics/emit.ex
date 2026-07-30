defmodule Kelix.Metrics.Emit do
  @moduledoc """
  Thin `:telemetry.execute/3` helpers for the counter/distribution events, called
  from the framework seams (`Kelix.InstancePool`, `Kelix.Router`,
  `Kelix.Mod.Registrar`). Kept in one place so the event names + metadata shapes
  stay in lockstep with the `Kelix.Metrics.metrics/0` definitions.

  Emitting is a **no-op when no reporter is attached** (metrics disabled), so a
  seam can always call these without checking whether observability is up.
  """

  @doc "A dispatch that reserved a slot + spawned an instance (`domain`, `function`)."
  @spec dispatch_accepted(String.t(), atom) :: :ok
  def dispatch_accepted(domain, function) do
    :telemetry.execute([:kelix, :dispatch, :accepted], %{count: 1}, %{
      domain: domain,
      function: function
    })
  end

  @doc "A rejected dispatch with its SIP `code` (404/405 routing, 503 quota, 500 load)."
  @spec dispatch_rejected(String.t(), atom, integer) :: :ok
  def dispatch_rejected(domain, function, code) do
    :telemetry.execute([:kelix, :dispatch, :rejected], %{count: 1}, %{
      domain: domain,
      function: function,
      code: code
    })
  end

  @doc "A registrar lifecycle event (`:registered | :unregistered | :expired | :disconnected`)."
  @spec registrar_event(String.t(), atom) :: :ok
  def registrar_event(domain, event) do
    :telemetry.execute([:kelix, :registrar, :event], %{count: 1}, %{domain: domain, event: event})
  end

  # ── conferencing (mcu module, design docs/design/mcu_module.md §11) ───────────
  #
  # The helpers live here, with the registrar's, for the reason the moduledoc gives:
  # event names and metadata shapes must stay in lockstep with the definitions in
  # `Kelix.Metrics.metrics/0`, and a loadable module cannot own half of that pair.

  @doc """
  The outcome of one inbound conference call: `:joined` for a leg that reached the
  mix, else the SIP code it was answered with (`404`, `486`, `488`, `503`, `500`).

  Read as a whole this is the funnel an operator needs — how many calls reach the
  mix versus die on an unknown DID, a full conference or a codec mismatch.
  """
  @spec mcu_call(atom | integer) :: :ok
  def mcu_call(result) do
    :telemetry.execute([:kelix, :mcu, :call], %{count: 1}, %{result: to_string(result)})
  end

  @doc "One MCU control RPC: its wall-clock duration in native units."
  @spec mcu_rpc(String.t(), integer) :: :ok
  def mcu_rpc(method, duration_native) do
    :telemetry.execute([:kelix, :mcu, :rpc], %{duration: duration_native}, %{method: method})
  end

  @doc """
  An MCU control RPC that failed, by `method` and a **bounded** reason label
  (`:mcu_error`, `:timeout`, `:unreachable`, …) — never the server's message, which
  would blow up the label cardinality. The message is in the logs.
  """
  @spec mcu_rpc_error(String.t(), atom) :: :ok
  def mcu_rpc_error(method, reason) do
    :telemetry.execute([:kelix, :mcu, :rpc_error], %{count: 1}, %{
      method: method,
      reason: to_string(reason)
    })
  end

  @doc "Gauge sample: conferences held on `mcu`."
  @spec mcu_conferences(String.t(), non_neg_integer) :: :ok
  def mcu_conferences(mcu, count) do
    :telemetry.execute([:kelix, :poll, :mcu_conferences], %{count: count}, %{mcu: mcu})
  end

  @doc "Gauge sample: participants in one conference."
  @spec mcu_participants(String.t(), String.t(), non_neg_integer) :: :ok
  def mcu_participants(mcu, conference, count) do
    :telemetry.execute([:kelix, :poll, :mcu_participants], %{count: count}, %{
      mcu: mcu,
      conference: conference
    })
  end

  @doc """
  Gauge sample: whether the module's control channel to `mcu` is up.

  Distinct from `kelix.mediaserver.up`, which is the *pool*'s view: a conference is
  pinned to its MCU (§1.3), so what matters to it is that channel, not whether the
  pool would hand the server out for a new point-to-point call.
  """
  @spec mcu_mediaserver_up(String.t(), boolean) :: :ok
  def mcu_mediaserver_up(mcu, up?) do
    :telemetry.execute([:kelix, :poll, :mcu_up], %{up: if(up?, do: 1, else: 0)}, %{mcu: mcu})
  end
end
