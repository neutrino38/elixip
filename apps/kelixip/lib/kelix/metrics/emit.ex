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
end
