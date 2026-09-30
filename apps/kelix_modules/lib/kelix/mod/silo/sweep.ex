defmodule Kelix.Mod.Silo.Sweep do
  @moduledoc """
  Expired messages deleted on a timer (chat-basic-plan, C6).

  A message is never consumed — retention is what reclaims it — so the sweep is
  also where a message that **no device ever received** is noticed. Each one
  increments `kelix_silo_expired_undelivered_total{domain}`: the metric that
  betrays a registrar script which forgot to call `Kelix.Mod.Silo.flush/2`.
  Nothing else guards that mistake, so the module doc says which alert to set.
  """
  require Logger

  @doc """
  Delete what expired by `now`. `{:ok, %{expired: n, undelivered: m}}`, the
  metric emitted per domain; `{:error, reason}` when the store did not answer,
  and the next tick tries again.
  """
  @spec run(module, term, integer) ::
          {:ok, %{expired: non_neg_integer, undelivered: non_neg_integer}} | {:error, term}
  def run(store, handle, now) do
    with {:ok, swept} <- store.sweep(handle, now) do
      undelivered = Enum.reject(swept, & &1.served)

      undelivered
      |> Enum.frequencies_by(& &1.domain)
      |> Enum.each(fn {domain, n} ->
        :telemetry.execute([:kelix, :silo, :expired_undelivered], %{count: n}, %{domain: domain})
      end)

      if swept != [] do
        Logger.info(
          module: __MODULE__,
          message:
            "silo: #{length(swept)} message(s) expired, #{length(undelivered)} of them " <>
              "never delivered to any device"
        )
      end

      {:ok, %{expired: length(swept), undelivered: length(undelivered)}}
    end
  end
end
