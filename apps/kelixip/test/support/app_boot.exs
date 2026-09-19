defmodule Kelix.Test.AppBoot do
  @moduledoc """
  Makes sure the `:kelixip` application is actually running before a suite that
  depends on it starts — and says why when it cannot be.

  From the umbrella root, `mix test` runs every app's suite in ONE VM, in a row.
  The SIP stack and the FSL start some of their singletons unlinked
  (`SIP.FSL.Host.bootstrap/0`, the `start/0` of `SIP.Session.ConfigRegistry`,
  `SIP.Auth.Secret`, `FSL.Monitor`), so what the elixip2 and elixipp suites
  started is still registered when the kelixip suite comes up. `Kelix.Supervisor`
  supervises those same names: its start then fails on `already_started`, Mix
  says nothing, and the suite runs against no server at all — every test that
  needs one fails on whatever it happens to assert first (`Kelix.ScriptRegistry is
  not running`, on the pipeline of 2026-09-19). Run from `apps/kelixip`, the VM is
  fresh and the same suite is green.

  Those leftovers belong to no one once their suite has ended, so they are
  stopped here, and the application is started again with its start error raised.
  """

  # The names Kelix.Application supervises that something outside it can also
  # register, unsupervised.
  @shared_singletons [
    Registry.SIP.Transac,
    Registry.SIPTransport,
    Registry.SIPDialog,
    SIP.Session.ConfigRegistry,
    SIP.Auth.Secret,
    FSL.Monitor
  ]

  def ensure_started! do
    unless List.keymember?(Application.started_applications(), :kelixip, 0) do
      Enum.each(@shared_singletons, &stop_leftover/1)

      case Application.ensure_all_started(:kelixip) do
        {:ok, _} -> :ok
        {:error, reason} -> raise "the :kelixip application did not start: #{inspect(reason)}"
      end
    end

    :ok
  end

  defp stop_leftover(name) do
    case Process.whereis(name) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end
  end
end
