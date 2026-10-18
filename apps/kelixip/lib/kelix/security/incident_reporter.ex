defmodule Kelix.Security.IncidentReporter do
  @moduledoc """
  The node's sink for `Elixip.Security.report/1` (`docs/design/fail2ban-plan.md`).

  Every incident the stack reports lands here by cast and is written twice: to the
  regular logger as a warning, so it reaches journald and syslog with everything
  else, and to the file `[security] log_file` names, one line per incident,
  timestamp first. Both carry the same `kelixip: …` text, so one fail2ban filter
  reads either.

  The file is opened in append mode for every batch — every incident the mailbox
  holds at that moment — and closed again. That is what makes rotation a
  non-event: nothing stays open, so logrotate needs no signal and no
  `copytruncate`. A file that cannot be written is reported once and the reporter
  stays up; the journal copy continues. Logging is never what stops the server.

  `[security] ignore` names the incident types dropped on arrival.
  """
  use GenServer
  require Logger

  alias Elixip.Security.Incident

  @prefix "kelixip: "

  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "The `:security_sink` Kelix.Config names: hand an incident to the node's reporter."
  @spec report(Incident.t()) :: :ok
  def report(%Incident{} = incident), do: report(__MODULE__, incident)

  @spec report(GenServer.server(), Incident.t()) :: :ok
  def report(server, %Incident{} = incident) do
    GenServer.cast(server, {:incident, DateTime.utc_now(), incident})
  end

  @impl true
  def init(opts) do
    cfg = Keyword.get_lazy(opts, :config, &configured/0)

    {:ok,
     %{
       log_file: Keyword.get(opts, :log_file, cfg.log_file),
       ignore: MapSet.new(Keyword.get(opts, :ignore, cfg.ignore)),
       write_failed: false
     }}
  end

  defp configured do
    case Process.whereis(Kelix.Config) do
      nil -> %{log_file: nil, ignore: []}
      _ -> Kelix.Config.current().security
    end
  end

  @impl true
  def handle_cast({:incident, at, incident}, state) do
    lines =
      [{at, incident} | drain([])]
      |> Enum.reject(fn {_at, i} -> MapSet.member?(state.ignore, i.type) end)
      |> Enum.map(fn {at, i} -> {at, @prefix <> to_string(i)} end)

    Enum.each(lines, fn {_at, text} -> Logger.warning(text) end)
    {:noreply, write(lines, state)}
  end

  # Everything else already queued, so one open serves the whole burst.
  defp drain(acc) do
    receive do
      {:"$gen_cast", {:incident, at, incident}} -> drain([{at, incident} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp write([], state), do: state
  defp write(_lines, %{log_file: nil} = state), do: state

  defp write(lines, state) do
    data =
      Enum.map(lines, fn {at, text} ->
        [at |> DateTime.truncate(:second) |> DateTime.to_iso8601(), " ", text, "\n"]
      end)

    case File.write(state.log_file, data, [:append]) do
      :ok ->
        %{state | write_failed: false}

      {:error, reason} ->
        unless state.write_failed do
          Logger.warning(
            module: __MODULE__,
            message:
              "cannot write #{state.log_file} (#{inspect(reason)}): security incidents go " <>
                "to the journal only"
          )
        end

        %{state | write_failed: true}
    end
  end
end
