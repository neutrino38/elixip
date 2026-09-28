defmodule Kelix.Traces do
  @moduledoc """
  The sequence diagrams an operator asked for, kept in memory.

  `kelictl debug <id> on` turns the journal of a live scenario on
  (`Kelix.Control.debug_scenario/2`); the diagram is written when the scenario
  ends, or at once with `kelictl debug <id> off`. Either way it lands here,
  through `SIP.FSL.Host.journal_output/3` — `Kelix.Config` names `store/3` as the
  node's `:sequence_output` — and `kelictl debug list` / `debug show <id>` read
  it back.

  **Memory only.** A trace is kept `[debug] trace_retention` seconds after it was
  written (3600 by default), and at most `[debug] max_traces` of them (100),
  the oldest dropped first to make room. Nothing is written to disk and a restart
  loses them all: they are an operator's working material, not a record.

  One instance can leave several diagrams — `on`, `off`, `on` again — and
  `get/1` returns them all, oldest first. PlantUML reads a file of several
  `@startuml` blocks as several diagrams, so they concatenate as they are.
  """
  use GenServer
  require Logger

  @typedoc "A kept diagram. `id` is the instance id of `kelictl monitor`, nil for a run the pool does not know."
  @type entry :: %{
          n: pos_integer,
          id: pos_integer | nil,
          scenario: String.t(),
          domain: String.t() | nil,
          script: String.t() | nil,
          pid: pid | nil,
          written_at: DateTime.t(),
          format: String.t(),
          size: non_neg_integer,
          document: String.t()
        }

  # How often expired traces are swept, at most. A trace is also filtered out on
  # read the moment it expires, so this only bounds how long its memory lingers.
  @max_sweep_ms 60_000

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []) do
    # `name: nil` starts an unregistered store, which a test drives by pid.
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Keep a finished diagram — the `:sequence_output` of this node, called by
  `SIP.FSL.Host.journal_output/3` in the scenario's own process. Answers what
  `c:FSL.Host.journal_output/3` expects.
  """
  @spec store(String.t(), map, module, GenServer.server()) :: {:ok, term} | {:error, term}
  def store(document, meta, renderer, server \\ __MODULE__) do
    GenServer.call(server, {:store, document, meta, format(renderer), self()})
  catch
    :exit, reason -> {:error, {:trace_store_unavailable, reason}}
  end

  @doc "The kept traces, oldest first, without their documents."
  @spec list(GenServer.server()) :: [map]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc "Every trace kept for instance `id`, oldest first, documents included."
  @spec get(pos_integer, GenServer.server()) :: {:ok, [entry]} | {:error, :not_found}
  def get(id, server \\ __MODULE__), do: GenServer.call(server, {:get, id})

  @doc "The retention (seconds) and capacity this store runs with."
  @spec limits() :: %{trace_retention: pos_integer, max_traces: pos_integer}
  def limits(), do: GenServer.call(__MODULE__, :limits)

  # ── server ──────────────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    limits =
      Keyword.get_lazy(opts, :limits, fn ->
        try do
          Kelix.Config.current().debug
        catch
          :exit, _ -> %Kelix.Config{}.debug
        end
      end)

    state = %{
      retention_ms: limits.trace_retention * 1000,
      max: limits.max_traces,
      limits: limits,
      seq: 0,
      # newest first: eviction drops from the tail
      traces: []
    }

    schedule_sweep(state)
    {:ok, state}
  end

  @impl true
  def handle_call({:store, document, meta, format, from_pid}, _from, state) do
    slot = Map.get(meta, :slot)
    row = instance_row(slot)
    n = state.seq + 1

    entry = %{
      n: n,
      id: if(is_integer(slot), do: slot),
      scenario: Map.get(meta, :scenario),
      domain: row && row.domain,
      script: row && row.script,
      pid: from_pid,
      written_at: DateTime.utc_now(),
      at_ms: now_ms(),
      format: format,
      size: byte_size(document),
      document: document
    }

    traces = Enum.take([entry | expire(state.traces, state)], state.max)

    Logger.info(
      module: __MODULE__,
      message:
        "sequence diagram of instance #{entry.id || "?"} (#{entry.scenario}) kept " <>
          "in memory, #{entry.size} bytes"
    )

    {:reply, {:ok, {:trace, entry.id || n}}, %{state | seq: n, traces: traces}}
  end

  def handle_call(:list, _from, state) do
    traces = expire(state.traces, state)
    rows = traces |> Enum.reverse() |> Enum.map(&summary(&1, state))
    {:reply, rows, %{state | traces: traces}}
  end

  def handle_call({:get, id}, _from, state) do
    traces = expire(state.traces, state)

    reply =
      case traces |> Enum.filter(&(&1.id == id)) |> Enum.reverse() do
        [] -> {:error, :not_found}
        found -> {:ok, Enum.map(found, &Map.merge(summary(&1, state), %{document: &1.document}))}
      end

    {:reply, reply, %{state | traces: traces}}
  end

  def handle_call(:limits, _from, state), do: {:reply, state.limits, state}

  @impl true
  def handle_info(:sweep, state) do
    schedule_sweep(state)
    {:noreply, %{state | traces: expire(state.traces, state)}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── internals ───────────────────────────────────────────────────────────────

  defp expire(traces, state) do
    cutoff = now_ms() - state.retention_ms
    Enum.filter(traces, &(&1.at_ms > cutoff))
  end

  defp summary(entry, state) do
    entry
    |> Map.drop([:document, :at_ms])
    |> Map.merge(%{
      running: is_pid(entry.pid) and Process.alive?(entry.pid),
      expires_in_s: max(div(entry.at_ms + state.retention_ms - now_ms(), 1000), 0)
    })
  end

  # Which domain and script the instance serves, while it is still registered —
  # it is: a diagram is written from the instance's own process, before it exits.
  defp instance_row(slot) when is_integer(slot) do
    Enum.find(Kelix.InstancePool.list(), &(&1.id == slot))
  catch
    :exit, _ -> nil
  end

  defp instance_row(_slot), do: nil

  defp format(FSL.Diagram.PlantUML), do: "plantuml"
  defp format(FSL.Diagram.Mermaid), do: "mermaid"
  defp format(renderer), do: inspect(renderer)

  defp schedule_sweep(state),
    do: Process.send_after(self(), :sweep, min(state.retention_ms, @max_sweep_ms))

  defp now_ms, do: System.monotonic_time(:millisecond)
end
