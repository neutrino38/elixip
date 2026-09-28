defmodule Elixipp.LogPane do
  @moduledoc """
  Ring buffer holding the last console log lines, shown in a pane under the live
  call table.

  This module is also the `:logger` handler that fills it: `log/2` formats the
  event with the formatter the handler was installed with, then stores the lines
  here instead of writing them to the terminal. A line written straight to the
  terminal scrolls the screen under Owl's live blocks, and the next redraw lands
  inside the previous table — see `Elixipp.CLI.capture_logger/0`.

  The file sink (`--log-file`) is untouched: the pane shows the tail, the file
  keeps everything.
  """
  use GenServer

  @name __MODULE__

  @doc """
  Starts the buffer, keeping at most `capacity` lines.
  """
  @spec start(pos_integer()) :: {:ok, pid()} | {:error, term()}
  def start(capacity), do: GenServer.start(__MODULE__, capacity, name: @name)

  @spec stop() :: :ok
  def stop do
    case Process.whereis(@name) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end
  end

  @doc """
  Stores one already-formatted line per newline found in `chardata`.
  """
  @spec push(Logger.level(), IO.chardata()) :: :ok
  def push(level, chardata), do: GenServer.cast(@name, {:push, level, chardata})

  @doc """
  The last `count` lines, oldest first — the order a terminal reads in.

  Answers `[]` when the buffer is not running, so a render function can call it
  unguarded.
  """
  @spec lines(pos_integer()) :: [{Logger.level(), String.t()}]
  def lines(count) do
    case Process.whereis(@name) do
      nil -> []
      pid -> GenServer.call(pid, {:lines, count})
    end
  end

  @doc """
  How many lines were dropped out of the buffer since it started.
  """
  @spec dropped() :: non_neg_integer()
  def dropped do
    case Process.whereis(@name) do
      nil -> 0
      pid -> GenServer.call(pid, :dropped)
    end
  end

  # ── :logger handler ──────────────────────────────────────────────────────────

  @doc false
  def log(event, %{formatter: {formatter, formatter_config}}) do
    push(event.level, formatter.format(event, formatter_config))
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(capacity) do
    {:ok, %{capacity: capacity, count: 0, dropped: 0, lines: :queue.new()}}
  end

  # The console formatter colours its output when it writes to a terminal, and it
  # wraps the whole event — the reset code lands AFTER the trailing newline. Left
  # in, that reset becomes a line of its own, and Owl counts every escape byte as
  # a visible column, so the pane's right border walks left. The pane colours by
  # level itself, so the codes are dropped here.
  @ansi ~r/\e\[[0-9;?]*[ -\/]*[@-~]/

  @impl true
  def handle_cast({:push, level, chardata}, state) do
    {:noreply,
     chardata
     |> IO.chardata_to_string()
     |> String.replace(@ansi, "")
     |> String.split("\n")
     |> Enum.reject(&(String.trim(&1) == ""))
     |> Enum.reduce(state, &append(&2, level, &1))}
  end

  @impl true
  def handle_call({:lines, count}, _from, state) do
    lines =
      state.lines
      |> :queue.to_list()
      |> Enum.take(-count)

    {:reply, lines, state}
  end

  def handle_call(:dropped, _from, state), do: {:reply, state.dropped, state}

  defp append(%{count: count, capacity: capacity} = state, level, line)
       when count >= capacity do
    {_, lines} = :queue.out(state.lines)
    %{state | lines: :queue.in({level, line}, lines), dropped: state.dropped + 1}
  end

  defp append(state, level, line) do
    %{state | lines: :queue.in({level, line}, state.lines), count: state.count + 1}
  end
end
