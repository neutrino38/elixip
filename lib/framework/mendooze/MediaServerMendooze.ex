defmodule MediaServer.Mendooze do
  @moduledoc """
  Server lifecycle GenServer of the Mendooze JSR309 adapter.

  One instance per media server connection. On `connect/1` it creates the
  server-side event queue (`EventQueueCreate`), starts the
  `MediaServer.Mendooze.EventPoller` on the returned source path, and then
  acts as the event router: the poller sends it decoded events, and the
  session tag carried by every event selects the destination
  `MediaServer.Mendooze.Conn` process from the registry.

  The remaining `MediaServer.Behaviour` callbacks (peer connections,
  players, recorders, echo) are implemented by `MediaServer.Mendooze.Conn`;
  the `@behaviour` declaration lands once the full callback set exists.

  Configuration (`config :elixip2, MediaServer.Mendooze`):
  `:xmlrpc_timeout_ms` (see `XmlRpc`), `:poller_retry_ms`,
  `:poller_max_failures` (see `EventPoller`).
  """

  use GenServer
  require Logger

  alias MediaServer.Mendooze.{EventPoller, XmlRpc}

  # ── MediaServer.Behaviour subset ────────────────────────────────────────────

  @doc """
  Connect to a Mendooze media server: `{host, http_port}` of the JSR309
  XML-RPC interface. Returns `{:ok, server_pid}` or `{:error, reason}`.
  """
  @spec connect(MediaServer.server_addr()) :: {:ok, pid()} | {:error, term()}
  def connect({host, port}) do
    case GenServer.start(__MODULE__, "http://#{host}:#{port}") do
      {:ok, pid} -> {:ok, pid}
      {:error, {:connect_failed, reason}} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Delete the event queue, stop the poller and terminate. With `force: true`,
  any peer connection still registered is closed first; without it, callers
  are expected to have closed their connections already (teardown order).
  """
  @spec disconnect(pid(), keyword()) :: :ok
  def disconnect(server, opts \\ []) do
    GenServer.call(server, {:disconnect, Keyword.get(opts, :force, false)})
  catch
    # already stopped — disconnect is idempotent
    :exit, _ -> :ok
  end

  # ── Internal API for Conn processes ─────────────────────────────────────────

  @doc false
  def register_conn(server, sess_tag, event_sink),
    do: GenServer.call(server, {:register_conn, sess_tag, self(), event_sink})

  @doc false
  def unregister_conn(server, sess_tag),
    do: GenServer.cast(server, {:unregister_conn, sess_tag})

  @doc false
  # RPC coordinates for Conn processes: %{base_url: ..., queue_id: ...}
  def rpc_info(server), do: GenServer.call(server, :rpc_info)

  # ── GenServer callbacks ─────────────────────────────────────────────────────

  @impl true
  def init(base_url) do
    case XmlRpc.call(base_url, "EventQueueCreate") do
      {:ok, [queue_id | rest]} when is_integer(queue_id) and queue_id >= 0 ->
        source_path = source_path(queue_id, rest)
        cfg = Application.get_env(:elixip2, __MODULE__, [])

        {:ok, poller} =
          EventPoller.start_link(
            base_url: base_url,
            source_path: source_path,
            sink: self(),
            retry_ms: Keyword.get(cfg, :poller_retry_ms, 1_000),
            max_failures: Keyword.get(cfg, :poller_max_failures, 5)
          )

        Logger.info("Mendooze: connected to #{base_url}, event queue #{queue_id}")

        {:ok,
         %{
           base_url: base_url,
           queue_id: queue_id,
           source_path: source_path,
           poller: poller,
           # sess_tag => %{pid: conn_pid, sink: event_sink_pid}
           conns: %{}
         }}

      {:ok, other} ->
        {:stop, {:connect_failed, {:unexpected_return, other}}}

      {:error, reason} ->
        {:stop, {:connect_failed, reason}}
    end
  end

  # Older servers return only [queueId]; the documented fallback path applies.
  defp source_path(_queue_id, [path | _]) when is_binary(path), do: path
  defp source_path(queue_id, _), do: "/events/jsr309/#{queue_id}"

  @impl true
  def handle_call({:disconnect, force}, _from, state) do
    if force do
      Enum.each(state.conns, fn {tag, %{pid: pid}} ->
        Logger.warning("Mendooze: force disconnect, closing leftover session #{tag}")

        try do
          GenServer.stop(pid, :shutdown)
        catch
          :exit, _ -> :ok
        end
      end)
    end

    case XmlRpc.call(state.base_url, "EventQueueDelete", [state.queue_id]) do
      {:ok, _} -> :ok
      # the server may already be gone; disconnect must still succeed
      {:error, reason} -> Logger.warning("Mendooze: EventQueueDelete failed: #{inspect(reason)}")
    end

    Process.unlink(state.poller)
    Process.exit(state.poller, :shutdown)
    {:stop, :normal, :ok, state}
  end

  def handle_call({:register_conn, sess_tag, conn_pid, event_sink}, _from, state) do
    Process.monitor(conn_pid)
    conns = Map.put(state.conns, sess_tag, %{pid: conn_pid, sink: event_sink})
    {:reply, :ok, %{state | conns: conns}}
  end

  def handle_call(:rpc_info, _from, state) do
    {:reply, %{base_url: state.base_url, queue_id: state.queue_id}, state}
  end

  @impl true
  def handle_cast({:unregister_conn, sess_tag}, state) do
    {:noreply, %{state | conns: Map.delete(state.conns, sess_tag)}}
  end

  @impl true
  def handle_info({:mendooze_event, event}, state) do
    sess_tag = elem(event, 1)

    case Map.get(state.conns, sess_tag) do
      %{pid: pid} ->
        send(pid, {:mendooze_event, event})

      nil ->
        # late events after a session teardown are expected
        Logger.debug("Mendooze: dropping event for unknown session #{sess_tag}")
    end

    {:noreply, state}
  end

  def handle_info({:mendooze_poller_down}, state) do
    Logger.error("Mendooze: media server #{state.base_url} unreachable")

    state.conns
    |> Enum.map(fn {_tag, %{sink: sink}} -> sink end)
    |> Enum.uniq()
    |> Enum.each(&send(&1, {:ms_event, self(), :server_disconnected}))

    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    conns = state.conns |> Enum.reject(fn {_tag, %{pid: p}} -> p == pid end) |> Map.new()
    {:noreply, %{state | conns: conns}}
  end
end
