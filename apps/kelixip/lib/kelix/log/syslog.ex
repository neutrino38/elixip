defmodule Kelix.Log.Syslog do
  @moduledoc """
  Syslog sink for `[log].target = "syslog"` (design §16 #4, §3.1).

  An RFC 3164 (BSD syslog) datagram writer over the local socket `/dev/log`, which
  both journald and rsyslog listen on. No dependency and no NIF: the release stays
  a pure-`.beam` artifact.

  Two things in one module, because they cannot be separated: a **`:logger`
  handler** (`log/2`, run in whichever process logged) and the **GenServer that owns
  the socket**. A unix datagram socket only delivers for its owning process — a send
  from any other returns `:ok` and is silently dropped — so the handler formats the
  line and hands it to this process, which emits it.

  It is started unconditionally but stays **inert** until `enable/1`: no socket, no
  handler, nothing on the wire. `Kelix.Config.apply_logger/1` enables it when the
  TOML asks for syslog and disables it otherwise, so switching targets needs no
  restart of anything else.

  A missing `/dev/log` (a container with no syslog) is not fatal: it is reported
  once and the sink stays inert, logs still going to stdout.
  """
  use GenServer
  require Logger

  @handler_id :kelixip_syslog
  @socket_path "/dev/log"

  # RFC 3164 §4.1.1. `local0..7` is what a service is expected to use.
  @facilities %{
    "kern" => 0,
    "user" => 1,
    "mail" => 2,
    "daemon" => 3,
    "auth" => 4,
    "syslog" => 5,
    "lpr" => 6,
    "news" => 7,
    "uucp" => 8,
    "cron" => 9,
    "authpriv" => 10,
    "ftp" => 11,
    "local0" => 16,
    "local1" => 17,
    "local2" => 18,
    "local3" => 19,
    "local4" => 20,
    "local5" => 21,
    "local6" => 22,
    "local7" => 23
  }

  # Elixir/OTP level -> RFC 3164 severity.
  @severities %{
    emergency: 0,
    alert: 1,
    critical: 2,
    error: 3,
    warning: 4,
    warn: 4,
    notice: 5,
    info: 6,
    debug: 7
  }

  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  @doc "The syslog facilities `[log].facility` accepts."
  @spec facilities() :: [String.t()]
  def facilities(), do: Map.keys(@facilities)

  # ── lifecycle ────────────────────────────────────────────────────────────────

  @spec start_link(keyword) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Start emitting, under `facility` (a name from `facilities/0`). Idempotent —
  re-enabling with another facility just switches it. Returns `:ok` even when the
  socket cannot be opened: logging must never be what stops the server.
  """
  @spec enable(String.t()) :: :ok
  def enable(facility) when is_binary(facility) do
    if Process.whereis(__MODULE__), do: GenServer.call(__MODULE__, {:enable, facility}), else: :ok
  end

  @doc "Stop emitting and drop the handler. Idempotent."
  @spec disable() :: :ok
  def disable() do
    if Process.whereis(__MODULE__), do: GenServer.call(__MODULE__, :disable), else: :ok
  end

  @doc false
  # Test seam: the datagram socket to write to (a test binds its own and reads back).
  def socket_path(), do: Application.get_env(:kelixip, :syslog_socket_path, @socket_path)

  # ── :logger handler ──────────────────────────────────────────────────────────

  @doc false
  # Runs in the process that logged. Formats, then hands the line to the owner of
  # the socket. Never raises and never logs: an error here would re-enter the
  # logger and recurse.
  def log(event, _config) do
    GenServer.cast(__MODULE__, {:emit, event.level, message_text(event)})
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # ── GenServer ────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts), do: {:ok, %{socket: nil, facility: nil, hostname: hostname(), tag: tag()}}

  @impl true
  def handle_call({:enable, facility}, _from, state) do
    case open_socket(state) do
      {:ok, state} ->
        add_handler()
        {:reply, :ok, %{state | facility: Map.fetch!(@facilities, facility)}}

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message:
            "cannot open #{socket_path()} (#{inspect(reason)}); syslog stays off, " <>
              "logs keep going to stdout"
        )

        {:reply, :ok, state}
    end
  end

  def handle_call(:disable, _from, state) do
    :logger.remove_handler(@handler_id)
    if state.socket, do: :gen_udp.close(state.socket)
    {:reply, :ok, %{state | socket: nil, facility: nil}}
  end

  @impl true
  def handle_cast({:emit, level, text}, %{socket: socket, facility: facility} = state)
      when socket != nil and facility != nil do
    packet = [
      "<",
      Integer.to_string(facility * 8 + Map.get(@severities, level, 6)),
      ">",
      timestamp(),
      " ",
      state.hostname,
      " ",
      state.tag,
      ": ",
      text
    ]

    _ = :gen_udp.send(socket, {:local, String.to_charlist(socket_path())}, 0, packet)
    {:noreply, state}
  end

  # inert (not enabled, or the socket could not be opened): drop
  def handle_cast({:emit, _level, _text}, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: socket}) do
    :logger.remove_handler(@handler_id)
    if socket, do: :gen_udp.close(socket)
    :ok
  end

  # ── internals ────────────────────────────────────────────────────────────────

  defp open_socket(%{socket: socket} = state) when socket != nil, do: {:ok, state}

  defp open_socket(state) do
    case :gen_udp.open(0, [:local, :binary]) do
      {:ok, socket} -> {:ok, %{state | socket: socket}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp add_handler() do
    # The level is set right after by Kelix.Config.apply_logger/1, along with every
    # other sink's.
    case :logger.add_handler(@handler_id, __MODULE__, %{}) do
      :ok -> :ok
      {:error, {:already_exist, _}} -> :ok
      _ -> :ok
    end
  end

  # RFC 3164 timestamp: "Mmm d hh:mm:ss", the day space-padded to two columns.
  defp timestamp() do
    {{_y, month, day}, {h, m, s}} = :calendar.local_time()

    [
      Enum.at(@months, month - 1),
      " ",
      String.pad_leading(Integer.to_string(day), 2),
      " ",
      two(h),
      ":",
      two(m),
      ":",
      two(s)
    ]
  end

  defp two(n), do: String.pad_leading(Integer.to_string(n), 2, "0")

  defp hostname() do
    case :inet.gethostname() do
      {:ok, name} -> to_string(name)
      _ -> "-"
    end
  end

  defp tag(), do: "kelixip[#{System.pid()}]"

  # This codebase logs keyword lists (`Logger.info(module: …, message: …)`), which
  # reach a handler as a report. Surface the message and keep the module as a
  # prefix, so a syslog line reads as prose rather than an inspected term.
  defp message_text(%{msg: {:string, text}}), do: text

  defp message_text(%{msg: {:report, report}}), do: report_text(report)

  defp message_text(%{msg: {format, args}}) when is_list(format),
    do: :io_lib.format(format, args)

  defp message_text(_event), do: ""

  defp report_text(report) when is_list(report) do
    case Keyword.fetch(report, :message) do
      {:ok, message} ->
        case Keyword.fetch(report, :module) do
          {:ok, module} -> [inspect(module), ": ", to_string(message)]
          :error -> to_string(message)
        end

      :error ->
        inspect(report)
    end
  end

  defp report_text(report) when is_map(report) do
    case Map.fetch(report, :message) do
      {:ok, message} -> to_string(message)
      :error -> inspect(report)
    end
  end

  defp report_text(report), do: inspect(report)
end
