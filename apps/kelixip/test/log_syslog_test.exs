defmodule Kelix.Log.SyslogTest do
  # async: false — installs a global :logger handler and swaps the socket path.
  use ExUnit.Case, async: false
  require Logger

  @moduledoc """
  Exercises the syslog sink against a **real** unix datagram socket the test binds
  itself, so the RFC 3164 framing is asserted on the actual bytes rather than
  mocked. No /dev/log and no syslog daemon involved.
  """

  alias Kelix.Log.Syslog

  setup do
    path = Path.join(System.tmp_dir!(), "kelix_syslog_#{System.unique_integer([:positive])}.sock")
    File.rm(path)

    # the collector: a bound unix datagram socket standing in for /dev/log
    {:ok, listener} = :gen_udp.open(0, [:local, :binary, ifaddr: {:local, path}, active: false])

    previous = Application.get_env(:kelixip, :syslog_socket_path)
    Application.put_env(:kelixip, :syslog_socket_path, path)

    on_exit(fn ->
      Syslog.disable()
      :gen_udp.close(listener)
      File.rm(path)

      if previous,
        do: Application.put_env(:kelixip, :syslog_socket_path, previous),
        else: Application.delete_env(:kelixip, :syslog_socket_path)
    end)

    %{listener: listener, path: path}
  end

  defp receive_line(listener, timeout \\ 1000) do
    case :gen_udp.recv(listener, 0, timeout) do
      {:ok, {_addr, _port, data}} -> data
      {:error, reason} -> flunk("nothing on the syslog socket: #{inspect(reason)}")
    end
  end

  test "a log line is emitted as RFC 3164, with the configured facility", ctx do
    assert :ok = Syslog.enable("local3")
    Logger.error(module: __MODULE__, message: "hello syslog")

    line = receive_line(ctx.listener)

    # local3 = 19, error = 3  ->  19*8 + 3 = 155
    assert line =~ ~r/\A<155>/
    # "Mmm dd hh:mm:ss host kelixip[pid]: …"
    assert line =~ ~r/\A<155>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ kelixip\[\d+\]: /
    assert line =~ "hello syslog"
  end

  test "the severity follows the log level", ctx do
    assert :ok = Syslog.enable("local0")

    # local0 = 16 -> 128 + severity
    Logger.warning(module: __MODULE__, message: "warn line")
    assert receive_line(ctx.listener) =~ ~r/\A<132>/

    Logger.info(module: __MODULE__, message: "info line")
    assert receive_line(ctx.listener) =~ ~r/\A<134>/
  end

  test "a keyword-list log reads as prose, not as an inspected term", ctx do
    assert :ok = Syslog.enable("local0")
    Logger.error(module: Kelix.Config, message: "config.toml loaded")

    line = receive_line(ctx.listener)
    assert line =~ "Kelix.Config: config.toml loaded"
    refute line =~ "message:"
  end

  test "a plain string log is emitted verbatim", ctx do
    assert :ok = Syslog.enable("local0")
    Logger.error("a bare string")
    assert receive_line(ctx.listener) =~ "a bare string"
  end

  test "disable/0 stops emitting", ctx do
    assert :ok = Syslog.enable("local0")
    Logger.error(module: __MODULE__, message: "before")
    assert receive_line(ctx.listener) =~ "before"

    assert :ok = Syslog.disable()
    Logger.error(module: __MODULE__, message: "after")
    assert {:error, :timeout} = :gen_udp.recv(ctx.listener, 0, 200)
  end

  test "enable/1 is idempotent and can switch facility", ctx do
    assert :ok = Syslog.enable("local0")
    assert :ok = Syslog.enable("local7")

    Logger.error(module: __MODULE__, message: "switched")
    # local7 = 23 -> 23*8 + 3 = 187
    assert receive_line(ctx.listener) =~ ~r/\A<187>/
  end

  test "an unreachable socket leaves the sink inert instead of failing" do
    Application.put_env(:kelixip, :syslog_socket_path, "/nonexistent/kelix.sock")
    # enable/1 answers :ok whatever happens: logging must never stop the server
    assert :ok = Syslog.enable("local0")
    # and logging still works (goes to the other sinks)
    Logger.error(module: __MODULE__, message: "still alive")
    assert :ok = Syslog.disable()
  end

  test "[log].facility is validated against the known facilities" do
    assert {:ok, cfg} = Kelix.Config.parse(~s([log]\ntarget = "syslog"\nfacility = "local5"))
    assert cfg.log.facility == "local5"

    assert {:error, msg} = Kelix.Config.parse(~s([log]\nfacility = "nope"))
    assert msg =~ "facility"
  end
end
