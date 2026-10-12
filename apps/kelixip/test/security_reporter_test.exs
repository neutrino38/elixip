defmodule Kelix.Security.IncidentReporterTest do
  # Drives a reporter of its own, writing in a scratch file. async: false — the
  # journal copy is read through capture_log.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Elixip.Security.Incident
  alias Kelix.Security.IncidentReporter

  @incident %Incident{
    type: :auth_failure,
    src: {192, 0, 2, 5},
    port: 5060,
    proto: "UDP",
    method: :REGISTER,
    realm: "example.com",
    user: "alice",
    reason: :bad_password
  }

  @line "kelixip: auth-failure src=192.0.2.5 port=5060 proto=UDP method=REGISTER " <>
          "realm=example.com user=\"alice\" reason=bad_password"

  setup do
    dir = Path.join(System.tmp_dir!(), "kelix_security_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    %{path: Path.join(dir, "security.log")}
  end

  defp start(opts) do
    {:ok, pid} = IncidentReporter.start_link([name: nil] ++ opts)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  # The cast is processed when a call behind it is answered.
  defp settle(pid), do: :sys.get_state(pid)

  defp lines(path), do: path |> File.read!() |> String.split("\n", trim: true)

  test "one line per incident: the UTC timestamp, a space, then the kelixip: text", %{path: path} do
    pid = start(log_file: path)
    capture_log(fn -> IncidentReporter.report(pid, @incident) && settle(pid) end)

    assert [line] = lines(path)
    assert [stamp, text] = String.split(line, " ", parts: 2)
    assert {:ok, %DateTime{}, 0} = DateTime.from_iso8601(stamp)
    assert text == @line
  end

  test "two incidents cast back to back land in order", %{path: path} do
    pid = start(log_file: path)

    capture_log(fn ->
      IncidentReporter.report(pid, %Incident{@incident | user: "first"})
      IncidentReporter.report(pid, %Incident{@incident | user: "second"})
      settle(pid)
    end)

    assert [first, second] = lines(path)
    assert first =~ ~s(user="first")
    assert second =~ ~s(user="second")
  end

  test "the file removed under the reporter is recreated on the next incident", %{path: path} do
    pid = start(log_file: path)
    capture_log(fn -> IncidentReporter.report(pid, @incident) && settle(pid) end)
    assert File.exists?(path)

    File.rm!(path)
    refute File.exists?(path)

    capture_log(fn -> IncidentReporter.report(pid, @incident) && settle(pid) end)
    assert [_one] = lines(path)
  end

  test "an unwritable path warns once, and the journal copy still carries the line" do
    pid = start(log_file: "/nonexistent-kelix-dir/security.log")

    log =
      capture_log(fn ->
        IncidentReporter.report(pid, @incident)
        IncidentReporter.report(pid, @incident)
        settle(pid)
      end)

    assert length(Regex.scan(~r/cannot write \/nonexistent-kelix-dir\/security.log/, log)) == 1
    assert length(Regex.scan(~r/\[warning\] kelixip: auth-failure src=192\.0\.2\.5 /, log)) == 2
    assert Process.alive?(pid)
  end

  test "with no log_file, the journal copy is all there is", %{path: path} do
    pid = start(log_file: nil)
    log = capture_log(fn -> IncidentReporter.report(pid, @incident) && settle(pid) end)

    assert log =~ @line
    refute File.exists?(path)
  end

  test "an ignored type writes nothing, the others still do", %{path: path} do
    pid = start(log_file: path, ignore: [:invalid_packet])

    log =
      capture_log(fn ->
        IncidentReporter.report(pid, %Incident{
          type: :invalid_packet,
          src: {192, 0, 2, 5},
          port: 5060,
          proto: "UDP",
          reason: :garbage
        })

        IncidentReporter.report(pid, @incident)
        settle(pid)
      end)

    assert [line] = lines(path)
    assert line =~ "auth-failure"
    refute log =~ "invalid-packet"
  end

  test "the application's reporter is the configured sink and takes the struct" do
    assert Application.get_env(:elixip2, :security_sink) == {IncidentReporter, :report}
    assert Process.whereis(IncidentReporter)
    log = capture_log(fn -> Elixip.Security.report(@incident) && settle(IncidentReporter) end)
    assert log =~ @line
  end
end
