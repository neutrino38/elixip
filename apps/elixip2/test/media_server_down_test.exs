defmodule SIP.Test.Media.ServerDown do
  @moduledoc """
  The media server as a failure domain (design docs/design/DESIGN-FRAMEWORK.md#67-the-media-server-as-a-failure-domain,
  R8 — B2BUA P3 R6).

  `:server_disconnected` was delivered to every sink and acted upon by nothing.
  A scenario without a clause for it left the event in its mailbox and went on
  waiting for media that could not come, until its own `after` fired — if it had
  one. Six reference scenarios closed that by hand; the seventh was always going
  to forget.

  Two halves are pinned here: the default reaction for a scenario that never
  considered the case, and the fact that a scenario which DID consider it keeps
  control.
  """
  use ExUnit.Case

  alias SIP.Session.Media

  setup_all do
    :ok = SIP.Transac.start()
    :ok = SIP.Transport.Selector.start()
    :ok = SIP.Dialog.start()
    {:ok, _cfg} = SIP.Session.ConfigRegistry.start()
    :ok
  end

  # A scenario with no idea media servers can die: one state, one clause, and an
  # `after` long enough that reaching it would be the failure.
  defmodule Oblivious do
    use SIP.Scenario

    state initial_state do
      goto(waiting)
    end

    state waiting do
      on_events do
        {:ms_event, _ref, :ice_connected} -> scenario_success("media connected")
      after
        30_000 -> scenario_failure("waited for media that never came")
      end
    end
  end

  # …and one that handles it itself. The default must not overrule this.
  defmodule Aware do
    use SIP.Scenario

    state initial_state do
      goto(waiting)
    end

    state waiting do
      on_events do
        {:ms_event, _ref, :server_disconnected} -> scenario_success("handled it myself")
      after
        30_000 -> scenario_failure("clause never ran")
      end
    end
  end

  # A scenario that reads every media event generically also counts as handling
  # it — being generous here errs toward leaving the scenario in charge.
  defmodule Generic do
    use SIP.Scenario

    state initial_state do
      goto(waiting)
    end

    state waiting do
      on_events do
        {:ms_event, _ref, event} -> scenario_success("saw #{inspect(event)}")
      after
        30_000 -> scenario_failure("clause never ran")
      end
    end
  end

  defp run(module) do
    test_pid = self()
    pid = spawn(fn -> send(test_pid, {:done, SIP.Scenario.Runner.run_instance(module, [])}) end)
    pid
  end

  test "a scenario that never considered it is shut down cooperatively, not left waiting" do
    pid = run(Oblivious)
    send(pid, {:ms_event, self(), :server_disconnected})

    # Aborted rather than failed: nothing went wrong with the scenario, its
    # media plane went away. And `finalize` ran, which is the point — the legs
    # and the media are released instead of being discovered at teardown.
    assert_receive {:done, {:aborted, _reason}}, 5_000
  end

  test "a scenario that handles it keeps control" do
    pid = run(Aware)
    send(pid, {:ms_event, self(), :server_disconnected})

    assert_receive {:done, :ok}, 5_000
  end

  test "so does one that reads media events generically" do
    pid = run(Generic)
    send(pid, {:ms_event, self(), :server_disconnected})

    assert_receive {:done, :ok}, 5_000
  end

  describe "the watcher" do
    test "an adapter that dies reaches the scenario as :server_disconnected" do
      ctx = Media.use_mediaserver(%SIP.Context{}, MediaServer.Mockup, "sip:localhost:8080")
      server = ctx.mediaserverpid

      # Killed outright: no terminate/2 runs, so the adapter announces nothing on
      # its own. This is the gap the watcher exists to close — without it the
      # scenario learns the truth only when its next media call exits :noproc.
      Process.exit(server, :kill)

      assert_receive {:ms_event, ^server, :server_disconnected}, 2_000
    end

    test "a server released on purpose announces nothing" do
      ctx = Media.use_mediaserver(%SIP.Context{}, MediaServer.Mockup, "sip:localhost:8080")
      server = ctx.mediaserverpid

      # The scenario asked for this. Announcing it would turn every clean
      # teardown into a media failure.
      Media.media_cleanup_ressources(ctx)

      refute_receive {:ms_event, ^server, :server_disconnected}, 500
    end
  end

  describe "the Conn call timeout" do
    setup do
      previous = Application.get_env(:elixip2, MediaServer.Mendooze)
      on_exit(fn -> Application.put_env(:elixip2, MediaServer.Mendooze, previous || []) end)
      :ok
    end

    test "is configurable" do
      Application.put_env(:elixip2, MediaServer.Mendooze, call_timeout_ms: 45_000)
      assert MediaServer.Mendooze.Conn.call_timeout() == 45_000
    end

    test "never drops below a multiple of the XML-RPC timeout" do
      # The invariant, not politeness: the inner timeout has to fire first, or a
      # slow server turns a call that would have RETURNED an error into an exit.
      Application.put_env(:elixip2, MediaServer.Mendooze,
        call_timeout_ms: 5_000,
        xmlrpc_timeout_ms: 20_000
      )

      assert MediaServer.Mendooze.Conn.call_timeout() >= 3 * 20_000
    end

    test "defaults to 10 s with the default RPC timeout" do
      Application.put_env(:elixip2, MediaServer.Mendooze, [])
      assert MediaServer.Mendooze.Conn.call_timeout() == 10_000
      # …and stays clear of the floor, so the default pair is a real two-level
      # arrangement and not the floor in disguise.
      assert MediaServer.Mendooze.Conn.call_timeout() > 3 * MediaServer.Mendooze.XmlRpc.timeout_ms()
    end
  end
end
