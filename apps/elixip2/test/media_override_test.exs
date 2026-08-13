defmodule SIP.Session.MediaOverrideTest do
  # The per-instance media override (context appdata :mediaserver_instance) must
  # win over the global :mediaserver app env, so a pool can pick an MCU per call
  # without racing on the shared env. Absent the override, the global env is used.
  use ExUnit.Case, async: false

  # a stand-in adapter: connect/1 succeeds so use_mediaserver/3 stores the module
  defmodule FakeMS do
    def connect(_url), do: {:ok, self()}
    def disconnect(_pid, _opts), do: :ok
  end

  # No global-env mutation here: the override path never reads the app env, and the
  # no-override path resolves to the :mockup default — so this test can't race with
  # concurrent media tests on the shared :mediaserver env.

  test "a per-instance appdata override wins over the global :mediaserver env" do
    ctx =
      %SIP.Context{}
      |> SIP.Context.appdata_set(:mediaserver_instance, module: FakeMS, url: "http://mcu/")
      |> SIP.Session.Media.use_mediaserver()

    assert SIP.Context.get(ctx, :mediaservermodule) == FakeMS
    assert SIP.Context.get(ctx, :lasterr) == :ok
  end

  # `module: :unavailable` is a VERDICT, not a server: whoever picked the media
  # server for this call looked and found none. It must not be resolved to an
  # adapter, and above all it must not fall through to the global env — whose
  # default is the test mockup.
  #
  # This is the regression test for 2026-08-13: a pooled MCU that had gone away
  # made `Kelix.Router` return no override at all, so the instance read the global
  # config, connected to `MediaServer.Mockup`, answered the call, carried no media
  # and logged `Scenario … succeeded`. Nobody saw or heard anything, and nothing in
  # the log said why.
  test "an :unavailable verdict refuses to connect instead of falling back to a stub" do
    ctx =
      %SIP.Context{}
      |> SIP.Context.appdata_set(:mediaserver_instance, module: :unavailable)
      |> SIP.Session.Media.use_mediaserver()

    assert SIP.Context.get(ctx, :lasterr) == {:error, :no_media_server}

    # Nothing was connected: no pid, and — the point of the test — NOT the mockup.
    assert SIP.Context.get(ctx, :mediaserverpid) == nil
    refute SIP.Context.get(ctx, :mediaservermodule) == MediaServer.Mockup
  end

  # The fallback itself stays, because a deployment that names its media server in
  # configuration is legitimate: that is the standalone `elixipp` tool, and any
  # kelixip without a `[mediaserver.pool.*]`. Only a pool that ANSWERED "nothing"
  # suppresses it.
  test "with no override at all the global env still applies" do
    ctx = SIP.Session.Media.use_mediaserver(%SIP.Context{})

    assert SIP.Context.get(ctx, :mediaservermodule) == MediaServer.Mockup
    assert SIP.Context.get(ctx, :lasterr) == :ok
  end
end
