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
  end
end
