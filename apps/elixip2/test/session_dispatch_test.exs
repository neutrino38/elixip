defmodule SIP.Session.DispatchTest do
  # What `SIP.Session.ConfigRegistry.dispatch/3` does with an @optional_callbacks
  # function the configured host does not implement. The dialog layer calls this
  # from `SIP.DialogImpl.init/1`, where a raise is not an error path: the dialog
  # dies before the request is answered, and the sender is left with nothing.
  use ExUnit.Case, async: false

  alias SIP.Session.ConfigRegistry

  defmodule PartialHost do
    @behaviour SIP.Session.Presence

    @impl true
    def on_new_subscribe(_dialog, _req, _trans), do: {:accept, self()}

    @impl true
    def on_new_publish(_dialog, _req, _trans), do: {:accept, self()}

    @impl true
    def on_subscription_expired(_dialog, _app), do: :ok
    # on_message/3 is optional, and this host does not implement it
  end

  defmodule ChattyHost do
    @behaviour SIP.Session.Presence

    @impl true
    def on_new_subscribe(_dialog, _req, _trans), do: {:accept, self()}

    @impl true
    def on_new_publish(_dialog, _req, _trans), do: {:accept, self()}

    @impl true
    def on_subscription_expired(_dialog, _app), do: :ok

    @impl true
    def on_message(_dialog, _req, _trans), do: {:reject, 405, "Method Not Allowed"}
  end

  setup do
    case ConfigRegistry.start() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end

    :ok
  end

  defp message_req(),
    do: %{
      method: :MESSAGE,
      ruri: %SIP.Uri{userpart: "bob", domain: "example.com"},
      callid: "call-1"
    }

  # Regression for 2026-09-22: a Linphone typing indicator (an out-of-dialog
  # MESSAGE carrying `application/im-iscomposing+xml`) reached a presence host with
  # no `on_message/3`. The `:undef` killed the dialog inside its `init/1` and the
  # sender got no response at all — the whole reason the callback is optional is
  # that a host may legitimately not have it.
  test "an optional callback the host does not implement is 501, not a crash" do
    ConfigRegistry.set_presence_processing_module(PartialHost)

    assert {:reject, 501, _reason} = ConfigRegistry.dispatch(self(), message_req(), self())
  end

  test "a host that implements it answers for itself" do
    ConfigRegistry.set_presence_processing_module(ChattyHost)

    assert {:reject, 405, "Method Not Allowed"} =
             ConfigRegistry.dispatch(self(), message_req(), self())
  end
end
