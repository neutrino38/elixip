defmodule SIP.Test.Probe do
  @moduledoc """
  The observation channel of the mockup transport: the test process attaches
  itself with `SIP.Test.Transport.Mockup.attach_probe/2` and receives every
  message the SIP stack under test puts on the (fake) wire, in a single
  normalized shape:

      {:sip_mockup, {:request_sent, method, msg}}    # the stack sent a request
      {:sip_mockup, {:response_sent, code, msg}}     # the stack sent a response

  Peers can push extra events with the `{:notify, event}` action; those arrive
  as `{:sip_mockup, event}` too. Tests assert with plain `assert_receive`:

      assert_receive {:sip_mockup, {:response_sent, 401, %{callid: ^cid}}}, 2_000
  """

  @doc "Send `event` to the probe pid; a nil probe is a no-op."
  def notify(nil, _event), do: :ok

  def notify(probe, event) when is_pid(probe) do
    send(probe, {:sip_mockup, event})
    :ok
  end
end
