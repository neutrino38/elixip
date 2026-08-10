defmodule SIP.Test.TCPListenerTest do
  @moduledoc """
  `SIP.Transport.TCPListener` against the shared listener contract.

  Plain TCP: no certificate, and the fastest of the three to establish, so the
  connection counts are given the least time to settle.
  """

  use SIP.Test.ListenerCase,
    listener: SIP.Transport.TCPListener,
    client: SIP.Test.ListenerClient.TCP,
    via_transport: "TCP",
    settle_ms: 1_000,
    # a stream transport, so SIP.Transport.Depack has to put the message back
    # together across segments
    fragmentable: true
end
