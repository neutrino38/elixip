defmodule SIP.Test.WSSListenerTest do
  @moduledoc """
  `SIP.Transport.WSSListener` against the shared listener contract.

  No reassembly test, and that is the point rather than an omission: WebSocket
  frames carry their own length, so a SIP message arrives whole and
  `SIP.Transport.Depack` is not in this transport's path at all.

  Inbound WSS also differs in how a disconnect is noticed — `Socket.Web.active/2`
  spawns a separate reader process and the GenServer monitors it — so the
  "removed on disconnect" case is exercising a mechanism of its own here, not the
  same one under a different socket module.
  """

  use SIP.Test.ListenerCase,
    listener: SIP.Transport.WSSListener,
    client: SIP.Test.ListenerClient.WSS,
    via_transport: "WSS",
    listener_opts: [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"]
end
