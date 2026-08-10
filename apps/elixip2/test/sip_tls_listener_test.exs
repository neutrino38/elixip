defmodule SIP.Test.TLSListenerTest do
  @moduledoc """
  `SIP.Transport.TLSListener` against the shared listener contract.

  Same stream semantics as TCP — Depack still reassembles, here across TLS records
  rather than TCP segments — plus a server certificate and a handshake, which is
  why the counts get longer to settle.
  """

  use SIP.Test.ListenerCase,
    listener: SIP.Transport.TLSListener,
    client: SIP.Test.ListenerClient.TLS,
    via_transport: "TLS",
    listener_opts: [certfile: "certs/certificate.pem", keyfile: "certs/private_key.pem"],
    fragmentable: true
end
