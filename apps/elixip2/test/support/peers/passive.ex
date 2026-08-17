defmodule SIP.Test.Peers.Passive do
  @moduledoc """
  The default peer: it initiates nothing and only honours the baseline
  reactions of `SIP.Test.Peer.default_request/2` — 200 OK to the stack's
  OPTIONS keepalives (disable with `reply_options: false` to simulate a dead
  peer) and to its BYEs.

  This is the peer in place when a test never calls `set_peer/3`: UAS tests
  (the test injects requests and asserts on the responses the stack sends)
  need nothing more.
  """
  use SIP.Test.Peer
end
