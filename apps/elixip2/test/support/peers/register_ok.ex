defmodule SIP.Test.Peers.RegisterOK do
  @moduledoc """
  A registrar that accepts everything: REGISTER → 200 OK echoing the request's
  Contact, after `reply_delay` ms (default 100). Combine with
  `reply_options: false` to establish a registration and then simulate a peer
  that stops answering the keepalive OPTIONS.
  """
  use SIP.Test.Peer

  @impl true
  def init(opts) do
    Map.merge(%{reply_delay: 100}, Map.new(opts))
  end

  @impl true
  def on_request(%{method: :REGISTER} = req, state) do
    {[reply(req, 200, "OK", [contact: req.contact], state.reply_delay)], state}
  end

  def on_request(req, state), do: default_request(req, state)
end
