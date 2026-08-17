defmodule SIP.Test.Peers.BusyUAS do
  @moduledoc """
  A remote party that rings then rejects: INVITE → 100 Trying, 180 Ringing
  after `ringing_delay` ms (default 100), 486 Busy Here after `busy_delay` ms
  (default 300).
  """
  use SIP.Test.Peer

  @impl true
  def init(opts) do
    Map.merge(%{ringing_delay: 100, busy_delay: 300}, Map.new(opts))
  end

  @impl true
  def on_request(%{method: :INVITE} = req, state) do
    actions = [
      trying(req),
      reply(req, 180, "Ringing", [], state.ringing_delay),
      reply(req, 486, "Busy Here", [], state.busy_delay)
    ]

    {actions, state}
  end

  def on_request(req, state), do: default_request(req, state)
end
