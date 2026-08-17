defmodule SIP.Test.Peers.NoAnswerUAS do
  @moduledoc """
  A remote party that rings forever: INVITE → 100 Trying, 180 Ringing after
  `ringing_delay` ms (default 100), then 408 Request Timeout after
  `timeout_delay` ms (default 500) — the ringing was never answered.
  """
  use SIP.Test.Peer

  @impl true
  def init(opts) do
    Map.merge(%{ringing_delay: 100, timeout_delay: 500}, Map.new(opts))
  end

  @impl true
  def on_request(%{method: :INVITE} = req, state) do
    actions = [
      trying(req),
      reply(req, 180, "Ringing", [], state.ringing_delay),
      reply(req, 408, "Request Timeout", [], state.timeout_delay)
    ]

    {actions, state}
  end

  def on_request(req, state), do: default_request(req, state)
end
