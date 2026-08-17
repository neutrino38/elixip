defmodule SIP.Test.Peers.AnsweringUAS do
  @moduledoc """
  A remote party that answers the call: INVITE → 100 Trying, 180 Ringing after
  `ringing_delay` ms (default 100), 200 OK with an SDP answer after
  `answer_delay` ms (default 300). CANCEL is honoured with 200 + 487 when it
  matches the pending INVITE, 481 when there is none.
  """
  use SIP.Test.Peer

  @impl true
  def init(opts) do
    Map.merge(%{ringing_delay: 100, answer_delay: 300}, Map.new(opts))
  end

  @impl true
  def on_request(%{method: :INVITE} = req, state) do
    actions = [
      trying(req),
      reply(req, 180, "Ringing", [], state.ringing_delay),
      reply(
        req,
        200,
        "OK",
        [body: [sdp_answer_body()], contact: remote_contact()],
        state.answer_delay
      )
    ]

    {actions, Map.put(state, :invite, req)}
  end

  def on_request(%{method: :ACK}, state) do
    {[], Map.delete(state, :invite)}
  end

  def on_request(%{method: :CANCEL} = req, state) do
    case state do
      %{invite: %{transid: transid}} when transid == req.transid ->
        {[reply(req, 200, "OK", [], 0), reply(req, 487, nil, [], 100)], state}

      # A pending INVITE on another branch: not ours to cancel.
      %{invite: _} ->
        {[], state}

      _ ->
        {[reply(req, 481, "No such transaction", [], 0)], state}
    end
  end

  def on_request(req, state), do: default_request(req, state)
end
