defmodule SIP.Test.Peers.ChallengingUAS do
  @moduledoc """
  A remote party enforcing Digest authentication: a REGISTER or INVITE without
  an Authorization header is challenged with a 401 (realm `elioz.net` by
  default, override with `realm:`); the retried request carrying credentials
  is accepted with 200 OK. Replies go out after `reply_delay` ms (default 100).

  The credentials themselves are NOT verified — this peer exercises the
  challenge/retry flow, not `SIP.Auth`.
  """
  use SIP.Test.Peer

  @impl true
  def init(opts) do
    Map.merge(%{realm: "elioz.net", reply_delay: 100}, Map.new(opts))
  end

  @impl true
  def on_request(%{method: method} = req, state) when method in [:REGISTER, :INVITE] do
    action =
      cond do
        not Map.has_key?(req, :authorization) ->
          challenge(req, 401, state.reply_delay, state.realm)

        method == :REGISTER ->
          reply(req, 200, "OK", [contact: req.contact], state.reply_delay)

        true ->
          fields = [body: [sdp_answer_body()], contact: remote_contact()]
          reply(req, 200, "OK", fields, state.reply_delay)
      end

    {[action], state}
  end

  def on_request(req, state), do: default_request(req, state)
end
