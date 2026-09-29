defmodule Kelix.Conversations do
  @moduledoc """
  What makes two MESSAGEs one conversation (chat-basic-plan, C3b, C3c).

  kelixip's contract is one scenario instance per dialog, and page mode breaks
  it from below: every MESSAGE opens a dialog of its own, with a new Call-ID,
  closed 60 s later. A chat script built on that contract would be born and die
  with each message. So the unit of a chat is the **conversation**, and a
  dialog is one of its messages: `Kelix.Router` computes the key here, and
  `Kelix.InstancePool` hands the MESSAGE to the live instance holding it, or
  spawns one and registers it under it — in one call of its own, so two
  MESSAGEs of one conversation arriving together start one instance.

  The key is `{domain, rule, from, to, flow}`:

    * `rule` names the `[[domain.chat]]` block — a bot and a relay are two
      conversations even between the same two AORs;
    * `from` and `to` are the AORs, `user@host`, read by
      `SIP.Msg.Ops.address_of_record/2` — tags, display names and Call-IDs
      change with every message, the AORs do not;
    * `flow` is `{transport, ip, port}`, read by `SIP.Msg.Ops.source_flow/1`.

  The flow is what lets routing stand for trust. A `From` is forged in one line;
  a `From` writing to a `To` over the flow that already carried an
  authenticated MESSAGE is the sender who authenticated. So a chat script
  challenges the first MESSAGE of its conversation and lets the next ones
  through: the router only hands it MESSAGEs from that flow. A new flow — Trix
  reconnecting its WebSocket, a NAT moving a UDP port, the same user on another
  device — is a new conversation, challenged once.

  A connected flow can end under a conversation; `Kelix.InstancePool` watches
  it and tells the instance `{:conversation, :transport_down}`. A conversation
  that hibernates is kept under `hibernation_key/1`, without the flow.
  """

  alias Kelix.DialRule

  @type flow :: {String.t(), :inet.ip_address(), :inet.port_number()}
  @type key :: {String.t(), String.t() | :default, String.t(), String.t(), flow}

  @doc """
  The conversation `req` belongs to, under the chat rule that routed it. `nil`
  for a rule that is not a chat rule, and for a request missing one of the
  parts — no `From` or `To` user, no flow (a request that did not come off the
  network). Such a MESSAGE is served by an instance of its own.
  """
  @spec key(String.t(), DialRule.t(), map) :: key | nil
  def key(domain, %DialRule{idle_timeout: idle} = rule, req)
      when is_binary(domain) and is_integer(idle) and is_map(req) do
    from = SIP.Msg.Ops.address_of_record(req, :from)
    to = SIP.Msg.Ops.address_of_record(req, :to)
    flow = SIP.Msg.Ops.source_flow(req)

    if from && to && flow, do: {domain, rule_id(rule), from, to, flow}
  end

  def key(_domain, _rule, _req), do: nil

  # Rules are first-match and a pattern appears once per domain in practice; the
  # catch-all is single by construction (`Kelix.Domains`).
  defp rule_id(%DialRule{default?: true}), do: :default
  defp rule_id(%DialRule{raw: raw}), do: raw

  @doc """
  The key a conversation hibernates under (chat-basic-plan, C3d): the live key
  without its flow. A conversation set aside outlives the flow it came in on —
  the user closed the tab, the connection dropped — and wakes on the next
  MESSAGE between the same two parties, over whatever flow.
  """
  @spec hibernation_key(key) :: {String.t(), String.t() | :default, String.t(), String.t()}
  def hibernation_key({domain, rule, from, to, _flow}), do: {domain, rule, from, to}

  @doc "A key as an operator reads it, for the log and the monitor."
  @spec label(key) :: String.t()
  def label({_domain, _rule, from, to, {transport, ip, port}}),
    do: "#{from} → #{to} via #{transport} #{:inet.ntoa(ip)}:#{port}"
end
