defmodule Kelix.Conversations do
  @moduledoc """
  What makes two MESSAGEs one conversation (chat-basic-plan, C3b).

  kelixip's contract is one scenario instance per dialog, and page mode breaks
  it from below: every MESSAGE opens a dialog of its own, with a new Call-ID,
  closed 60 s later. A chat script built on that contract would be born and die
  with each message. So the unit of a chat is the **conversation**, and a
  dialog is one of its messages: `Kelix.Router` computes the key here, and
  `Kelix.InstancePool` hands the MESSAGE to the live instance holding it, or
  spawns one and registers it under it — in one call of its own, so two
  MESSAGEs of one conversation arriving together start one instance.

  The key is `{domain, rule, parties}`, where `rule` names the
  `[[domain.chat]]` block (a bot, a relay and a room are three different
  conversations even between the same two AORs) and `parties` is what the
  block's `conversation` declares:

  | `conversation` | parties | one conversation per |
  |---|---|---|
  | `"pair"` | `{from, to}` | user and bot: Alice→bot is not bot→Alice |
  | `"peers"` (default) | `[a, b]`, sorted | pair of users: Bob's answer reaches the instance Alice's message started |
  | `"to"` | `to` | room: every member writes to one instance |

  The AORs are `user@host`, read by `SIP.Msg.Ops.address_of_record/2`. Neither
  the source address nor the transport is part of the key: Trix reconnects its
  WebSocket at every wake-up, a NAT moves a UDP port, and Alice writing from her
  phone then from her desk is one conversation. The source decides **trust**
  (C3c), never routing.
  """

  alias Kelix.DialRule

  @type key :: {String.t(), String.t() | :default, term}

  @doc """
  The conversation `req` belongs to, under the chat rule that routed it. `nil`
  when the rule declares none (a call rule) or when the request names no AOR the
  key needs — such a MESSAGE is served by an instance of its own, as before
  conversations existed.
  """
  @spec key(String.t(), DialRule.t(), map) :: key | nil
  def key(domain, %DialRule{conversation: kind} = rule, req)
      when is_binary(domain) and kind in [:pair, :peers, :to] and is_map(req) do
    case parties(kind, aor(req, :from), aor(req, :to)) do
      nil -> nil
      parties -> {domain, rule_id(rule), parties}
    end
  end

  def key(_domain, _rule, _req), do: nil

  defp parties(:to, _from, to) when is_binary(to), do: to
  defp parties(:pair, from, to) when is_binary(from) and is_binary(to), do: {from, to}
  defp parties(:peers, from, to) when is_binary(from) and is_binary(to), do: Enum.sort([from, to])
  defp parties(_kind, _from, _to), do: nil

  defp aor(req, header), do: SIP.Msg.Ops.address_of_record(req, header)

  # Rules are first-match and a pattern appears once per domain in practice; the
  # catch-all is single by construction (`Kelix.Domains`).
  defp rule_id(%DialRule{default?: true}), do: :default
  defp rule_id(%DialRule{raw: raw}), do: raw

  @doc "A key as an operator reads it, for the log and the monitor."
  @spec label(key) :: String.t()
  def label({_domain, _rule, {from, to}}), do: "#{from} → #{to}"
  def label({_domain, _rule, [a, b]}), do: "#{a} ↔ #{b}"
  def label({_domain, _rule, to}) when is_binary(to), do: to
end
