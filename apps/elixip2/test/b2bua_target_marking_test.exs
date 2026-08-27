defmodule SIP.Test.B2buaTargetMarking do
  @moduledoc """
  Step 5 of `docs/design/multi-interface.md`, phase 1: every target of a Peer is
  resolved and marked with its side of the network **before** any of them is
  attempted.

  The media server a leg is placed on follows from that mark, and one server
  serves the whole session, so the marks of all the targets have to be known
  together — not discovered one attempt at a time.

  Not `async`: `:internal_networks` is node-wide.
  """
  use ExUnit.Case, async: false

  alias SIP.Session.B2bua

  setup do
    previous = Application.fetch_env(:elixip2, :internal_networks)

    on_exit(fn ->
      case previous do
        {:ok, v} -> Application.put_env(:elixip2, :internal_networks, v)
        :error -> Application.delete_env(:elixip2, :internal_networks)
      end
    end)

    :ok
  end

  defp uri(text) do
    {:ok, uri} = SIP.Uri.parse(text)
    uri
  end

  describe "resolve_and_mark/1" do
    test "a name that resolves gets its address and its side" do
      Application.put_env(:elixip2, :internal_networks, [{{127, 0, 0, 0}, 8}])

      marked = B2bua.resolve_and_mark(uri("sip:bob@localhost:5070"))

      assert marked.destip == {127, 0, 0, 1}
      assert marked.net_side == :internal
    end

    test "the same target is public once the node is told nothing" do
      Application.delete_env(:elixip2, :internal_networks)

      marked = B2bua.resolve_and_mark(uri("sip:bob@localhost:5070"))

      assert marked.destip == {127, 0, 0, 1}
      assert marked.net_side == :public
    end

    test "a target already carrying its destination keeps it, and is marked" do
      # A registrar contact: storing the registration flow is the whole point, so
      # nothing re-resolves it.
      Application.put_env(:elixip2, :internal_networks, [{{10, 0, 0, 0}, 8}])

      stored = %SIP.Uri{uri("sip:bob@example.invalid") | destip: {10, 4, 5, 6}, destport: 5060}
      marked = B2bua.resolve_and_mark(stored)

      assert marked.destip == {10, 4, 5, 6}
      assert marked.destport == 5060
      assert marked.net_side == :internal
    end

    test "a target that cannot be resolved is left exactly as it was" do
      # It fails at its own turn, with the message it has always failed with: this
      # pass adds what it can and changes nothing else.
      before = uri("sip:bob@no-such-host.invalid:5070")
      assert B2bua.resolve_and_mark(before) == before
      assert before.net_side == nil
    end

    test "anything that is not a URI passes through" do
      assert B2bua.resolve_and_mark(:not_a_uri) == :not_a_uri
    end
  end

  describe "stamp_destination/2 — the side travels with the routing" do
    test "a :keep peer keeps its R-URI and takes the target's side" do
      # `:keep` is the trunk case, and an interconnect is exactly a trunk: the
      # R-URI stays what the caller asked for and only the routing comes from the
      # target. Dropping the mark here would lose it on the leg that needs it most.
      target = %SIP.Uri{
        uri("sip:trunk@peer.example")
        | destip: {10, 1, 1, 1},
          destport: 5060,
          destproto: "TCP",
          net_side: :internal
      }

      stamped = B2bua.stamp_destination(uri("sip:+33123456789@caller.example"), target)

      # The identity is the caller's...
      assert stamped.userpart == "+33123456789"
      assert stamped.domain == "caller.example"
      # ...and the whole resolved-routing cluster is the target's, mark included.
      assert stamped.destip == {10, 1, 1, 1}
      assert stamped.destport == 5060
      assert stamped.destproto == "TCP"
      assert stamped.net_side == :internal
    end

    test "an unmarked target stamps no mark" do
      target = %SIP.Uri{uri("sip:trunk@peer.example") | destip: {8, 8, 8, 8}, destport: 5060}
      stamped = B2bua.stamp_destination(uri("sip:bob@caller.example"), target)

      assert stamped.net_side == nil
    end
  end
end
