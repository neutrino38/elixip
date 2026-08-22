defmodule SIP.Test.DialogInboundRequest do
  use ExUnit.Case, async: true

  @moduledoc """
  Requests we originate inside an INBOUND dialog (RFC 3261 §12.2.1.1).

  A UAS is the callee: its own identity is the *To* of the request that created
  the dialog, and the tag it generated is the *To* tag. Addressing an outbound
  BYE the UAC way — From from the original From, To from the original To —
  names the callee on both sides, and the far end matches no dialog.

  Found the day `play.exs` first reached its `hanging_up` state at end of file:
  the BYE raised before it could even be built, and once that was fixed the
  addressing was still the caller's. Nothing covered a UAS-originated in-dialog
  request until then.
  """

  alias SIP.DialogImpl

  # The INVITE a UAS receives: alice calls bob, alice's tag is on From.
  defp inbound_invite do
    %{
      method: :INVITE,
      ruri: %SIP.Uri{userpart: "bob", domain: "example.com"},
      from: %SIP.Uri{userpart: "alice", domain: "example.com", params: %{"tag" => "alice-tag"}},
      to: %SIP.Uri{userpart: "bob", domain: "example.com"},
      contact: %SIP.Uri{userpart: "alice", domain: "10.0.0.9", port: 5060}
    }
  end

  defp inbound_dialog do
    %DialogImpl{
      direction: :inbound,
      msg: inbound_invite(),
      fromtag: "alice-tag",
      totag: "bob-tag",
      remotetarget: %SIP.Uri{userpart: "alice", domain: "10.0.0.9", port: 5060}
    }
  end

  defp bare_bye do
    %{method: :BYE, ruri: %SIP.Uri{userpart: nil, domain: nil}, from: nil, to: nil}
  end

  describe "inbound dialog" do
    test "the BYE carries our identity in From and the caller's in To" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert req.from.userpart == "bob"
      assert req.to.userpart == "alice"
    end

    test "the tags follow the same swap: ours on From, the caller's on To" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert SIP.Uri.get_uri_param(req.from, "tag") == {:ok, "bob-tag"}
      assert SIP.Uri.get_uri_param(req.to, "tag") == {:ok, "alice-tag"}
    end

    test "the request is routed to the caller's Contact" do
      req = DialogImpl.address_in_dialog(bare_bye(), inbound_dialog())

      assert req.ruri.userpart == "alice"
      assert req.ruri.domain == "10.0.0.9"
    end

    test "the remote target and route set are learnt from the INVITE itself" do
      # An outbound dialog learns them from the establishing response; an inbound
      # one has no response to learn from, so init must take them off the request.
      invite = Map.put(inbound_invite(), :recordroute, "<sip:proxy.example.com;lr=on>")

      state = %DialogImpl{
        direction: :inbound,
        msg: invite,
        remotetarget: Map.get(invite, :contact),
        routeset: Map.get(invite, :recordroute, [])
      }

      assert state.remotetarget.domain == "10.0.0.9"

      assert DialogImpl.add_route_set(%{method: :BYE}, state).route ==
               "<sip:proxy.example.com;lr=on>"
    end
  end

  describe "outbound dialog is unchanged" do
    defp outbound_dialog do
      %DialogImpl{
        direction: :outbound,
        msg: %{
          method: :INVITE,
          ruri: %SIP.Uri{userpart: "bob", domain: "example.com"},
          from: %SIP.Uri{userpart: "alice", domain: "example.com"},
          to: %SIP.Uri{userpart: "bob", domain: "example.com"}
        },
        fromtag: "alice-tag",
        totag: "bob-tag",
        remotetarget: %SIP.Uri{userpart: "bob", domain: "10.0.0.7", port: 5060}
      }
    end

    test "we stay the From, the callee stays the To, tags likewise" do
      req =
        DialogImpl.address_in_dialog(
          %{
            method: :BYE,
            ruri: %SIP.Uri{userpart: nil, domain: nil},
            from: %SIP.Uri{userpart: "alice", domain: "example.com"},
            to: nil
          },
          outbound_dialog()
        )

      assert req.from.userpart == "alice"
      assert SIP.Uri.get_uri_param(req.from, "tag") == {:ok, "alice-tag"}
      assert req.to.userpart == "bob"
      assert SIP.Uri.get_uri_param(req.to, "tag") == {:ok, "bob-tag"}
      assert req.ruri.domain == "10.0.0.7"
    end

    # Both ends come from the dialog, symmetrically with the inbound clause. The
    # From used to be taken from the request as given, so a caller with no
    # identity of its own — a UAS instance, a B2BUA leg, anything using the
    # placeholder URI `SIP.Session.CallInDialog` builds — sent a From with no
    # domain. That serializes to nothing and takes the whole message down, which
    # is how the B2BUA teardown BYE first surfaced it.
    test "a placeholder From is replaced by the dialog's own identity" do
      req =
        DialogImpl.address_in_dialog(
          %{
            method: :BYE,
            ruri: %SIP.Uri{userpart: nil, domain: nil},
            from: %SIP.Uri{userpart: nil, domain: nil},
            to: nil
          },
          outbound_dialog()
        )

      assert req.from.userpart == "alice"
      assert req.from.domain == "example.com"
      assert SIP.Uri.get_uri_param(req.from, "tag") == {:ok, "alice-tag"}

      # And the result actually serializes, which is the point.
      assert {:ok, _} = SIP.Uri.serialize(req.from)
    end
  end

  describe "the fate of a request we sent into an inbound dialog" do
    # The dialog as it is once we have answered the caller: `state: :established`
    # is what the 2xx we sent put there, and the re-INVITE we then sent the caller
    # is the transaction the responses below answer.
    defp calling_back(dialog_state) do
      %DialogImpl{
        inbound_dialog()
        | state: dialog_state,
          app: self(),
          transactions: %{self() => %{req: re_invite(), module: SIP.ICT}}
      }
    end

    defp re_invite, do: Map.merge(inbound_invite(), %{cseq: [2, :INVITE]})

    defp final(code) do
      %{
        method: false,
        response: code,
        to: %SIP.Uri{userpart: "bob", domain: "example.com", params: %{"tag" => "bob-tag"}},
        cseq: [2, :INVITE]
      }
    end

    # What puts `:established` there. Nothing else ever could: an inbound dialog
    # is created by a request we ANSWER, and handle_UAS_response/3 — which
    # establishes the outbound side on receipt of a 2xx — only ever reads
    # responses we RECEIVE. So the state stayed `:initial` for the dialog's whole
    # life, which is what made a refused re-offer look like a refused INVITE.
    @tag :capture_log
    test "the 2xx we send to the request that created the dialog establishes it" do
      creating = Map.merge(inbound_invite(), %{cseq: [1, :INVITE]})
      state = %DialogImpl{inbound_dialog() | msg: creating, state: :initial}

      assert {:reply, _rc, state} =
               DialogImpl.handle_call({:replyreq, creating, 200, "OK", []}, {self(), nil}, state)

      assert state.state == :established
    end

    # A 2xx to anything else does not: a re-INVITE from the caller, an OPTIONS,
    # the CANCEL of a call still ringing — all of them are answered 2xx on a
    # dialog whose creating request has not been.
    @tag :capture_log
    test "a 2xx to any later request does not" do
      state = %DialogImpl{
        inbound_dialog()
        | msg: Map.merge(inbound_invite(), %{cseq: [1, :INVITE]}),
          state: :initial
      }

      assert {:reply, _rc, state} =
               DialogImpl.handle_call(
                 {:replyreq, re_invite(), 200, "OK", []},
                 {self(), nil},
                 state
               )

      assert state.state == :initial
    end

    # The one this suite exists for. A B2BUA relaying the callee's "camera on"
    # re-offer onto the caller's leg gets a 488 from a browser that cannot use it.
    # RFC 3261 §14.1: the session then stays exactly as it was — the re-offer
    # failed, the call did not. Read as an initial-request rejection instead, it
    # killed the caller's dialog: the B2BUA saw its caller hang up, BYEd the
    # callee, and answered 481 to the caller's own UPDATE and BYE (2026-08-21).
    test "a 488 refusing our re-offer ends the transaction and nothing else" do
      assert {:noreply, state} =
               DialogImpl.handle_info({:response, final(488), self()}, calling_back(:established))

      assert state.state == :established
      assert_receive {488, _rsp, _tid, _dlg}
    end

    # Same request, before we ever answered the caller — an UPDATE inside an early
    # dialog (RFC 3311). The reading is the same one, and it is the DIRECTION that
    # settles it: an inbound dialog was created by a request we answer, never one
    # we send, so no response arriving here can be about its creation.
    test "and the same holds before the dialog is established" do
      assert {:noreply, state} =
               DialogImpl.handle_info({:response, final(488), self()}, calling_back(:initial))

      assert state.state == :initial
    end

    # The exception, and the only non-2xx that is not a matter of policy: the far
    # end says it knows no such dialog (RFC 3261 §12.2.1.2). Ours cannot outlive
    # that, so the dialog stops and the application is told.
    test "a 481 says the dialog is gone at the far end, so it ends here too" do
      assert {:stop, :normal, state} =
               DialogImpl.handle_info({:response, final(481), self()}, calling_back(:established))

      assert state.state == :terminated
    end
  end

  describe "an outbound dialog still dies with its initial request" do
    test "a 488 to the INVITE that would have created it terminates it" do
      state = %DialogImpl{
        outbound_dialog()
        | state: :initial,
          app: self(),
          transactions: %{self() => %{req: outbound_dialog().msg, module: SIP.ICT}}
      }

      rsp = %{
        method: false,
        response: 488,
        to: %SIP.Uri{userpart: "bob", domain: "example.com", params: %{"tag" => "bob-tag"}},
        cseq: [1, :INVITE]
      }

      assert {:stop, :normal, state} = DialogImpl.handle_info({:response, rsp, self()}, state)
      assert state.state == :terminated
    end
  end
end
