defmodule SIP.MsgOpsMediaControlTest do
  @moduledoc """
  `SIP.Msg.Ops.picture_fast_update?/1` and its counterpart
  `picture_fast_update/0` — the RFC 5168 request a video UA sends to ask the far
  end's encoder for a fresh intra-frame.

  Reading it is the message layer's job (CLAUDE.md, *Message Layer*): any video
  leg meets the question — a conference leg, a B2BUA relaying INFO — and the
  policy built on it stays with the caller. It used to be a private pair of
  helpers in each MCU reference script.
  """
  use ExUnit.Case, async: true

  @body elem(SIP.Msg.Ops.picture_fast_update(), 0)

  defp info(fields), do: Map.merge(%{method: :INFO}, Map.new(fields))

  describe "what it recognises" do
    test "the body we send is the body we read back" do
      {body, contenttype} = SIP.Msg.Ops.picture_fast_update()

      assert contenttype == "application/media_control+xml"
      assert SIP.Msg.Ops.picture_fast_update?(info(contenttype: contenttype, body: body))
    end

    test "a part carrying its own content type, inside a multipart body" do
      req =
        info(
          contenttype: "multipart/mixed; boundary=x",
          body: [
            %{contenttype: "application/sdp", data: "v=0\r\n"},
            %{contenttype: "application/media_control+xml", data: @body}
          ]
        )

      assert SIP.Msg.Ops.picture_fast_update?(req)
    end

    test "a single part under the message's content type" do
      req =
        info(
          contenttype: "application/media_control+xml",
          body: [%{contenttype: nil, data: @body}]
        )

      assert SIP.Msg.Ops.picture_fast_update?(req)
    end
  end

  describe "what it refuses, and why each one matters" do
    # The content type identifies the body. Without this half, any INFO whose
    # text happened to mention the primitive would be taken for a request.
    test "the primitive under the wrong content type" do
      refute SIP.Msg.Ops.picture_fast_update?(info(contenttype: "text/plain", body: @body))
    end

    # The primitive says WHICH request it carries: media_control carries more than
    # one, and a scenario asking for something else must not get a frame.
    test "a media_control body asking for something else" do
      other =
        ~s(<?xml version="1.0" encoding="utf-8" ?>) <>
          ~s(<media_control><vc_primitive><to_encoder><stream_layout/>) <>
          ~s(</to_encoder></vc_primitive></media_control>)

      refute SIP.Msg.Ops.picture_fast_update?(
               info(contenttype: "application/media_control+xml", body: other)
             )
    end

    test "an INFO with no body at all, and a keep-alive with an empty one" do
      refute SIP.Msg.Ops.picture_fast_update?(info([]))
      refute SIP.Msg.Ops.picture_fast_update?(info(contenttype: nil, body: nil))
      refute SIP.Msg.Ops.picture_fast_update?(info(contenttype: nil, body: []))
    end

    test "a part shape the stack can produce but that carries no data" do
      req = info(contenttype: "application/media_control+xml", body: [%{contenttype: nil}])

      refute SIP.Msg.Ops.picture_fast_update?(req)
    end
  end
end
