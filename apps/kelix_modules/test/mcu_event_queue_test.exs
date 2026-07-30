defmodule Kelix.Mod.Mcu.EventQueueTest do
  # The MCU event stream decoding (docs/design/mcu_module.md §3.7). Pure functions:
  # the wire contract is what matters here, not the HTTP plumbing around it.
  use ExUnit.Case, async: true

  alias Kelix.Mod.Mcu.EventQueue

  defp frame(params) do
    XMLRPC.encode!(%XMLRPC.MethodResponse{param: params})
  end

  describe "decode_frames/1" do
    test "splits complete frames and keeps the incomplete tail" do
      a = frame([1, 42, "c-1", 7])
      b = frame([1, 42, "c-1", 8])
      {head, tail} = String.split_at(b, div(String.length(b), 2))

      # one complete frame plus the beginning of the next one
      assert {[^a], rest} = EventQueue.decode_frames(a <> head)
      assert rest == head

      # the tail completes it on the next chunk
      assert {[^b], ""} = EventQueue.decode_frames(rest <> tail)
    end

    test "the bare keep-alive chunk yields nothing and leaves no residue" do
      assert {[], ""} = EventQueue.decode_frames("\r\n")
      assert {[], ""} = EventQueue.decode_frames("\r\n\r\n")
    end

    test "two frames in one chunk are both returned, in order" do
      a = frame([1, 42, "c-a", 1])
      b = frame([1, 42, "c-b", 2])
      assert {[^a, ^b], ""} = EventQueue.decode_frames(a <> "\r\n" <> b)
    end
  end

  describe "decode_event/1" do
    test "type 1 is an FPU request" do
      assert {:ok, {:fpu_requested, 42, "c-3f9a", 7}} =
               EventQueue.decode_event(frame([1, 42, "c-3f9a", 7]))
    end

    test "type 2 (doc sharing) is deliberately ignored, not an error" do
      assert :ignore = EventQueue.decode_event(frame([2, 42, "c-3f9a", 7, "ok"]))
    end

    test "types 3 and 4 decode already, ahead of the server emitting them (P7)" do
      assert {:ok, {:media_timeout, 42, "c-1", 7, :audio}} =
               EventQueue.decode_event(frame([3, 42, "c-1", 7, 0, 0]))

      assert {:ok, {:media_connected, 42, "c-1", 7, :video}} =
               EventQueue.decode_event(frame([4, 42, "c-1", 7, 1, 0]))
    end

    test "an unknown type is reported, not silently dropped" do
      assert {:error, {:unknown_event, _}} = EventQueue.decode_event(frame([99, 1]))
    end

    test "a non-XML-RPC frame is a decode error" do
      assert {:error, {:decode_error, _}} = EventQueue.decode_event("<not-xmlrpc/>")
    end
  end
end
