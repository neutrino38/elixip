defmodule Kelix.Mod.Mcu.EventQueueTest do
  # The MCU event stream decoding (docs/design/DESIGN-MCU.md#3-architecture). Pure functions:
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

  # The retry FSM, driven by calling handle_info/2 on a hand-built state: what
  # matters is the decisions it takes, not the :httpc plumbing that delivers them.
  describe "a media server that went away" do
    # Answers :info like Kelix.Mod.Mcu.Client and forwards the casts it receives.
    defmodule StubClient do
      use GenServer

      def start_link(queue_id, test), do: GenServer.start_link(__MODULE__, {queue_id, test})

      @impl true
      def init(s), do: {:ok, s}

      @impl true
      def handle_call(:info, _from, {queue_id, _test} = s),
        do: {:reply, %{name: "mcu1", base_url: "", queue_id: queue_id, status: :up}, s}

      @impl true
      def handle_cast(msg, {_queue_id, test} = s) do
        send(test, {:client_cast, msg})
        {:noreply, s}
      end
    end

    @not_found {{~c"HTTP/1.1", 404, ~c"Not Found"}, [], "Not found"}
    @refused {:error, {:failed_connect, [{:to_address, {~c"127.0.0.1", 9090}}]}}

    defp poller_state(client, overrides \\ %{}) do
      Map.merge(
        %{
          name: "mcu1",
          base_url: "http://127.0.0.1:9090",
          client: client,
          sink: self(),
          # long enough that no timer fires during the test
          retry_ms: 60_000,
          max_failures: 5,
          stall_ms: 60_000,
          request: make_ref(),
          buffer: "",
          failures: 0,
          connected?: false,
          down_notified?: false,
          renewing: nil,
          timer: nil
        },
        overrides
      )
    end

    test "a 404 asks the client for a new queue — once, not once per retry" do
      {:ok, client} = StubClient.start_link(449_511_429, self())
      state = poller_state(client)

      {:noreply, state} = EventQueue.handle_info({:http, {state.request, @not_found}}, state)
      assert_receive {:client_cast, {:renew_queue, 449_511_429}}, 500
      assert state.renewing == 449_511_429

      # the retry loop keeps hitting the same dead id until the new one lands; it
      # must not stack an EventQueueCreate per second
      {:noreply, _state} = EventQueue.handle_info({:http, {state.request, @not_found}}, state)
      refute_receive {:client_cast, _}, 100
    end

    test "a repeated failure is reported a few times, then not until it is back" do
      {:ok, client} = StubClient.start_link(1, self())

      # while we have not concluded the stream is down, every attempt is reported
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          state = poller_state(client)
          EventQueue.handle_info({:http, {state.request, @refused}}, state)
        end)

      assert log =~ "event stream error"

      # once it has been called down, the per-attempt line stops: the single error
      # from retry/1 is the last word until the stream really comes back
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          state = poller_state(client, %{down_notified?: true, failures: 12})
          EventQueue.handle_info({:http, {state.request, @refused}}, state)
        end)

      refute log =~ "event stream error"
    end

    test "coming back says how many attempts it took, and re-arms the reporting" do
      {:ok, client} = StubClient.start_link(1, self())
      state = poller_state(client, %{down_notified?: true, failures: 12, renewing: 1})

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {:noreply, state} =
            EventQueue.handle_info({:http, {state.request, :stream_start, []}}, state)

          send(self(), {:reconnected, state})
        end)

      assert log =~ "event stream connected again after 12 failed attempts"

      assert_received {:reconnected, state}
      assert state.failures == 0
      refute state.down_notified?
      refute state.renewing
    end
  end
end
