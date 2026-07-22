defmodule HTTP.SessionTest do
  @moduledoc """
  Tests for the HTTP.Session scenario mixin (`http_GET` / the Valet coordinator).

  We drive `HTTP.Session.get_async/4` directly (the layer under the macro) so we
  can inject a fake `Req` `:adapter` — a `fn request -> {request, response} end`
  step that lets us fabricate a response, a slow response, a network error or a
  worker crash without any real socket. `Valet` captures the calling process, so
  the test process plays the role of the scenario: it is the one that must
  receive `{tag, …}`.
  """
  use ExUnit.Case, async: true

  # An adapter returning a fixed 200 response.
  defp ok_adapter(body) do
    [adapter: fn req -> {req, %Req.Response{status: 200, body: body}} end]
  end

  test "delivers {tag, {:ok, %Req.Response{}}} on success" do
    HTTP.Session.get_async("http://stub/ok", 1_000, :prov, ok_adapter("hello"))

    assert_receive {:prov, {:ok, %Req.Response{status: 200, body: "hello"}}}, 1_000
  end

  test "routes the tag: two concurrent requests never cross their replies" do
    HTTP.Session.get_async("http://stub/a", 1_000, :req_a, ok_adapter("A"))
    HTTP.Session.get_async("http://stub/b", 1_000, :req_b, ok_adapter("B"))

    assert_receive {:req_a, {:ok, %Req.Response{body: "A"}}}, 1_000
    assert_receive {:req_b, {:ok, %Req.Response{body: "B"}}}, 1_000
  end

  test "a network error comes back as {tag, {:error, exception}}" do
    # An adapter that returns an exception struct makes Req.get return {:error, _}.
    # Disable Req's default transient-error retry so the error surfaces at once.
    adapter = [
      retry: false,
      adapter: fn req -> {req, %Req.TransportError{reason: :econnrefused}} end
    ]

    HTTP.Session.get_async("http://stub/down", 1_000, :prov, adapter)

    assert_receive {:prov, {:error, %Req.TransportError{reason: :econnrefused}}}, 1_000
  end

  test "a worker crash comes back as {tag, {:error, {:crash, reason}}}" do
    # Exiting inside the adapter kills the worker before it can send a result;
    # the coordinator turns the :DOWN into {:crash, reason}. (An exit is not
    # caught by fetch/2's try/rescue, so the worker really dies.)
    adapter = [adapter: fn _req -> exit(:boom) end]
    HTTP.Session.get_async("http://stub/boom", 1_000, :prov, adapter)

    assert_receive {:prov, {:error, {:crash, :boom}}}, 1_000
  end

  test "timeout: worker is killed, {:error, :timeout} delivered, NO late message" do
    # The adapter sleeps far longer than the timeout; the coordinator must fire
    # its `after`, kill the worker and report :timeout.
    slow = [
      adapter: fn req ->
        Process.sleep(2_000)
        {req, %Req.Response{status: 200}}
      end
    ]

    coord = HTTP.Session.get_async("http://stub/slow", 100, :prov, slow)

    # The single reply we expect is the timeout.
    assert_receive {:prov, {:error, :timeout}}, 1_000

    # The coordinator sends exactly one message then terminates.
    refute Process.alive?(coord)

    # Crucially: the killed worker must NOT deliver a late reply. Wait well past
    # the adapter's 2s sleep and assert the mailbox stays clean — no residual
    # {:prov, …} of any kind arrives after the timeout.
    refute_receive {:prov, _}, 2_500
  end
end
