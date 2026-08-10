defmodule SIP.Test.Wait do
  @moduledoc """
  Polling helper shared by every app's test suite.

  It replaces the fifteen private `wait_until/2` copies that had drifted into
  three mutually incompatible signatures: ms-based returning `:ok | :timeout`
  (the listener tests), ms-based returning `true | false` (the media pool), and
  attempt-based returning the truthy value or calling `flunk/1` (the MCU tests).
  Reading a call site meant first finding out which of the three it was, and the
  attempt-based form silently changed its own timeout whenever the default
  attempt count was edited.

  Two entry points, because the call sites genuinely want two things:

    * `until/2` answers whether the condition held, so it composes with both
      `assert` and `refute` — the media pool tests need the negative
      ("a server the pool disabled never comes back healthy").
    * `until!/2` is for an arrange step, where a condition that never holds is
      not a result to assert on but a broken fixture; it fails on the spot with
      the caller's own line rather than letting the real test fail confusingly
      further down.
  """

  @poll_ms 10
  @default_timeout_ms 2_000

  @doc """
  Polls `fun` until it returns a truthy value, and returns that value.

  Returns `false` if `timeout_ms` elapses first, so the result reads correctly
  under both `assert` and `refute`. Note that a `refute` spends the whole
  timeout by construction — pass a short one.
  """
  def until(fun, timeout_ms \\ @default_timeout_ms) when is_function(fun, 0) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    poll(fun, deadline)
  end

  # The budget is a wall-clock deadline, not a countdown decremented by the poll
  # interval. Every one of the fifteen helpers this replaces decremented by its
  # own sleep, which silently assumes the condition is cheap to evaluate: the
  # listener tests poll with `:gen_tcp.recv(sock, 0, 100)`, so a nominal 2 s
  # budget really allowed 200 iterations x 100 ms of blocking recv — twenty
  # seconds. A deadline holds whatever the condition costs.
  defp poll(fun, deadline) do
    case fun.() do
      falsy when falsy in [nil, false] ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(@poll_ms)
          poll(fun, deadline)
        else
          false
        end

      truthy ->
        truthy
    end
  end

  @doc """
  Like `until/2`, but fails the test when the condition never holds.

  For arrange steps ("the stub MCU has come up") where a silent `false` would
  surface as an unrelated failure later on.
  """
  def until!(fun, timeout_ms \\ @default_timeout_ms) when is_function(fun, 0) do
    case until(fun, timeout_ms) do
      false -> ExUnit.Assertions.flunk("condition never held within #{timeout_ms} ms")
      truthy -> truthy
    end
  end
end
