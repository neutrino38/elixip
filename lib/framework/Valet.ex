defmodule Valet do
  @moduledoc """
  Valet turns any synchronous processing that takes time into an asynchronous
  one whose result is delivered as a single tagged message to the caller.

  `ask/4` spawns a disposable **coordinator** that owns a monitored **worker**
  running `fun`. A single `receive`/`after` serializes the worker result against
  the timeout, so there is no race and exactly one message is sent back to the
  caller before the coordinator terminates — no late message can ever leak:

      {tag, result}                      # whatever `fun` returned, verbatim
      {tag, {:error, :timeout}}          # `timeout` elapsed; the worker was killed
      {tag, {:error, {:crash, reason}}}  # the worker died before returning

  `args` is the list of positional arguments applied to `fun` (`apply(fun, args)`),
  so its length must match the function's arity.
  """

  defp coordinator(caller_pid, timeout, tag, fun, args) do
    coord = self()

    # spawn_monitor so a worker crash surfaces as a :DOWN we can turn into
    # {:crash, reason} instead of silently hanging until `after`. The worker's
    # mailbox is private to this coordinator, so a bare marker tag is enough.
    {worker, ref} = spawn_monitor(fn -> send(coord, {:valet, apply(fun, args)}) end)

    receive do
      # Result arrived in time. The worker then exits :normal, leaving a
      # pending :DOWN in our mailbox — flush it so it cannot leak.
      {:valet, result} ->
        Process.demonitor(ref, [:flush])
        send(caller_pid, {tag, result})

      # Worker died before sending a result (exception / killed elsewhere).
      {:DOWN, ^ref, :process, ^worker, reason} ->
        send(caller_pid, {tag, {:error, {:crash, reason}}})
    after
      timeout ->
        Process.exit(worker, :kill)
        Process.demonitor(ref, [:flush])
        send(caller_pid, {tag, {:error, :timeout}})
    end
  end

  @doc """
  Run `apply(fun, args)` asynchronously, bounding the whole operation to
  `timeout` milliseconds. Returns the coordinator pid immediately; the caller is
  never blocked. The result is delivered to the **calling** process as a single
  `{tag, result}` message (see the module doc for the shapes).
  """
  @spec ask(term(), function(), list(), pos_integer()) :: pid()
  def ask(tag, fun, args, timeout)
      when is_function(fun) and is_list(args) and is_integer(timeout) and timeout > 0 do
    caller = self()
    spawn(fn -> coordinator(caller, timeout, tag, fun, args) end)
  end
end
