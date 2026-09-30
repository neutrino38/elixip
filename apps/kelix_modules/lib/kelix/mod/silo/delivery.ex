defmodule Kelix.Mod.Silo.Delivery do
  @moduledoc """
  One flush: the stored messages of an AOR delivered to the devices a REGISTER
  just bound (chat-basic-plan, C6). It runs in a task of the module's own, not
  in the registrar script that asked for it — delivery is not the registrar's
  time — and is started by `Kelix.Mod.Silo.flush/2`.

  ## The batch

  The AOR's backlog is claimed **as one batch** (`c:Kelix.Mod.Silo.Store.claim/6`),
  so one node delivers all of it, and in order. A claim that finds part of the
  backlog held by another flush — another node, or this one serving the AOR's
  other device — gives back what it took and comes back later, until the lease
  it would wait for has run out: delivering the free part now would put a newer
  message ahead of older ones on the device. Nodes meet through the rows; no
  message crosses between them.

  ## One device at a time, devices in parallel

  Page mode carries nothing a client could reorder by — every MESSAGE is a
  transaction of its own, with a Call-ID of its own — so per device, message
  *n+1* leaves only once *n* has its final answer. The answer is read with the
  classes of `SIP.Msg.Ops.page_verdict/1`:

    * `:delivered`, `:accepted` and `:refused` add the device to the message's
      served set — a device that said 603 or 415 once will say it again;
    * `:unreachable` stops that device's queue for this flush: sending *n+1*
      after a lost *n* would deliver them out of order at the next one.

  Each message is rebuilt with `SIP.MsgTemplate.page_request/2` — its sender,
  its recipient in `To`, the carried-over headers, the body untouched, and
  `Date` set to its arrival.

  ## What it leaves behind

  No journal: no scenario runs here. One `info` line per attempt — AOR, device,
  stored message id, answer — never the content, and the module's counters.
  """
  require Logger

  alias Kelix.Mod.Silo.Store

  # Past the dialog timeout, how long a page may stay silent before it counts as
  # not answered. The transaction layer answers a lost MESSAGE with a 408 well
  # within it.
  @margin_ms 5_000

  @typedoc """
  What a flush needs from the module: the store and its handle, the owner name
  its claims carry, the lease, the page timeout (s), the first retry delay (ms),
  and `report`, called with each counter event.
  """
  @type ctx :: %{
          store: module,
          handle: Store.handle(),
          owner: String.t(),
          lease: pos_integer,
          page_timeout: pos_integer,
          retry_ms: pos_integer,
          report: (atom -> any)
        }

  @doc """
  Deliver the backlog of `aor` on `domain` to `targets` — Request-URIs, as
  `SIP.Msg.Ops.register_targets/1` returns them. Returns once every device's
  queue is done, and the batch given back.
  """
  @spec run(ctx, String.t(), String.t(), [SIP.Uri.t()]) :: :ok
  def run(ctx, domain, aor, targets) do
    case SBB.Page.devices(targets) do
      [] ->
        :ok

      devices ->
        claim(ctx, domain, aor, devices, System.monotonic_time(:millisecond), ctx.retry_ms)
    end
  end

  defp claim(ctx, domain, aor, devices, started, delay) do
    now = now()

    case ctx.store.claim(ctx.handle, domain, aor, ctx.owner, now, now + ctx.lease) do
      {:ok, [], 0} ->
        :ok

      {:ok, messages, 0} ->
        deliver(ctx, domain, aor, devices, messages)
        release(ctx, messages)

      {:ok, messages, _busy} ->
        # Another flush holds part of the backlog: give ours back and wait for
        # the whole of it, or the device gets a newer message before older ones.
        release(ctx, messages)

        if System.monotonic_time(:millisecond) - started + delay <= ctx.lease * 1_000 do
          Process.sleep(delay)
          claim(ctx, domain, aor, devices, started, min(delay * 2, 30_000))
        else
          Logger.warning(
            module: __MODULE__,
            message: "silo: #{aor}@#{domain} held by another flush past the lease — not flushed"
          )
        end

      {:error, reason} ->
        Logger.warning(
          module: __MODULE__,
          message: "silo: #{aor}@#{domain} not flushed, the store failed: #{short(reason)}"
        )
    end
  end

  defp release(ctx, messages) do
    case ctx.store.release(ctx.handle, Enum.map(messages, & &1.id), ctx.owner) do
      :ok ->
        :ok

      {:error, reason} ->
        # The lease frees them anyway once it runs out.
        Logger.warning(
          module: __MODULE__,
          message: "silo: could not release a batch (#{short(reason)}), the lease will"
        )
    end
  end

  defp deliver(ctx, domain, aor, devices, messages) do
    devices
    |> Enum.map(fn {device, target} ->
      Task.async(fn -> queue(ctx, "#{aor}@#{domain}", device, target, messages) end)
    end)
    |> Task.await_many(:infinity)

    :ok
  end

  # One device's queue: the messages it was not served yet, in arrival order,
  # each once the previous one is answered.
  defp queue(ctx, aor, device, target, messages) do
    messages
    |> Enum.reject(&(device in &1.served))
    |> Enum.reduce_while(:ok, fn msg, :ok ->
      answer = page(ctx, msg, target)
      verdict = verdict(answer)

      Logger.info(
        module: __MODULE__,
        message: "silo: #{aor} device #{device} message #{msg.id}: #{answer_text(answer)}"
      )

      ctx.report.(verdict)

      if verdict == :unreachable do
        {:halt, :ok}
      else
        serve(ctx, msg, device)
        {:cont, :ok}
      end
    end)
  end

  defp serve(ctx, msg, device) do
    case ctx.store.serve(ctx.handle, msg.id, device, now()) do
      :ok ->
        :ok

      {:error, reason} ->
        # Delivered but not recorded: the device will get it again at its next
        # REGISTER. A duplicate, not a loss.
        Logger.warning(
          module: __MODULE__,
          message:
            "silo: message #{msg.id} reached #{device} but could not be recorded: #{short(reason)}"
        )
    end
  end

  @doc false
  # The request a stored message goes out as.
  @spec request(Store.message(), SIP.Uri.t()) :: map
  def request(msg, target) do
    msg.headers
    |> Map.merge(%{
      from: msg.sender,
      to: msg.recipient,
      contenttype: msg.content_type,
      body: msg.body
    })
    |> SIP.MsgTemplate.page_request(ruri: target, date: DateTime.from_unix!(msg.received_at))
  end

  defp page(ctx, msg, target) do
    ref = make_ref()

    {:ok, _relay} =
      SIP.Session.Page.Relay.start(
        request(msg, target),
        to_string(target),
        ctx.page_timeout,
        false,
        ref: ref
      )

    receive do
      {:page, :answered, %{ref: ^ref, code: code}} -> code
      {:page, :failed, %{ref: ^ref, reason: reason}} -> {:failed, reason}
    after
      ctx.page_timeout * 1_000 + @margin_ms -> {:failed, :timeout}
    end
  end

  defp verdict(code) when is_integer(code), do: SIP.Msg.Ops.page_verdict(code)
  defp verdict({:failed, _reason}), do: SIP.Msg.Ops.page_verdict(:failed)

  defp answer_text(code) when is_integer(code), do: Integer.to_string(code)
  defp answer_text({:failed, reason}), do: "not answered (#{short(reason)})"

  defp short(reason), do: reason |> inspect() |> String.slice(0, 200)

  defp now, do: System.os_time(:second)
end
