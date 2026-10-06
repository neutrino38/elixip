defmodule SBB.Page do
  @moduledoc """
  The page relay, as a service building block: one inbound MESSAGE, one page per
  device of the recipient, one outcome (docs/design/chat-basic-plan.md, C4).

      state relay do
        req = last_uas_req()

        case Kelix.Mod.Registrar.targets(ctx_get(:domain), req) do
          {:ok, peer} ->
            page(args: %{peer: peer})

            on_events do
              {:page, :delivered, %{code: code}} -> goto(answer, code)
              {:page, :refused, %{code: code}} -> goto(answer, code)
              {:page, :unreachable, _} -> goto(store, "no device took it")
            end

          :notfound ->
            goto(store, "nobody registered")
        end
      end

  What a chat B2BUA is: not the two-leg machinery of a call — there is no dialog
  to bridge, no BYE, no re-offer — but **one inbound transaction, N outbound
  transactions, one answer**. The MESSAGE is rebuilt (`SIP.MsgTemplate.page_request/2`)
  and sent to **every** contact of the peer at once, not hunted serially: RFC
  3428 §8 lets a proxy fork a MESSAGE, and every modern client expects it on
  every device.

  The block does not answer the inbound MESSAGE: the code to answer is in the
  outcome, and whether to answer it, store the message first or answer
  something else is the script's.

  ## What it takes

  Through `args`:

    * `:peer` — the devices, as `Kelix.Mod.Registrar.targets/2` returns them
      (`%SIP.B2bua.Peer{}`, every q group at once), or a list of URIs. A peer
      handing out targets through a provider has no device list to fan out to,
      and is `:unreachable`;
    * `:request` — the MESSAGE to relay, `last_uas_req()` by default;
    * `:timeout` — how long to wait for the devices, in ms (16 s by default).
      Past it, a device that has not answered counts as not reached. The bound
      is the sender's: its own transaction gives up at 32 s (timer F), and an
      answer after that reaches nobody.

  ## What it answers

  See `@sbb_returns` below. Every outcome carries:

    * `served` — the device keys (`SIP.Msg.Ops.device_key/1`) that gave a final
      verdict, a 2xx or a refusal: the ones a later delivery from storage must
      not serve again;
    * `answers` — every device's answer so far, `device key => code`, or
      `{:failed, reason}` for a page that never got one.

  A 2xx other than 202 wins at once: the devices still silent are not waited
  for, and their answers, when they come, are not reported. A 202 says
  *accepted, not delivered* — a client answers it for a sender it quarantines —
  so 202s alone give a 202, once every device has answered: the relay does not
  upgrade it into a 200 the recipient never gave.

  With no 2xx, the split between `:refused` and `:unreachable` is a reading of
  SIP codes (`SIP.Msg.Ops.page_verdict/1`), not a policy: a refusal is a verdict
  on the content or the sender, and storing it would bring a blocked sender's
  message back at every REGISTER.

  ## In the journal

  Each device's page is a lane of its own — its own Call-ID — labelled with
  the device, so the fan-out reads as it happened: which device answered what,
  and which one never did.
  """

  @doc false
  defmacro __using__(_opts) do
    # See SBB.Call: `:page` is a block's namespace, so `on_events` classifies
    # its returns as scenario events.
    SIP.Scenario.register_namespace(__CALLER__.module, :page)

    quote do
      import SBB.Page
    end
  end

  @doc """
  Relay the MESSAGE to every device of the peer and wait for the outcome.
  Options are `sbb_fsm/2`'s; see the module doc for the `args` it reads.
  """
  defmacro page(opts \\ []) do
    quote do
      sbb_fsm(SBB.Page.Fanout, unquote(opts))
    end
  end

  @doc """
  The devices of `peer`, one per device key, in the order they are to be paged:
  `[{device_key, target}]`. Two bindings of one device (a re-registration from a
  new address with the same `+sip.instance`) are paged once.
  """
  @spec devices(term()) :: [{binary(), SIP.Uri.t()}]
  def devices(%SIP.B2bua.Peer{provider: nil, uris: uris}), do: devices(uris)
  def devices(%SIP.B2bua.Peer{}), do: []

  def devices(uris) when is_list(uris) do
    uris
    |> List.flatten()
    |> Enum.map(&target/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&{SIP.Msg.Ops.device_key(&1), &1})
    |> Enum.uniq_by(&elem(&1, 0))
  end

  def devices(one), do: devices([one])

  defp target(%SIP.Uri{} = uri), do: uri

  defp target(str) when is_binary(str) do
    case SIP.Uri.parse(str) do
      {:ok, uri} -> uri
      _junk -> nil
    end
  end

  defp target(_other), do: nil

  @doc """
  Where a fan-out stands: `{outcome, code}` once it is decided, `:wait` while it
  is not. `answers` maps each device that answered to its code or
  `{:failed, reason}`; `pending` is the number still silent.
  """
  @spec decide(%{binary() => term()}, non_neg_integer()) ::
          {:delivered | :refused, 100..699} | {:unreachable, nil} | :wait
  def decide(answers, pending) do
    verdicts = Enum.map(answers, fn {_device, answer} -> {verdict(answer), answer} end)

    cond do
      (code = first_code(verdicts, :delivered)) != nil -> {:delivered, code}
      pending > 0 -> :wait
      first_code(verdicts, :accepted) != nil -> {:delivered, 202}
      (code = best_refusal(verdicts)) != nil -> {:refused, code}
      true -> {:unreachable, nil}
    end
  end

  @doc """
  Note one device's answer. `:not_ours` for an answer to another fan-out — one
  the instance ran earlier and left before every device had answered; else
  whether to go on waiting, with the updated `pending` and `answers`.
  """
  @spec record(%{term() => binary()}, %{binary() => term()}, term(), term()) ::
          :not_ours | {:wait | :decided, map(), map()}
  def record(pending, answers, ref, answer) do
    case Map.pop(pending, ref) do
      {nil, _pending} ->
        :not_ours

      {device, pending} ->
        answers = Map.put(answers, device, answer)
        decision = if decide(answers, map_size(pending)) == :wait, do: :wait, else: :decided
        {decision, pending, answers}
    end
  end

  @doc "The device keys that gave a final verdict: a 2xx or a refusal."
  @spec served(%{binary() => term()}) :: [binary()]
  def served(answers) do
    for {device, answer} <- answers,
        verdict(answer) in [:delivered, :accepted, :refused],
        do: device
  end

  defp verdict(code) when is_integer(code), do: SIP.Msg.Ops.page_verdict(code)
  defp verdict({:failed, _reason}), do: SIP.Msg.Ops.page_verdict(:failed)

  defp first_code(verdicts, wanted),
    do: Enum.find_value(verdicts, fn {v, code} -> if v == wanted, do: code end)

  # The refusal relayed to the sender: a 6xx says *anywhere* (RFC 3261 §21.6)
  # and outranks a 4xx that speaks for one device only.
  defp best_refusal(verdicts) do
    verdicts
    |> Enum.filter(fn {v, _code} -> v == :refused end)
    |> Enum.map(&elem(&1, 1))
    |> Enum.sort_by(&(-div(&1, 100)))
    |> List.first()
  end

  @doc false
  # Page every device, each under a `ref` of its own and a journal lane named
  # after it. Returns the context and the pending map, `ref => device key`.
  @spec fan_out(%SIP.Context{}, map(), [{binary(), SIP.Uri.t()}], reference()) ::
          {%SIP.Context{}, %{term() => binary()}}
  def fan_out(sip_ctx, req, devices, fanout) do
    Enum.reduce(devices, {sip_ctx, %{}}, fn {device, target}, {ctx, pending} ->
      ref = {fanout, device}
      opts = [ref: ref, leg: "page " <> device_label(target)]
      ctx = SIP.Session.Page.do_send_page(ctx, target, req, nil, opts)
      {ctx, Map.put(pending, ref, device)}
    end)
  end

  # The lane label: user@host of the contact, short enough for a diagram.
  defp device_label(%SIP.Uri{userpart: user, domain: host}) when is_binary(user),
    do: "#{user}@#{host}"

  defp device_label(%SIP.Uri{domain: host}), do: to_string(host)

  defmodule Fanout do
    @moduledoc "The FSM behind `SBB.Page.page/1`."

    use SIP.SBB

    @sbb_namespace :page

    @sbb_args [:peer, :request, :timeout]

    @sbb_returns [
      delivered:
        "a device took the message — %{code, served, answers}: `code` is the first " <>
          "2xx other than 202, else 202 once every device has answered",
      refused:
        "no 2xx, and a device gave a verdict on the content or the sender — " <>
          "%{code, served, answers}, `code` the refusal to relay (6xx first)",
      unreachable:
        "no device took it and none refused it: *not now* — %{served, answers}; " <>
          "what storage is for"
    ]

    # The `:timeout` below bounds the wait; this only catches a sequence that
    # somehow outlives it.
    @sbb_timeout 60_000

    @default_timeout 16_000

    state initial_state do
      req = sbb_data_get(:request) || last_uas_req()
      fanout = make_ref()

      case SBB.Page.devices(sbb_data_get(:peer)) do
        [] ->
          sbb_return({:page, :unreachable, %{served: [], answers: %{}}})

        devices ->
          {sip_ctx, pending} = SBB.Page.fan_out(sip_ctx, req, devices, fanout)
          sbb_data_set(:pending, pending)
          sbb_data_set(:answers, %{})
          goto(waiting, "paged #{map_size(pending)} device(s)")
      end
    end

    # `stay` rather than `goto(waiting)`: the timeout is one bound for the whole
    # fan-out, and re-entering the state would re-arm it at every answer.
    state waiting do
      on_events do
        {:page, :answered, %{code: code, ref: ref}} ->
          case SBB.Page.record(sbb_data_get(:pending), sbb_data_get(:answers), ref, code) do
            :not_ours ->
              stay("answer to another fan-out")

            {decision, pending, answers} ->
              sbb_data_set(:pending, pending)
              sbb_data_set(:answers, answers)

              if decision == :wait,
                do: stay("#{code} from a device"),
                else: goto(concluded, "#{code} from a device")
          end

        {:page, :failed, %{reason: reason, ref: ref}} ->
          case SBB.Page.record(
                 sbb_data_get(:pending),
                 sbb_data_get(:answers),
                 ref,
                 {:failed, reason}
               ) do
            :not_ours ->
              stay("failure of another fan-out")

            {decision, pending, answers} ->
              sbb_data_set(:pending, pending)
              sbb_data_set(:answers, answers)

              if decision == :wait,
                do: stay("a page failed"),
                else: goto(concluded, "a page failed")
          end
      after
        sbb_data_get(:timeout) || @default_timeout ->
          goto(concluded, "devices silent past the timeout")
      end
    end

    # The devices still silent are let go — their pages carry on, unreported —
    # and the outcome is named literally, so `sbb_return` can check it.
    state concluded do
      pending = sbb_data_get(:pending)
      SIP.Session.Page.abandon_pages(Map.keys(pending))

      answers = sbb_data_get(:answers)
      served = SBB.Page.served(answers)

      case SBB.Page.decide(answers, 0) do
        {:delivered, code} ->
          sbb_return({:page, :delivered, %{code: code, served: served, answers: answers}})

        {:refused, code} ->
          sbb_return({:page, :refused, %{code: code, served: served, answers: answers}})

        {:unreachable, nil} ->
          sbb_return({:page, :unreachable, %{served: served, answers: answers}})
      end
    end
  end
end
