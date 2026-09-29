defmodule SIP.Scenario do
  @moduledoc """
  What a **SIP** scenario writes: the Finite State Language, bound to a SIP
  session.

      defmodule UAC.Invite do
        use SIP.Scenario

        config username: "toto", domain: "mydomain.com", passwd: "xxxx"

        state calling do
          send_INVITE("sip:bob@mydomain.com", :mediaserver, timeout: 30)
          goto wait_answer
        end
      end

  Seven `use` lines' worth of SIP verbs — `SIP.Session.CallUAC`,
  `SIP.Session.Media`, `SIP.Session.B2bua`, the two halves of the subscription
  layer, `SIP.Session.SubscribeUAC` (watcher) and `SIP.Session.Notifier`
  (notifier), `SIP.Session.Publish` (RFC 3903) and `SIP.Session.Page` (RFC 3428
  page mode) — plus `FSL.Machine`, told
  which embedding to call back into (`SIP.FSL.Host`) and what this binding calls
  its context variable (`sip_ctx`).

  Both halves of RFC 6665 are brought in unconditionally, the way both halves of
  INVITE already are: a scenario is a UAC or a UAS by what it writes, not by what
  it `use`s, and a macro nobody calls costs nothing.

  **This facade is not a transition device.** `SIP.Scenario` is the name a SIP
  scenario *should* use: it is the one that brings the SIP verbs with it, and it
  is what `FSL.md` documents. `FSL.Machine` is what a non-SIP user of the
  language writes, and it brings nothing but the language.

  The order of the lines below is load-bearing. The session mixins reach
  `SIP.Context`, which records `sip_ctx` and this binding's own `set/3` / `get/2`
  as the accessors the generic context macros go through — and it has to have
  done so before `FSL.Machine` expands a single `state`, because that macro
  generates the head that binds the variable. `use FSL.Context` inside
  `FSL.Machine` then finds the work done and does nothing.
  """

  @doc """
  Start the SIP layers once (transactions, transport selector, dialog, config
  registry, auth secret). Idempotent.

  Use it before spawning several scenario instances that each call `run(false)`.
  The layers themselves are `SIP.FSL.Host.bootstrap/0`.
  """
  @spec start_stack() :: :ok
  defdelegate start_stack(), to: SIP.FSL.Host, as: :bootstrap

  @doc false
  defdelegate deadline(timeout), to: FSL.Machine

  @doc false
  defdelegate remaining_timeout(deadline), to: FSL.Machine

  @doc """
  Teach a scenario the namespace of a service building block it is about to
  call, so a clause matching that block's return is classified as a block return
  rather than as a message from a peer. Called by a face module's `__using__`.
  """
  defdelegate register_namespace(caller_module, namespace), to: FSL.Machine

  defmacro __using__(opts) do
    kind = Keyword.get(opts, :kind, :scenario)

    quote do
      use SIP.Session.CallUAC
      use SIP.Session.Media
      use SIP.Session.B2bua
      use SIP.Session.SubscribeUAC
      use SIP.Session.Notifier
      use SIP.Session.Publish
      use SIP.Session.Page

      use FSL.Machine,
        host: SIP.FSL.Host,
        ctx_var: :sip_ctx,
        kind: unquote(kind)

      import SIP.Scenario, only: [uas: 1]

      # The SIP role a scenario plays, in FSL's opaque `__scenario_type__/0`
      # slot: `:uac` unless `uas/1` says otherwise. Set here and not in the
      # language, because `uac` and `uas` are role names in a protocol
      # (extraction plan §4.11).
      @scenario_type :uac
    end
  end

  @doc """
  Declare that this scenario is a server (UAS) scenario of a given kind, e.g.
  `uas :register`. This sets `__scenario_type__/0` to `:uas_<kind>` so the loader
  and `elixipp` can tell server scenarios apart from the default `:uac` client
  scenarios. The scenario itself implements the request handling (e.g. replying
  to a REGISTER), since that is application responsibility.

  A SIP macro, not one of the language's: FSL keeps the slot and passes whatever
  is in it to `c:FSL.Host.spawn_child/2` without looking. Written and read
  exactly as before; it is simply defined one module further down.
  """
  defmacro uas(kind) when is_atom(kind) do
    type = :"uas_#{kind}"

    quote do
      @scenario_type unquote(type)
    end
  end
end
