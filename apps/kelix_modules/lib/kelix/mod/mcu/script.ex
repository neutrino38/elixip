defmodule Kelix.Mod.Mcu.Script do
  @moduledoc """
  MCU helpers mixin for the MCU scenario scripts (`mcu.exs`, `mcu_adhoc.exs`
  and their copies).

  This module provides the `admit`, `attach` and `leave` DSL macros (through
  `__using__/1`), following the `SIP.Session.Media` scheme: the expansion
  rebinds the scenario's `sip_ctx` variable in place, so the state code reads
  like the other DSL verbs — no visible `sip_ctx =` — and only tests
  `sip_ctx.lasterr` afterwards.
  """

  # NOTE: like SIP.Session.Media, this mixin must be combined with a session
  # module (e.g. SIP.Session.CallUAS) that brings in `use SIP.Context` — the
  # macro relies on `var!(sip_ctx)`.
  defmacro __using__(_opts) do
    quote do
      # Admit the INVITE `req` into the conference its R-URI designates, on the
      # domain of the current context. The SIP response policy stays with the
      # script (§11.1: the module decides, the SCRIPT composes the reply): the
      # expansion delegates to the script's own `do_admit/4` —
      # `do_admit(sip_ctx, req, dialog_pid, domain)` — which wraps the
      # context-aware `Kelix.Mod.Mcu.admit/4`, sends the error replies and
      # returns the updated context. The verdict lands in `sip_ctx.lasterr`
      # (see `Kelix.Mod.Mcu.admit/4`), on which a pending `goto` also aborts by
      # itself.
      #
      # An admitted leg comes back WIRED — `:username`, `:media_conn_opts` and
      # `:mediaserver_instance` are set — so a script calls `media_connect()`
      # next and states none of it. `Kelix.Mod.Mcu.admit/4` says why each one
      # follows from what a conference leg is.
      defmacro admit(req, dialog_pid) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "mcu_admit")

          var!(sip_ctx) =
            do_admit(var!(sip_ctx), unquote(req), unquote(dialog_pid), var!(sip_ctx).domain)
        end
      end

      # ACK time: put the admitted leg in the mix. Delegates to the script's own
      # `do_attach/1` — `do_attach(sip_ctx)` — which wraps the context-aware
      # `Kelix.Mod.Mcu.attach/1` and decides which verdicts the call survives
      # (the reference scripts keep it on a transient failure, and let the
      # JSR309 refusal abort through the `goto` that follows).
      defmacro attach() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "mcu_attach")
          var!(sip_ctx) = do_attach(var!(sip_ctx))
        end
      end

      # Declare that this script handles `{:mcu_message, envelope}` (§20.5 G-2), so
      # its leg may be addressed by its peers. Nothing is delivered to a leg that
      # did not say it: an `on_events` block is a plain `receive`, and a message no
      # clause matches would sit in the mailbox for the whole call. Call it once,
      # where the leg is admitted — and then handle `{:mcu_message, _}` in every
      # `on_events` the call goes through.
      defmacro mcu_accept_messages() do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "mcu_accept_messages")
          var!(sip_ctx) = Kelix.Mod.Mcu.accept_messages(var!(sip_ctx))
        end
      end

      # Send a collaboration message to the other participants' scripts (§20):
      # `mcu_send(:others, "hand.raised", "")`, `mcu_send({:part_id, 7}, …)`,
      # `mcu_send(:all, …)`.
      #
      # Unlike `admit`/`attach`/`leave`, the outcome does **not** land in `lasterr`:
      # a `goto` aborts on any `lasterr` other than `:ok`, and a message refused
      # because the sender is over its rate must never end a call. It goes to
      # `appdata_get(:mcu_last_send)` — `{:ok, %{delivered: n, skipped: […]}}` or
      # `{:error, reason}` — for the scripts that care to look.
      defmacro mcu_send(target, kind, payload, opts \\ []) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "mcu_send")

          var!(sip_ctx) =
            Kelix.Mod.Mcu.send_message(
              var!(sip_ctx),
              unquote(target),
              unquote(kind),
              unquote(payload),
              unquote(opts)
            )
        end
      end

      # Teardown: remove the participant and release the slot, idempotently.
      # Delegates to the script's own `do_leave/2` — `do_leave(sip_ctx, reason)`
      # — which wraps the context-aware `Kelix.Mod.Mcu.leave/2`.
      defmacro leave(reason) do
        quote do
          SIP.Scenario.Monitor.note_command(:media, "mcu_leave")
          var!(sip_ctx) = do_leave(var!(sip_ctx), unquote(reason))
        end
      end
    end
  end
end
