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
