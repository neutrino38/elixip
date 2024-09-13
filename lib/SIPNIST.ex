defmodule SIP.NIST do
  @moduledoc "SIP non-INVITE client transaction"
  use GenServer
  import SIP.Trans.Timer
  require SIP.Msg.Ops
  require Logger

  # Callbacks

  @impl true
  def init({ t_mod, t_pid, remote_ip, remote_port, sipmsg, upperlayer }) do
    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: nil, timeout: 0,
                      t_isreliable: apply(t_mod, :is_reliable, []), destip: remote_ip,
                      destport: remote_port, state: :trying, upperlayer: upperlayer }

    # state = if not initial_state.t_isreliable, do: schedule_timer_A(initial_state), else: initial_state

    { :ok, initial_state }
  end

  defp fsm_reply(state, resp_code, rsp) when state.state in [ :trying, :proceeding ] do

    case SIP.Transac.Common.sendout_msg(state, rsp) do
      {:ok, new_state} ->
        Logger.info([ transid: rsp.transid, module: __MODULE__,
                    message: "Sent response #{resp_code} to #{state.msg.method}"])

        case resp_code do
          # Transition to proceeding
          rc when rc in 100..199 ->
            { :ok, Map.put(new_state, :state, :proceeding) }

            rc when rc in 200..699 ->
            new_state = schedule_timer_K(new_state, 5000) |> Map.put(:state, :complete)
            { :ok, new_state }
        end

      { :invalid_sip_msg, _state } ->
        Logger.error([ transid: rsp.transid, module: __MODULE__,
                        message: "Fail to serialize SIP message."])
        { :invalid_sip_msg, state }

      { code, _state } ->
          Logger.error([ transid: rsp.transid, module: __MODULE__,
          message: "Transport error. Fail to send SIP response #{resp_code}. Err #{code}"])
          { code, state }
    end

  end

  defp fsm_reply(state, _resp_code, rsp) when state.state == :complete do
    Logger.info([ transid: rsp.transid, module: __MODULE__,
                  message: "Final response to #{state.msg.method} already sent"])
    { :ignore, state }
  end


  @impl true
  def handle_call( { resp_code, reason, upd_fields, totag }, _from, state ) when is_integer(resp_code) do
    try do
      rsp = SIP.Msg.Ops.reply_to_request(state.msg, resp_code, reason, upd_fields, totag)
      { code, newstate } = fsm_reply(state, resp_code, rsp)
      { :reply, code, newstate }

    rescue
      e in RuntimerError ->
        Logger.error([ transid: state.msg.transid, module: __MODULE__,
                        message: "Failed to build #{resp_code} response"])
        Logger.error([ transid: state.msg.transid, module: __MODULE__,
                        message: e.message])
        { :reply, :missingparams, state }
    end

  end

 @impl true
 def handle_call(:ack, _from, state) do
  Logger.warning([ transid: state.msg.transid, module: __MODULE__,
                   message: "Sending ACK is not supported for a server transaction"])
  { :reply, :unsupported, state }
 end
end
