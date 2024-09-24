defmodule SIP.NIST do
  @moduledoc "SIP non-INVITE client transaction"
  use GenServer
  import SIP.Trans.Timer
  require SIP.Msg.Ops
  require Logger

  # reply to request internally
  defp internal_reply(state, sipmsg, resp_code, reason, upd_fields, totag) do
    resp = SIP.Msg.Ops.reply_to_request(sipmsg, resp_code, reason, upd_fields, totag)
    case fsm_reply(state, resp_code, resp) do
      { :ok, new_state } when resp_code in 200..599 -> { :ok, schedule_timer_K(new_state, 5000) }
      { :ok, new_state } when resp_code in 100..199 -> { :ok, new_state }
      { code, state }  -> { code, schedule_timer_K(state, 5000) }
    end
  end

  # Call upper layer request handling function and
  defp process_incoming_request(state, ul_fun) when is_function(ul_fun) do
    case ul_fun.(state.sipmsg, self(), state.debug) do
      # upper layer has started processing the request. Save the PID and the totag
      { :ok, ul_pid, { _ftag, _cid, totag } } -> { :ok, Map.put(state, :app, ul_pid) |> Map.put(:totag, totag) }

      # upper layer could not process the request and indicated a response code
      # close the transaction with this response code
      { :error, { code, reason, { _ftag, _cid, totag } }} ->
        { _errcode, state } = internal_reply(state, state.sipmsg, code, reason, [], totag)
        { :upperlayerfailure, state }


      # General error
      _ ->
        { _errcode, state } =  internal_reply(state, state.sipmsg, 403, "Denied", [], nil)
        { :upperlayerfailure, state }
    end
  end

  # When upperlayer is a callback that returns the upperlayer PID
  defp process_incoming_request(state) when is_function(state.upperlayer) do
    process_incoming_request(state, state.upperlayer)
  end

  # when upperlayer is a PID -> send the message
  defp process_incoming_request(state) when is_pid(state.upperlayer) do
    send(state.upperlayer, { state.sipmsg.method, state.sipmsg } )
    { :ok, Map.put(state, :app, state.upperlayer) }
  end

  # when upperlayer is not specified -> send to the dialog layer
  defp process_incoming_request(state) when is_nil(state.upperlayer) do
    process_incoming_request(state, &SIP.Dialog.process_incoming_request/3)
  end

  # Callbacks

  @impl true
  def init({ t_mod, t_pid, remote_ip, remote_port, sipmsg, upperlayer }) do
    initial_state = %SIP.Transac{ msg: sipmsg, tmod: t_mod, tpid: t_pid, app: nil, timeout: 0,
                      t_isreliable: apply(t_mod, :is_reliable, []), destip: remote_ip,
                      destport: remote_port, state: :trying, upperlayer: upperlayer }

    # state = if not initial_state.t_isreliable, do: schedule_timer_A(initial_state), else: initial_state

    # Asynchornously process the request
    GenServer.cast(self(), :sipreq)
    { :ok, initial_state }
  end

  @impl true
  # This is invoked at NIST transaction creation to forward the request to upperlayer
  # asynchronously
  def handle_cast(:sipreq, state) do
    case process_incoming_request(state) do
      # Schedule timer F (max NIST transaction)
      { :ok, state } -> { :noreply, SIP.Trans.Timer.schedule_timer_F(state) }

      # In case of failure, timerK is scheduled by internal_reply()
      { :upperlayerfailure, state } -> { :noreply, state }
    end
  end

  @impl true
  # Timer K - kill the transaction
  def handle_info({ :timeout, _tref, :timerK } , state)  do
    case handle_timer(:timerK, state) do
      { :noreply, newstate } -> { :noreply, newstate }
      { :stop, _reason, state} ->
        GenServer.stop(self())
        # Notify the tranport that this transaction is terminated
        { :noreply, state }
    end
  end

  # Timer F - timeout
  def handle_info({ :timeout, _tref, :timerF } , state)  do
    case internal_reply(state, state.sipmsg, 408, "Timeout", [], state.totag) do
      { :ok, new_state } -> { :noreply, new_state }
      { _err, new_state } -> { :noreply, new_state }
    end
  end

  #Implementation of reply transaction interface
  @impl true
  def handle_call({ resp_code, reason, upd_fields, totag }, state) when is_integer(resp_code) do
    { code, new_state } = internal_reply(state, state.sipmsg, resp_code, reason, upd_fields, totag);
    { :reply, code, new_state }
  end

  # Transaction state machine function
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
            # Final answer
            # Cancel timer F, arm timer K
            # set transaction state to terminated
            new_state = schedule_timer_K(new_state, 5000)
                        |> schedule_generic_timer(:timerF, :timerf, nil)
                        |> Map.put(:state, :terminated)
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

  defp fsm_reply(state, _resp_code, rsp) when state.state == :terminated do
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
