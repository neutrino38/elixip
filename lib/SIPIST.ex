defmodule SIP.IST do
  @moduledoc "SIP INVITE server transaction"
  use GenServer
  import SIP.Trans.Timer
  import SIP.Transac.Common
  require Logger

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
    case process_UAS_request(state) do
      # Schedule timer F (max NIST transaction)
      { :ok, state } -> { :noreply, SIP.Trans.Timer.schedule_timer_F(state) }

      # In case of failure, timerK is scheduled by internal_reply()
      { :upperlayerfailure, state } -> { :noreply, state }
    end
  end

  @impl true
  # Timer K - kill the transaction
  def handle_info({ :timeout, _tref, :timerK } , state)  do
    handle_timer(:timerK, state)
  end

  # Timer F - timeout
  def handle_info({ :timeout, _tref, :timerF } , state)  do
    case reply_to_UAC(state, state.sipmsg, 408, "Timeout", [], state.totag) do
      { :ok, new_state } -> { :noreply, new_state }
      { _err, new_state } -> { :noreply, new_state }
    end
  end

  #Implementation of reply transaction interface
  @impl true
  def handle_call({ resp_code, reason, upd_fields, totag }, _from, state) when is_integer(resp_code) do
    { code, new_state } = reply_to_UAC(state, state.msg, resp_code, reason, upd_fields, totag);
    { :reply, code, new_state }
  end

  @impl true
  def handle_call(:ack, _from, state) do
    if state.state in [:confirmed, :rejected] do
      send_ack(state)
    else
      Logger.debug([ transid: state.msg.transid,  module: __MODULE__,
                     message: "Cannot ACK an ICT in state #{state.state}"])
      { :reply, :badstate, state }
    end

  end
end
