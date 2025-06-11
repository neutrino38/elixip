defmodule SIP.Trans.Timer do
  require Logger
  @timer_T1_val 500
  @timer_T2_val 4000
  @timer_T4_val 5000

  defp notify_dialog_layer(state, timer, transact_module) do
    if !is_nil(state.app) do
      send(state.app, {:transaction_timeout, timer, self(), state.msg, transact_module })
    end
  end
  # Arm T1 timer
  @spec schedule_timer_A(any(), non_neg_integer()) :: any()
  def schedule_timer_A(state, ms \\ @timer_T1_val) do
    Process.send_after(self(), { :timerA, ms }, ms )
    state
  end

  @doc """
  Schedule timer B
  - timer B defines the overall INVITE client transaction timeout
  """
  @spec schedule_timer_B(map(), non_neg_integer() | atom()) :: map()
  def schedule_timer_B(state, ms \\ :default) do
    ms = if ms == :default do
      t1 = Application.get_env(:elixip2, :sip_timer_T1, @timer_T1_val)
      64 *t1
    else
      ms
    end
    schedule_generic_timer(state, :timerB, :tB_ref, ms)
  end
  def cancel_timer_B(state) do
    schedule_generic_timer(state, :timerB, :tB_ref, nil)
  end

  def schedule_timer_D(state, ms \\ 32) do
    schedule_generic_timer(state, :timerD, :tD_ref, ms)
  end

  def cancel_timer_D(state) do
    schedule_generic_timer(state, :timerD, :tD_ref, nil)
  end

  @doc """
  Schedule/reschedule the F timer and save its reference (pid) in the transaction state
  - timer F is the maixmum non INVITE transaction timeout. If it fires, the client should
  stop expecting a final answer.
  """
  def schedule_timer_F(state) do
    t1 = Application.get_env(:elixip2, :sip_timer_T1, @timer_T1_val)
    schedule_generic_timer(state, :timerF, :timerf, t1 * 64)
  end

  def cancel_timer_F(state) do
    schedule_generic_timer(state, :timerF, :timerf, nil)
  end

  @doc """
  Schedule/reschedule the H timer and save its reference (pid) in the transaction state
  Wait time for ACK receipt
  """
  def schedule_timer_H(state) do
    t1 = Application.get_env(:elixip2, :sip_timer_T1, @timer_T1_val)
    schedule_generic_timer(state, :timerH, :timerh, t1 * 64)
  end

  def cancel_timer_H(state) do
    schedule_generic_timer(state, :timerH, :timerh, nil)
  end


  @doc "Schedule/reschedule the K timer and save its reference (pid) in the transaction state"
   def schedule_timer_K(state, :default) do
    schedule_generic_timer(state, :timerK, :timerk, @timer_T4_val)
  end

  def schedule_timer_K(state, ms) do
    schedule_generic_timer(state, :timerK, :timerk, ms)
  end


  @doc """
  Schedule a generic cancellable timer

  state: transactipn internal state
  timer_id: atom to be sent as in timer
  timer_field: atom to designate the field used in the transaction state map
               to store the timer reference

  ms: number of milliseconds for the timer

  if ms is nil, cancel timer
  if ms is 0, fire timer immediatly
  if ms > 0, schedule timer
  """
  @spec schedule_generic_timer(state :: map() , timer_id :: atom() , timer_field :: atom(), ms :: integer() | nil ) :: map()
    def schedule_generic_timer(state, timer_id, timer_field, ms) when is_atom(timer_id) do
    # If needed cancel previous timer
    state = case Map.fetch(state, timer_field) do
      { :ok, nil } -> state
      { :ok, timer_ref } ->
        :erlang.cancel_timer(timer_ref)
        Map.put(state, timer_field, nil)
      :error -> Map.put(state, timer_field, nil)
    end

    case ms do
      nil -> state # Nothing to do as timer is already cancelled

      # Send message immediatly
      0 ->
        send(self(), timer_id)
        state

      # Schedule timer
      millis when millis > 0 ->
        # IO.puts("Scheduling timer #{timer_id} after #{ms} ms")
        tref = :erlang.start_timer(ms, self(), timer_id)
        Map.put(state, timer_field, tref)
    end
  end


  @doc "Handle timer messages"
  def handle_timer({ :timerA, ms }, state) when ms < @timer_T2_val and state.state == :sending do
    if not state.t_isreliable do
      # If transport is not reliable, retransmit
      code = GenServer.call(state.tpid, { :sendmsg, state.msgstr, state.destip, state.destport } )
      if code != :ok do
        Logger.error([ transid: state.msg.transid, message: "timer_A: Fail to retransmit message: #{code}"])
      end
    end
    schedule_timer_A(state, ms*2)
    { :noreply, state }
  end

  def handle_timer({ :timerA, ms }, state) when ms >= @timer_T2_val and state.state == :sending do
    Logger.error([ transid: state.msg.transid, message: "timer_A: max restransmition delay expired."])
    { :noreply, state }
  end

  def handle_timer({ :timerA, _ms }, state) when state.state != :sending do
    { :noreply, state }
  end


  def handle_timer( :timerK, state, module) when state.state in [ :confirmed, :terminated ] do
    # Timer K expired: destroy transaction
    Logger.debug([ transid: state.msg.transid, module: module,
                   message: "timer_K: SIP transaction terminated."])
    # Notify the ??
    { :stop, :normal, state }
  end

  def handle_timer( :timer_K, state, _module) do
    { :noreply, state }
  end

  def handle_timer( timer, state, module) when timer in [ :timerB, :timerD, :timerF, :timerH ] do
    notify_dialog_layer(state, timer, module)
    reason = case timer do
      :timerB ->
        Logger.info([ transid: state.msg.transid, message: "client INVITE not answered on time."])
        :normal

      :timerD ->
        # ICT retransmission grace period
        :normal

      :timerF ->
        Logger.info([ transid: state.msg.transid, module: module,
                    message: "#{state.msg.method} request not answered on time."])
        :normal

      :timerH ->
        Logger.info([ transid: state.msg.transid, message: "ACK not received on time."])
        :normal

    end
    { :stop, reason, state }
  end



  def handle_UAS_timerA({ :timerA, ms }, state) when ms < @timer_T2_val and state.state == :confirmed do
    # If transport is not reliable, retransmit
    code = GenServer.call(state.tpid, { :sendmsg, state.rspstr, state.destip, state.destport } )
    if code != :ok do
      Logger.warning([ transid: state.msg.transid, message: "timer_T1: Fail to retransmit message: #{code}"])
    else
      Logger.debug([ transid: state.msg.transid,  module: __MODULE__,
                     message: "Resending the final response because ACK was not received"])
    end
    schedule_timer_A(state, ms*2)
    { :noreply, state }
  end

  def handle_UAS_timerA({ :timerA, ms }, state) when ms >= @timer_T2_val and state.state == :confirmed do
    Logger.error([ transid: state.msg.transid, message: "timer_A: max restransmition delay expired."])
    { :noreply, state }
  end


  # Ignoring timer A in terminated state
  def handle_UAS_timerA({ :timerA, _ms }, state) when state.state == :terminated do
    { :noreply, state }
  end


end
