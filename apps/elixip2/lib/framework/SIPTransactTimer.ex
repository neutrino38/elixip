defmodule SIP.Trans.Timer do
  require Logger
  @timer_T1_val 500
  @timer_T2_val 4000
  @timer_T4_val 5000
  @trying_delay_val 200

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

  # Timer D — RFC 3261 §17.1.1.2: at least 32 s for unreliable transport. It
  # bounds the time the application layer has to ACK a 2xx INVITE response
  # before the client transaction is destroyed (value in milliseconds).
  def schedule_timer_D(state, ms \\ 32_000) do
    schedule_generic_timer(state, :timerD, :tD_ref, ms)
  end

  def cancel_timer_D(state) do
    schedule_generic_timer(state, :timerD, :tD_ref, nil)
  end

  @doc """
  Schedule the automatic 100 Trying of an INVITE server transaction.

  Not one of RFC 3261's lettered timers: §17.2.1 only states the delay — the
  server transaction "MUST generate a 100 (Trying) response unless it knows that
  the TU will generate a provisional or final response within 200 ms". So this
  arms the 200 ms, and the IST answers 100 only if the TU has still said nothing
  when it fires.
  """
  def schedule_timer_100(state, ms \\ @trying_delay_val) do
    schedule_generic_timer(state, :timer100, :timer100_ref, ms)
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

  # Arm timer K for an INVITE client transaction that has just ACKed a 2xx.
  #
  # 64*T1, and on a reliable transport too. RFC 3261 §17.1.1.2 destroys the client
  # transaction there (timer D = 0s), but §13.2.2.4 then makes the UAC *core* owe
  # an ACK for every 2xx it receives during 64*T1 — and in this stack the
  # serialized ACK, and the code that resends it, live in the transaction. Killing
  # it on the ACK left the retransmitted 200 of a callee that had not seen that
  # ACK matching nothing at all ("response not linked to any transaction"), so the
  # callee went on retransmitting into the void and tore down a call that was up.
  def schedule_timer_K(state, :after_ack) do
    t1 = Application.get_env(:elixip2, :sip_timer_T1, @timer_T1_val)
    schedule_generic_timer(state, :timerK, :timerk, 64 * t1)
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

      # Send message immediatly. Deliver the same shape as the ms>0 branch
      # (:erlang.start_timer/3 sends {:timeout, ref, msg}) so the transaction
      # FSMs' `handle_info({:timeout, _tref, timer})` clauses match. A bare atom
      # would crash handle_info — e.g. an ICT arming timer K with ms=0 on a
      # reliable transport (407/ACK over WSS).
      0 ->
        send(self(), {:timeout, make_ref(), timer_id})
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
      # Through SIP.Transport, which answers :transporterror instead of exiting on
      # a dead transport. This is the retransmit path, so it runs long after the
      # pid was cached — and an exit here killed the transaction, which killed its
      # dialog by the link, without running terminate/2 (design §14.4, R3).
      code = SIP.Transport.send_msg(state.tpid, state.msgstr, state.destip, state.destport)
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


  def handle_timer( :timerK, state, module) when state.state in [ :confirmed, :terminated, :rejected ] do
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
    reason = case timer do
      :timerB ->
        Logger.info([ transid: state.msg.transid, message: "client INVITE not answered on time. Timer B expired."])
        :normal

      :timerD ->
        # ICT retransmission grace period
        :normal

      :timerF ->
        Logger.info([ transid: state.msg.transid, module: module,
                      message: "#{state.msg.method} request not answered on time. Timer F expired."])
        :normal

      :timerH ->
        Logger.info([ transid: state.msg.transid, message: "ACK not received on time. Timer H expired."])
        :normal
    end
    notify_dialog_layer(state, timer, module)
    { :stop, reason, state }
  end



  def handle_UAS_timerA({ :timerA, ms }, state) when ms < @timer_T2_val and state.state == :confirmed do
    # If transport is not reliable, retransmit
    code = SIP.Transport.send_msg(state.tpid, state.rspstr, state.destip, state.destport)
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
