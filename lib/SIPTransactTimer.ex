defmodule SIP.Trans.Timer do
  require Logger
  @timer_T1_val 500
  @timer_T2_val 4000

  # Arm T1 timer
  def schedule_timer_A(state, ms \\ @timer_T1_val) do
    Process.send_after(self(), { :timerA, ms }, ms )
    state
  end

  @spec schedule_timer_B(map(), non_neg_integer()) :: map()
  def schedule_timer_B(state, ms \\ 64 * @timer_T1_val) do
    schedule_generic_timer(state, :timerB, :tB_ref, ms)
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

  @doc "Schedule/reschedule the K timer and save its reference (pid) in the transaction state"
  def schedule_timer_K(state, ms) do
    schedule_generic_timer(state, :timerK, :timerk, ms)
  end

  @doc "Schedule/reschedule the F timer and save its reference (pid) in the transaction state"
  def schedule_timer_F(state) do
    schedule_generic_timer(state, :timerF, :timerf, @timer_T1_val * 64)
  end

  @doc "Handle timer messages"
  def handle_timer({ :timerA, ms }, state) when ms < @timer_T2_val and state.state == :sending do
    if not state.t_isreliable do
      # If transport is not reliable, retransmit
      code = GenServer.call(state.tpid, { :sendmsg, state.msgstr, state.destip, state.destport } )
      if code != :ok do
        Logger.error([ transid: state.sipmsg.transid, message: "timer_T1: Fail to retransmit message: #{code}"])
      end
    end
    schedule_timer_A(state, ms*2)
    { :noreply, state }
  end

  def handle_timer({ :timerA, ms }, state) when ms >= @timer_T2_val and state.state == :sending do
    Logger.error([ transid: state.sipmsg.transid, message: "timer_A: max restransmition delay expired."])
    send(state.sipmsg.app, {:timeout, :timerA})
    { :stop, state, "timer_A: max restransmition delay expired." }
  end

  def handle_timer({ :timerA, _ms }, state) when state.state != :sending do
    { :noreply, state }
  end

  def handle_timer( :timerB, state) when state.state == :proceeding do
    send(state.app, {:timeout, :timerB})
    if state.sipmsg.method == :INVITE do
      Logger.info([ transid: state.sipmsg.transid, message: "INVITE not answered on time."])
    else
      Logger.error([ transid: state.sipmsg.transid, message: "timer_B: should not be used in NICT."])
    end
    { :stop, state, "timer_B: no final response receveived on time." }
  end

  def handle_timer( :timerK, state) when state.state in [ :confirmed, :terminated ] do
    # Timer K expired: destroy transaction
    Logger.debug([ transid: state.sipmsg.transid, message: "timer_K: SIP transaction terminated."])
    { :stop, state, "SIP transactipn timeout (timer K)" }
  end

  def handle_timer( :timer_K, state) do
    { :noreply, state }
  end
end
