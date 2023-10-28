defmodule SIP.Test.Transport.UDPMockup do
  @moduledoc """
  Mockup for transport module
  """
  use GenServer
  require Logger

   # Callbacks

  @impl true
  def init(nil) do
    initial_state = %{ t_isreliable: false }
    { :ok, initial_state }
  end

  @impl true
  def handle_call({ :sendmsg, msgstr }, _from, state) do
    Logger.debug("Transport mockeup: Message sent ---->\r\n" <> msgstr <> "\r\n-----------------")
    { :reply, :ok, state}
  end

  def handle_call( :stop , _from, state) do
    { :stop, "Normal stop", state}
  end
end

IO.puts("Répertoire de travail : #{File.cwd!()}")

defmodule SIP.Test.Transact do
  use ExUnit.Case
  doctest SIP.Transac

  test "Arm a T1 timer and check that it fires" do
    # Start fake transport layer
    { :ok, t_pid } = GenServer.start_link(SIP.Test.Transport.UDPMockup, nil)
    { code, msg } = File.read("test/SIP-INVITE-BASIC-AUDIO.txt")
    assert code == :ok
    state = %{ state: :sending, t_isreliable: false, msgstr: msg,
               tmod: SIP.Test.Transport.UDPMockup, tpid: t_pid }
    state = SIP.Trans.Timer.schedule_timer_T1(state)
    state = receive do
      { :timerT1, ms } ->
        # Timer has fired - handle it and check that it refires
        assert ms == 500
        { :noreply, st } =  SIP.Trans.Timer.handle_timer({:timerT1, ms}, state)
        # Emulate a provisional response
        %{ st | state: :proceeding }
      _ ->
        IO.puts("incorrect message received")
        assert false
    after
      1_000 ->
        IO.puts("No message received")
        assert false
    end

    assert state.state == :proceeding

    receive do
      { :timerT1, ms } ->
        # Timer has fired - handle it and check that it refires
        assert ms == 1000
        { :noreply, _st } =  SIP.Trans.Timer.handle_timer({:timerT1, ms}, state)
        _ ->
          IO.puts("incorrect message received")
          assert false
      after
        1_500 ->
          IO.puts("No message received")
          assert false
      end

      receive do
          _ ->
            IO.puts("incorrect message received")
            assert false
      after
          2_500 ->
            GenServer.call(state.tpid, :stop)
            assert true
      end

      receive do
        {:stop, _reference, :process, pid_to_monitor, reason} ->
          IO.puts("Le processus s'est terminé avec la raison : #{inspect(reason)}")
      end
  end
end
