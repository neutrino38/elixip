defmodule Kelix.Mcu.TestStub do
  @moduledoc """
  A recording MCU transport for the module tests.

  `transport/2` returns the `(method, params)` function a `Kelix.Mod.Mcu.Client`
  accepts in place of its HTTP layer, so the whole module can be driven — and its
  **exact RPC order** asserted (design §13) — with no media server in sight.

  Every call is echoed to the test process as `{:rpc, method, params}`, so a test
  reads the sequence off its own mailbox in order.
  """

  @default_returns %{
    "EventQueueCreate" => {:ok, [7]},
    "EventQueueDelete" => {:ok, []},
    "CreateConference" => {:ok, [42]},
    "SetCompositionType" => {:ok, []},
    "UpdateConference" => {:ok, []},
    "DeleteConference" => {:ok, []},
    # `returnVal` IS the row list (`xmlok()` in the server's xmlhandler.cpp), so a
    # server holding no conference answers an empty one
    "GetConferences" => {:ok, []},
    "CreateParticipant" => {:ok, [7]},
    "DeleteParticipant" => {:ok, []},
    # `[recPort, announcedIp]`: the address to put in the SDP answer is the server's
    # own, reported with the port it goes with (§16.5). A server returning the port
    # alone is a server too old for this module — see the `:no_media_ip` test.
    "StartReceiving" => {:ok, [52_014, "203.0.113.12"]},
    "StopReceiving" => {:ok, []},
    "StartSending" => {:ok, []},
    "StopSending" => {:ok, []},
    "SetAudioCodec" => {:ok, []},
    "SetVideoCodec" => {:ok, []},
    "SetTextCodec" => {:ok, []},
    "SetRTPProperties" => {:ok, []},
    "SetLocalCryptoSDES" => {:ok, []},
    "SetRemoteCryptoSDES" => {:ok, []},
    "SetLocalSTUNCredentials" => {:ok, []},
    "SetRemoteSTUNCredentials" => {:ok, []},
    "SetRemoteCryptoDTLS" => {:ok, []},
    # server-wide and cacheable (§2 point 3): the only secret the controller does
    # not generate itself
    "GetLocalCryptoDTLSFingerprint" =>
      {:ok,
       [
         "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
       ]},
    "AddSidebarParticipant" => {:ok, []},
    "AddMosaicParticipant" => {:ok, []},
    "SendFPU" => {:ok, []},
    "SetMute" => {:ok, []},
    "SetParticipantDisplayName" => {:ok, [1]},
    # one `(s i i i i i i i)` row per media, `isReceiving` before `isSending`
    "GetParticipantStatistics" => {:ok, [["audio", 1, 1, 0, 100, 90, 16_000, 14_400]]}
  }

  @doc """
  A transport reporting to `test_pid`.

  `overrides` maps a method name to what it must answer — a plain result, or a
  `(params -> result)` function when the answer depends on the arguments. An
  unlisted method answers `{:ok, []}`, which is what a void RPC returns.
  """
  @spec transport(pid, map) :: (String.t(), [term] -> {:ok, [term]} | {:error, term})
  def transport(test_pid, overrides \\ %{}) do
    # a lambda cannot live in a module attribute, hence the runtime merge:
    # S5's WS text door echoes the token back inside the full URL, exactly like
    # the real server (scheme decided server-side; override with a wss://
    # variant to rehearse TLS)
    defaults =
      Map.put(
        @default_returns,
        "ConfigureParticipantMediaConnection",
        fn [conf_id, _part_id, _media, _proto, token] ->
          {:ok, ["ws://203.0.113.12:9090/mcu/#{conf_id}/#{token}"]}
        end
      )

    returns = Map.merge(defaults, overrides)

    fn method, params ->
      send(test_pid, {:rpc, method, params})

      case Map.get(returns, method, {:ok, []}) do
        fun when is_function(fun, 1) -> fun.(params)
        result -> result
      end
    end
  end

  @doc "The methods the transport was called with, in order (drains the mailbox)."
  @spec rpc_order() :: [String.t()]
  def rpc_order(timeout \\ 50) do
    receive do
      {:rpc, method, _params} -> [method | rpc_order(timeout)]
    after
      timeout -> []
    end
  end

  @doc """
  The calls **with their arguments**, in order (drains the mailbox).

  For the assertions where the parameters are the point — a resolved recording path, a
  slot's wire value — and where `assert_received` cannot be used because the call
  happened during a setup that already drained.
  """
  @spec rpc_calls() :: [{String.t(), [term]}]
  def rpc_calls(timeout \\ 50) do
    receive do
      {:rpc, method, params} -> [{method, params} | rpc_calls(timeout)]
    after
      timeout -> []
    end
  end
end
