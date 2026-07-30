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
    "GetConferences" => {:ok, [[]]},
    "CreateParticipant" => {:ok, [7]},
    "DeleteParticipant" => {:ok, []},
    "StartReceiving" => {:ok, [52_014]},
    "StopReceiving" => {:ok, []},
    "StartSending" => {:ok, []},
    "StopSending" => {:ok, []},
    "SetAudioCodec" => {:ok, []},
    "SetVideoCodec" => {:ok, []},
    "SetTextCodec" => {:ok, []},
    "SetRTPProperties" => {:ok, []},
    "AddSidebarParticipant" => {:ok, []},
    "AddMosaicParticipant" => {:ok, []},
    "SendFPU" => {:ok, []},
    "SetMute" => {:ok, []},
    "GetParticipantStatistics" => {:ok, [%{}]}
  }

  @doc """
  A transport reporting to `test_pid`.

  `overrides` maps a method name to what it must answer — a plain result, or a
  `(params -> result)` function when the answer depends on the arguments. An
  unlisted method answers `{:ok, []}`, which is what a void RPC returns.
  """
  @spec transport(pid, map) :: (String.t(), [term] -> {:ok, [term]} | {:error, term})
  def transport(test_pid, overrides \\ %{}) do
    returns = Map.merge(@default_returns, overrides)

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
end
