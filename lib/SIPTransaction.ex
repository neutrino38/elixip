defmodule SIPTransaction do
@moduledoc "SIP Transaction Layer"

@doc "Start the transaction layer"
def start() do
  #Create the registry
  case Registry.start_link(keys: :unique, name: Registry.SIPTransaction)
    { :ok, pid } ->
      Logger.info("SIP transaction layer started with PID #{pid}")
      :ok

    { code, _pid } ->
      Logger.error ("SIP transaction layer failed to start with error #{code}")
      code
  end
end

@doc """
Start an INVITE client transaction (ICT)
- first arg is the SIP message to send
- second arg is a function that will loopkup a transport process
"""
def start_uac_transaction(sipmsg, transport_fn) when is_map(sipmsg) and sipmsg.method == :INVITE do
