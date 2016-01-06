defmodule SIP.Dialog.Listener
	@callback on_dialog_event(pid, any) :: any
	@callback on_request( pid, SIP.Packet.t )  :: any
	@callback on_response_provisional( pid, SIP.Packet.t )  :: any
	@callback on_response_success( pid, SIP.Packet.t ) :: any
	@callback on_response_redirect( pid, SIP.Packet.t ) :: any
	@callback on_response_failure( pid, SIP.Packet.t ) :: any
	@callback on_ack( pid, SIP.Packet.t ) :: any
end