defmodule SIP.Dialog do
	@moduledoc """
	SIP dialog layer. Each transaction is a process (and a state machine). It communcate
	with the follwoing processes:
		- all the transport layers for UAS requests:
			when the dialog is created and registered, incoming requests matching the dialog are
			forwarded to the dialog process which is responsible to create a transaction in the
			transaction layer
		
		- all the transaction processes managed by this dialog: all relevant events are forwarded
		  to the dialog but transaction layer will filter out retransmission
		
		- one application process 
		
		- in case of INVITE dialog, dialog is closed if first transaction fails or upon receiving a BYE
		  message. By default, there will be a dialog life time that can be set as parameter. Dialog
		  is extended upon session refresh
		  
		- REGISTER dialogs expire after last registration expire and is automatically refreshed by
		  REGISTATION update
		  
		- same for PUBLISH or SUBSCRIBE dialog
		
		- MESSAGE and INFO create dialog that only last during the transaction
	"""

	@doc """
	Create a dialog from an incoming SIP packet
	"""
	def create_d( packet, app_pid, options )
	end
	
	@doc """
	Forward a request coming from another dialog. All the responses
	will be automatically forwarded back. Useful to build a B2BUA or
	an SBC
	"""
	def forward_request_d( dialog_id, req, other_dialog )
	end
	
	def forward_response_d( dialog_id, resp, req_cseq )
	end
	
	