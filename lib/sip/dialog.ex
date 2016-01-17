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
	Create a dialog from an incoming SIP request. Use this method when an application
	receives an incoming SIP packet from network and manage this request within a dialog
	
	Returns the process ID of the dialog
	"""
	def create_incoming_d( packet, app_pid, transport_pid, options )
		d_data = init_d_data( app_id, packet, option )
		Process.spawn( fn -> invite_dialog_init( d_data ) end )
	end
	
	@doc """
	Create a dialog from an outging (UAC) SIP transaction. Use this to create
	
	- an outgoing call
	"""
	def create_outgoing_call( ruri, from, to, body, app_pid, options ) do
	end
	
	def create_outgoing_registration( ruri, from, to, app_pid, options ) do
	end

	def create_outgoing_presence( method, ruri, from, to, app_pid, options ) do
	end
	
	def send_ood_message( method, ruri, from, to, app_pid, options ) do
	end
	
	@doc """
	Reply to an incoming request. Use this function to reply to any incoming request 
	
	dialog_id: 	pid of dialog process
	req_id:    	pid of request transaction
	error_code: SIP error code of the responses
	reason:		SIP reason. nil to use default reason
	headers:	SIP headers to inject. Make sure that you know what you are doing here ...
	
	"""
	def reply_d( dialog_id, req_id, error_code, reason, headers ) when error_code in 100..699 do
	end
	
	def reply_d( dialog_id, req_id, 200, reason, headers, body ) when error_code in 100..699 do
	end

	@doc """
	Challenge the request
	Send 401 Proxy Authentication required
	Send 407 Authentication required
	"""
	def challenge_d( dialog_id, req_id, code, headers ) when code == 401 or when code == 407 do
	end
	
	@doc """
	Forward a request coming from another dialog. All the responses
	will be automatically forwarded back. Useful to build a B2BUA or
	an SBC
	"""
	def fwd_request( dialog_id, req, other_dialog ) do
	end
	
	def fwd_response( dialog_id, req_id, resp, req_cseq )
	end
	
	@doc """
	Use this function to send in-dialog UPDATE, INFO, MESSAGE
	"""
	def send_request(dialog_id, method, body ) do
	end
	
	@doc """
	Use this function to send in-dialog NOTIFY, PUBLISH, NOTIFY
	"""
	def send_presence_message(dialog_id, method, body ) do
	end
	
	@doc """
	Stop running dialog.
	- INVITE dialog -> send BYE
	- UAC REGISTER dialog send REGISTER with Expiration; 0
	- UAC PUBLISH dialog send unPUBLISH
	"""
	def terminate_d( dialog_id )
	end
	
	# ------------- Utility functions -------------------------------
	
	defp init_d_data( app_id ) do
		%{ :cseq_in => 0, :cseq_out => 1, :initial_req => nil,
		   :trans_in => [], :trans_out => [], 
		   :app_id => app_id, :peer_ip => nil, :peer_port => nil }
	end
	
	defp init_d_data( app_id, initial_req, option ) do
		%{ init_d_data( app_id ) | :initial_req => initial_req,
		   :peer_ip => initial_req.src_ip, :peer_port => initial_req.src_port }
	end
	
	defp add_incoming_trans( d_data, t_id, packet ) do
	
		newcseq = packet.getCSeqNum()
		if d_data[:dialog_id] = nil do
			d_data = %{ d_data | :dialog_id => packet.getDialogId() }
		else
			if packet.getDialogId() != d_data[:dialog_id] do
				raise "SIP packet is not associated with this dialog"
			end
		end
				
		# Here we check if we can accept the new incoming transaction.
		# We accept 
		cond do
			packet.is_request == false -> 
				raise "SIP Response cannot start a transaction"
						
			# We accept only transaction with CSeq higher than the last CSeq
			newcseq <= d_data[:cseq_in] ->
				SIP.Transaction.reply_t(t_id, 500, "Invalid CSeq"),
				raise "CSeq is already expired"
		
			true -> %{ d_data | :trans_in => [ d_data[:trans_in] | t_id ], 
					   :cseq_in => newcseq )
		end
	end
	
	defp del_incoming_trans( d_data, t_id )
		d_data
	end
	
	internal_challenge_d(req_id, code, reason)
	
	defp internal_reply_d(d_data, t_id, code, reason) do
		if req_id in d_data[:trans_in] do: SIP.Transaction.reply_t(t_id, code, reason)
	end
	# ---------------- INVITE DIALOG FSM ---------------------------

	defp invite_dialog_init_uas( d_data, transport_pid )
		next_state = :init_state
	
		if d_data.packet != nil do
			# Icomong packet used to create dialog -> create UAS transaction
			t_pid = SIP.Transaction.start_incoming_t( d_data[:initial_req], sess_id, transport_pid, self() )
			d_data = add_incoming_trans( d_data, t_pid )
		else
			
		end
		
		# Register the dialog in the transport layer and in the app
		Process.send( transport_pid, { :dialog_add, d_data[:dialog_id], self() } )
		
		# Notify the application about dialog creation
		Process.send( d_data[:app_id], { :dialog_add, d_data[:dialog_id], self() } )
		
		receive do
			{ :trying,   req_id, code, reason } when code in 100..199 -> 
				internal_reply_d(req_id, code, reason),
				next_state = :init_state
	
			{ :ringing, req_id } ->
				internal_reply_d(req_id, code, reason),
				next_state = :early_state

			# App requires authentication
			{ :auth, req_id, } ->
				internal_challenge_d(req_id, code, reason),
				next_state = :auth_uas_state

			{ :reply, req_id, code, reason } when code in 200..699 ->
				SIP.Transaction.reply_t(req_id, code, reason),
				next_state = :terminating_state
			
			# App send a reply code
			{ :reply, req_id, code, reason, body } when code in 200..299 ->
				SIP.Transaction.reply_t(req_id, code, reason, body),
				next_state = :terminating_state
			
			# Intial transaction is cancelled
			{ :transaction_cancel, t_id, reason } -> 
				Process.send( data_d[:app_id], { :dialog_cancel, t_id } ),
				next_state = :cancelling_state
				
			{ :transaction_close, self(), :confirmed } ->
		end
		
		if next_state != :init_state do
			invite_dialog_state( next_state, d_data, :init_state )
		else
			invite_dialog_init_uas( d_data, transport_pid )
		end
	end
	
	defp invite_dialog_state( :auth_uas_state, d_data, prev_st )
	end
	
	defp invite_dialog_state( :cancelling_state, d_data, prev_st )
	end
	
	defp invite_dialog_state( :early_state, d_data, prev_st )
	end
	
	
	defp invite_dialog_state( :confirmed_state, d_data, prev_st )
	end
	
	defp invite_dialog_state( :terminating_state, d_data, prev_st )
	end

	defp invite_dialog_state( :terminated_state, d_data, prev_st )
	end
	
	defp other_dialog_init( d_data )
	end
	
	defp other_dialog_state( :early_state, d_data, prev_st )
	end

	defp other_dialog_state_cancelling( :cancelling_state, d_data, prev_st )
	end

	
	defp other_dialog_state_confirmed( :confirmed_state, d_data, prev_st )
	end
	
