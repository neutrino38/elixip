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
		if packet.method == :INVITE do	
			Process.spawn( fn -> invite_dialog_init( :uas, d_data, transport_pid ) end )
		else
			Process.spawn( fn -> other_dialog_init( :uas, d_data, transport_pid ) end )
		end
	end
	
	@doc """
	Create a dialog from an outging (UAC) SIP transaction. Use this to create
	
	- an outgoing call
	"""
	def create_outgoing_call( ruri, from, to, body, app_pid, options ) do
		# to do extract UA from options
		ua = option
		packet = SIP.Packet.create( :INVITE, 1, ruri, from, to, nil, ua, body )
		init_d_data( app_id, packet, option )
		
		Process.spawn( fn -> invite_dialog_init( :uac, d_data, nil ) end )
	end
	
	@doc """
	Register as an UAC
	"""
	def create_outgoing_registration( ruri, from, to, app_pid, options ) do
		d_data = init_d_data( app_id, packet, option )
		Process.spawn( fn -> other_dialog_init( :uac, :REGISTER, d_data ) end )
	end

	@doc """
	Register as an UAC
	"""
	def create_outgoing_presence( method, ruri, from, to, app_pid, options )
		if method in [ :PUBLISH, :SUBSCRIBE ] do
			Process.spawn( fn -> other_dialog_init( :uac, :REGISTER, d_data ) end )
		else
			raise "Cannot "
	end
	
	def send_ood_message( method, ruri, from, to, app_pid, options ) do
	end
	
	@doc """
	Reply to an incoming request. Use this function to reply to any incoming request 
	
	d_id: 	pid of dialog process
	t_id:    	pid of request transaction
	error_code: SIP error code of the responses
	reason:		SIP reason. nil to use default reason
	headers:	SIP headers to inject. Make sure that you know what you are doing here ...
	
	"""
	def reply_d( d_id, t_id, error_code, reason, headers, body ) when error_code in 100..699 or is_atom(error_code) do
		cond do
			error_code == 180 -> evt = :ringing
			error_code == 183 ->
				evt = :progress,
				if body == nil do
					raise "Progress event needs an SDP body"
				end
				
			error_code in 100..102 -> evt = :trying, body = nil
			error_code in [200, 202] evt = :accepted
			error_code in 300..699 evt = :reply
			
			error_code = :ringing -> error_code = 180, evt = :ringing
			error_code = :trying -> error_code = 100, evt = :trying
			error_code = :progress -> 
				error_code = 183, evt = :progress,
				if body == nil do
					raise "Progress event needs an SDP body"
				end
				
			error_code = :busy -> evt = :reply, error_code = 486
			error_code = :refused -> evt = :reply, error_code = 403
			error_code = :accepted -> evt = :reply, error_code = 200
			
			true -> raise "unsupported answer #{error_code}"
		end
		
		Process.send( d_id, { evt, t_id, code, reason, headers, body } )
	end

	def reply_d( d_id, t_id, error_code, reason ) when error_code in 100..699 do
		reply_d( d_id, t_id, error_code, reason, nil, nil )
	end	
	
	def reply_d( d_id, t_id, error_code, reason, body ) when error_code in 100..699 do
		reply_d( d_id, t_id, error_code, reason, nil, body )
	end

	def reply_d( d_id, t_id, answer, body ) when is_atom(answer) do
		reply_d( d_id, t_id, answer, reason, nil, body )
	end
	
	def reply_d( d_id, t_id, answer ) when is_atom(answer) or error_code in 100..699 do
		reply_d( d_id, t_id, answer, reason, nil, nil )
	end

	def reply_d( d_id, t_id, answer, body ) when is_atom(answer) do
		reply_d( d_id, nil, answer, reason, nil, body )
	end
	
	def reply_d( d_id, answer ) when is_atom(answer) or error_code in 100..699 do
		reply_d( d_id, nil, answer, reason, nil, nil )
	end
	
	
	@doc """
	Challenge the request
	Send 401 Proxy Authentication required
	Send 407 Authentication required
	"""
	def challenge_d( dialog_id, req_id, code, headers ) when code == 401 or when code == 407 do
	end
	
	@doc """
	Use this function to send in-dialog UPDATE, INFO, MESSAGE
	Note that from, to, contact, CSeq and other dialog related headers
	will be overwritten with dialog values.
	"""
	def send_request_d(d_id, method, headers, body ) do
		Process.send( d_id, { :in_dialog_req_out, method, headers, body } )
	end

	@doc """
	Forward a request to another dialog. Obtain the transaction
	ID for this request
	"""
	def fwd_request_d( d_id, req ) when req.is_request do
		send_request_d(d_id, req.method, req.headers, req.body)
	end

	@doc """
	Forward a response to a dalog. Caller must know the UAS transaction ID
	that is
	ID for this request
	"""	
	def fwd_response_d( d_id, t_id, resp )
		reply_d(d_id, t_id, resp.error_code, resp.reason, resp.body)
	end
		
	
	@doc """
	Stop running dialog.
	- INVITE dialog -> send BYE
	- UAC REGISTER dialog send REGISTER with Expiration; 0
	- UAC PUBLISH dialog send unPUBLISH
	"""
	def terminate_d( d_id )
		Process.send( d_id, :terminate )
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
	
	defp add_trans( :uac, d_data, t_id, packet ) do
	
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
		
			# If too many requests are being processed
			length(d_data.trans_in) > 3 ->
				SIP.Transaction.reply_t(t_id, 491, nil),
				d_data
		
			true -> %{ d_data | :trans_in => [ d_data.trans_in | t_id ], 
					   :cseq_in => newcseq )
		end
	end
	
	defp add_trans( :uac, d_data, t_id, packet ) do
		newcseq = packet.getCSeqNum()
		if d_data[:dialog_id] = nil do
			d_data = %{ d_data | :dialog_id => packet.getDialogId() }
		else
			if packet.getDialogId() != d_data[:dialog_id] do
				raise "SIP packet is not associated with this dialog"
			end
		end
		
	end
	
	# Remove a transation from dialog transaction list
	defp del_trans( :uas, d_data, t_id )
		trans_in = List.remove(d_data.trans_in, t_id)
		d_data = %{ d_data | :trans_in => trans_in }
	end

	defp del_trans( :uac, d_data, t_id )
		trans_out = List.remove(d_data.trans_out, t_id)
		d_data = %{ d_data | :trans_out => trans_out }
		
	end
	
	defp internal_challenge_d(req_id, code) where code in [ 401, 407 ] do
		m = SIP.Transaction.reply_get_data_t(t_id, :method)
		SIP.Transaction.reply_t(t_id, code, nil)
	end
	
	defp internal_reply_d(d_data, t_id, code, reason) do
		if req_id in d_data[:trans_in] do: SIP.Transaction.reply_t(t_id, code, reason)
	end

	defp create_indialog_req(d_data, method, headers, body)
	
	# ---------------- INVITE DIALOG FSM ---------------------------
	defp invite_dialog_init( :uas, d_data, transport_pid )
		next_state = :init_state
	
		if d_data.packet != nil do
			# Icomong packet used to create dialog -> create UAS transaction
			t_pid = SIP.Transaction.start_incoming_t( d_data[:initial_req], transport_pid, self() )
			d_data = add_trans( :uas, d_data, t_pid )
		else
			raise "Cannot start a dialog without packet"
		end
		
		# Register the dialog in the transport layer and in the app
		Process.send( transport_pid, { :dialog_add, d_data[:dialog_id], self() } )
		
		# Notify the application about dialog creation
		Process.send( d_data[:app_id], { :dialog_add, d_data[:dialog_id], self() } )
		
		receive do
			{ :trying, req_id, code, reason } when code in 100..199 -> 
				internal_reply_d(req_id, code, reason),
				next_state = :init_state
	
			{ :ringing, req_id } ->
				internal_reply_d(req_id, 180, "Ringing"),
				next_state = :early_state

			{ :progress, req_id, body } ->
				internal_reply_d(req_id, 183, "Session Progress", body),
				next_state = :early_state

				
			# App requires authentication
			{ :auth, req_id, } ->
				data_d = internal_challenge_d(data_d, req_id),
				next_state = :auth_uas_state

			{ :reply, req_id, code, reason } when code in 300..699 ->
				SIP.Transaction.reply_t(req_id, code, reason),
				next_state = :terminating_state
			
			# App send a reply code
			{ :reply, req_id, code, reason, body } when code in 200..299 ->
				SIP.Transaction.reply_t(req_id, code, reason, body),
				next_state = :accepted_state
			
			# Intial transaction is cancelled
			{ :uas_transaction_cancel, t_id, reason } -> 
				Process.send( data_d[:app_id], { :dialog_cancel, t_id } ),
				data_d = del_trans( :uas, d_data, t_id ),
				next_state = :cancelling_state
				
			{ :uas_transaction_close, t_id, reason } ->
				Process.send( data_d[:app_id], { :dialog_rejected, t_id } ),
				data_d = del_trans( :uas, d_data, t_id ),
				next_state = :terminated_state
		end
		
		if next_state != :init_state do
			invite_dialog_state( next_state, d_data, :init_state )
		else
			invite_dialog_init( :uas, d_data, transport_pid )
		end
	end

	defp invite_dialog_init( :uac, d_data, transport_pid )
		
		next_state = :init_state
		if transport_pid == nil do
			transport_pid = select_transport( d_data, ruri )
		end
		
		{ t_pid, p } = SIP.Transaction.start_outgoing_t( d_data.packet, transport_pid, self() )
			
		# Register the dialog in the transport layer and in the app
		Process.send( transport_pid, { :dialog_add, d_data[:dialog_id], self() } )
		
		# Notify the application about dialog creation
		Process.send( d_data.app_id, { :dialog_add, d_data[:dialog_id], self() } )
		
		receive do
			{ :uac_transaction_progress, t_id, packet } ->
				if  case packet.response_code do
					183 -> Process.send( d_data.app_id, { :dialog_early, d_data.dialog_id, self(), packet } )
					180 -> Process.send( d_data.app_id, { :dialog_early, d_data.dialog_id, self(), packet } )
				end,
				next_state = :early_state

			{ :uac_transaction_success, t_id, packet } -> 
				Process.send( d_data.app_id, { :dialog_accepted, d_data.dialog_id, self(), packet } ),
				next_state = :accepted_state
			
			{ :uac_transaction_redirect, t_id, initial_req, resp } ->
				data_d = del_trans( :uac, d_data, t_id ),
				if d_data.redirect_count < @max_redirect do
					d_data = %{ d_data | redirect_count: d_data.redirect_count + 1 }
					if d_data.transfer_auto_accept do
						d_data = execute_3xx_redirect( d_data, initial_req )
						Process.send( d_data.app_id, { :dialog_redirected, d_data.dialog_id, self() } )
						next_state = :init_state 
					else
						Process.send( d_data.app_id, { :dialog_redirect_pending, d_data.dialog_id, self() } )
						next_state = :wait_app_accept_redirect
					end
				else
					# Too many redirections
					Process.send( data_d[:app_id], { :dialog_rejected, t_id, :too_many_redirections } )
					next_state = :terminated_state
				end
			
			{ :uac_transaction_auth_required, self(), initial_req, resp } ->
				data_d = del_trans( :uac, d_data, t_id ),
				if d_data.auth_user != nil do
					d_data = answer_challenge( d_data, initial_req, resp.getChallengeInfo() )
					next_state = :uac_auth_state
				else
					# No credential for this dialog. 
					# We do nothing. If the APP may handle the challenge itself
					# todo - add a timer
					next_state = :init_state
				end
				
			# Initial dialog failed. Transport error ?
			{ :uac_transaction_close, t_id, reason } ->
				Process.send( data_d[:app_id], { :dialog_rejected, t_id, reason } ),
				data_d = del_trans( :uas, d_data, t_id ),
				next_state = :terminated_state
		end
		
		if next_state != :init_state do
			invite_dialog_state( next_state, d_data, :init_state )
		else
			invite_dialog_init( :uac, d_data, transport_pid )
		end
	end
	
	defp invite_dialog_state( :auth_uas_state, d_data, prev_st )
	
		receive do
			{ :sip_in, p, tr_id } when p.method == ->  
		end
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
	
	# ---------------- NON INVITE DIALOG FSM ---------------------------
	defp other_dialog_init( :uac, d_data )
		
	end
	
	defp other_dialog_state( :early_state, d_data, prev_st )
	end

	defp other_dialog_state_cancelling( :cancelling_state, d_data, prev_st )
	end

	
	defp other_dialog_state_confirmed( :confirmed_state, d_data, prev_st )
	end
	
