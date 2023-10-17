#---------------- SIP TRANSACTION LAYER ---------------------
defmodule SIP.Transaction do
		@moduledoc """
		SIP transaction layer. Each transaction is a process (and a state machine). It communcate
		with two other processes: a transport process that is in charge of sending or receiveing
		packets and a session level process that receives SIP messages once processed by the transaction
		layer. It handles the retransmission in case on unreliable transport
		"""
		

		@t1_value 		500
		
		@timer_D_value	32000
		
		defp init_t_data( transport_pid, session_pid )
			%{ cancel: nil, timer_A_ref: nil, timer_A_value: @t1_value, timer_B_ref: nil, timer_D_ref: nil,
			   transport_pid: transport_pid, session_pid: session_pid, local_ack: true }
		end
		
		
		@doc
		"""
		Compute a transaction key from the packet. This transaction key will be used to
		check the match
		"""
		
		@doc """
		Starts an outgoing transaction (UAC). It creates a SIP packet and
		start the process (FSM) that will manages the reply
		method 
		
		session_id is either nil -> call ID and from_tag will be generated
							 call_id :: binary -> from_tag will be generated
							 { from_tag, call_id } 
							 { from_tag, call_id, to_tag }
		
		"""
		def start_outgoing_t( packet, transport_pid, session_pid )
							  when is_atom(method) and is_integer(cseq) do
			
			if 	packet.is_request do
				# Start the transaction. FSM will start sending the message to transmission layer
				t_id = Process.spawn(fn -> client_transition_init(packet, init_t_data(transport_pid, session_pid) )  end)
				{ t_id, p }
			else
				raise "Packet must me a request to open a transaction"
			end
		end
	
		def start_outgoing_t( method, cseq, ruri, from, to, session_id, ua, 
						      body, transport_pid, session_pid )
							  when is_atom(method) and is_integer(cseq) do
							  
			p = SIP.Packet.create(method, cseq, ruri, from, to, session_id, ua, body)
			start_outgoing_t( packet, transport_pid, session_pid )
		end
		
		@doc """
		Given a packet, start an incoming (UAS) transaction.
		"""
		def start_incoming_t( packet, transport_pid, session_pid, ua ) do
			if packet.is_request do
			
				if packet.method in [ :ACK, :PRACK, :CANCEL ] do
					raise "Cannot start a transaction #{packet.method}"
				end
			
				t_data = %{ init_t_data(transport_pid, session_pid) | :ua => ua }
				t_id = Process.spawn(fn -> server_transaction_state_init(p, t_data )  end)
			else
				raise "Cannot start a transaction with a RESPONSE"
			end
		end
						
		@doc """
		Send a reply to an UAS transaction
		
		error_code: SIP error code (can also be 1xx, 2xx and 3xx)
		reason: 	reason string to send
		body: 		must be a tupple { content_type, content_payload }
		"""
		def reply_t( transaction_pid, error_code, reason, headers, body ) when error_code in 200..299 and is_tuple(body) do
			Process.send( transaction_pid, { :sip_reply, error_code, reason, headers, body } )
		end

		def reply_t( transaction_pid, error_code, reason, headers ) when error_code in 100..699 do
			Process.send( transaction_pid, { :sip_reply, error_code, reason, headers, nil } )
		end

		def reply_t( transaction_pid, error_code, reason, headers ) when not error_code in 100..699 do
			raise "Invalid SIP response code specified"
		end
		
		@doc """
		Cancel an existing UAC transaction
		"""
		def cancel_t( transaction_pid ) do
			Process.send( transaction_pid, :cancel )
		end
		
		@doc """
		Compute the transction key for a packet
		"""
		def compute_transaction_key( p, t_type ) when is_map(key) do
			cid = packet.getHeaderValue("Call-ID")
			if packet.branch != nil and cid != nil do
				case t_type do
					# todo: add fromtag
					"uac" -> "uac-" <> cid <> "-" <> packet.branch
					"uas" -> "uac-" <> cid <> "-" <> packet.branch
					_ 	  -> raise "Invalid SIP transaction type. Must be uas or uac"
					
			else
				raise "Packet has no branch ID or no Call-ID. It is not bound to any transaction !"
			end
		end
		
		
		# Send a prack message given a transaction - if PRACK is required
		defp sendPRACK(initial_req, t_data)
		end
		
		# Send an ACK message given a transaction 
		# - if the transaction is an invite transaction
		# -
		defp sendACK(initial_req, t_data) do
			if initial_req.method == :INVITE do
				# Only send ACK on an INVITE transaction
				if t_data[:ack] != nil do
					# Ack was already sent ? Resend same ack packet !
					Process.send(transport_pid, { :sip_out, t_data[:ack] }
				else
					if t_data[:local_ack] do
						# If session is configured to send ACK locally, do IT
						ack = %SIP.Packet{initial_req | method: :ACK }
						Process.send(transport_pid, { :sip_out, ack } )
						t_data = %{ t_data | ack: ack ]
					end
				end
			end
			t_data
		end

		# Send an ACK message given a transaction
		defp sendCANCEL(initial_req, t_data) do
			if t_data[:cancel] != nil do
				cancel = t_data[:cancel]
				t_data = %{ t_data | cancel: cancel }
			else
				cancel = %SIP.Packet{initial_req | method: :CANCEL }
			end
			Process.send(t_data[:transport_pid], { :sip_out, cancel } )
			t_data
		end

		# Create a reply from the initial request and send it
		defp uas_reply( req, is_ini_req, t_data, error_code, reason ) do
			uas_reply( req, t_data, error_code, reason, store_reply, nil )
		end
		
		# Create a reply from the initial request and send it
		defp uas_reply( req, is_ini_req, t_data, error_code, reason, body ) do
			p = req.reply(error_code, reason, t_data[:ua])
			if is_tupple(body) do
				{ content_type, content_payload } = body
				p = p.setHeaderValue("Content-Type", content_type)
				p = %SIP.Packet{ p | body: content_payload }
			end
			Process.send( t_data[:transport_pid], { :sip_out, p } )
			t_data = timer_stop(:timer_B, t_data)
			if error_code in 200..699 and is_ini_req do
				%{ t_data | final_resp: p }
			end
		end
		
		defp uas_resend_reply( t_data ) do
			if t_data[:final_reply] != nil do
				Process.send( t_data[:transport_pid], { :sip_out, t_data[:final_reply] } )
			end
		end
		
		# SIP timer A, B and D management
		defp start_timer( :timer_A, t_data ) do
			t_data  = %{ t_data | timer_A_ref: :erlang.start_timer( t_data[:timer_A_value], self(), :timer_A }
		end
		
		defp stop_timer( :timer_A, t_data ) do
			if t_data[:timer_A_ref] != nil do
				:erlang.cancel_timer(t_data[:timer_A_ref])
				t_data  = %{ t_data | timer_A_ref: nil, timer_A_value: @t1_value }
			end
			t_data
		end
		
		defp stop_timer( :timer_B, t_data ) do
			if t_data[:timer_B_ref] != nil do
				:erlang.cancel_timer(t_data[:timer_B_ref])
				t_data  = %{ t_data | timer_B_ref: nil }
			end
			t_data
		end
		
		defp start_timer( :timer_B, t_data ) do
			# Timer B can be restarted
			t_data = stop_timer( :timer_B, t_data )
			t_data = %{ t_data | timer_B_ref: :erlang.start_timer( t_data[:timer_B_value], self(), timer ) }
		end

		defp start_timer( :timer_F, t_data ) do
			t_data = stop_timer( :timer_B, t_data )
			t_data = %{ t_data | timer_D_ref: :erlang.start_timer( @timer_D_value, self(), timer ) }
		end
		
		
		# --------------- Client Transaction state machine --------------------------------------
		defp client_transition_init( initial_req, packet, t_data ) do
		
			# Ask transmission layer to create a transaction entry
			Process.send( t_data[:transport_pid], { :uac_transaction_add, compute_transaction_key(packet, "uac"),  self() } )
		
			# Send the message out
			Process.send( t_data[:transport_pid], { :sip_out, initial_req, self() } )
			
			#Start timer B
			t_data = %{ t_data | timer_B_ref: :erlang.start_timer(@timer_B_value) }
			
			# Start waiting for response messages
			client_transaction_state_0XX( initial_req, t_data, true )
		end
		
		defp client_transition_to_2XX_to_6xx( initial_req, packet, t_data ) do
			t_data = stop_timer(:timer_A, t_data)
			t_data = %{ start_timer(:timer_D, t_data) | resp: packet }
			session_pid = t_data[:session_pid]
			
			cond do
				# Handle 2xx responses
				packet.response_code in 200..299 ->
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_success, self(), packet } ),
					client_transaction_state_2XX( initial_req, packet, t_data, true )
				
				# Handle 3xx responses
				packet.response_code in 300..399 ->
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_redirect, self(), initial_req, resp } ),
					client_transaction_state_3XX( initial_req, packet, t_data, true )
					
				# Handle auth required
				packet.response_code in [401, 407] ->
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_auth_required, self(), initial_req, resp } ),
					client_transaction_state_456XX( initial_req, packet, t_data, true )
					
				# Handle 4xx to 6xx errors
				packet.response_code in 400..699 ->				,
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_error, self(), packet } ),
					client_transaction_state_456XX( initial_req, packet, t_data, true )
				
				true ->
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_close, self(), :invalid_response } ),
					raise "Invalid SIP response. Terimnating transaction",
			end
		end
		
		defp client_transaction_state_0XX( initial_req, t_data, restart_timer ) do
			# Arm  timer A in case of unreliable transport
			if initial_req.transport == udp and restart_timer do
				t_data  = start_timer( :timer_A, t_data )
			end
			session_pid = t_data[:session_pid]
			
			receive do
				# We received packet from transport completed with via and Contact headers populated
				{ :sip_out, :ok, packet} -> client_transaction_state_0XX( packet, t_data )
				
				#The packet could not be send. Kill ourselves and notify the session
				{ :sip_out, rez, packet }   ->
					t_data = stop_timer(:timer_A, t_data),
					client_transaction_end( initial_req, t_data, :tranport_error, "Transport failed to send packet. Terminating SIP transaction" )
				
				# An incoming SIP packet matches the transaction
				{ :sip_in, packet }   ->
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_0XX( initial_req, t_data, false )
						
						# Ignore packet not matching initial request
						packet.getHeaderValue(:CSeq) != initial_req.getHeaderValue(:CSeq) ->
							client_transaction_state_0XX( initial_req, t_data, false )
							
						# Handle 1xx responses. Notify session only for 180 and 183
						# Todo - handle PRACK sending here.
						packet.response_code in [180, 183] ->
							t_data = stop_timer(:timer_A, t_data),
							sendPRACK(initial_req, transport_pid),
							if session_pid != nil do: Process.send(session_pid, { :uac_transaction_progress, self(), packet } ),
							client_transaction_state_1XX( initial_req, t_data )
						
						packet.response_code in 100..199  ->
							t_data = stop_timer(:timer_A, t_data),
							sendPRACK(initial_req, t_data[:transport_pid]),
							client_transaction_state_1XX( initial_req, t_data )
						
						# Handle other responses
						packet.response_code in 200..699 ->
							client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
							
						# Ignore the rest
						true -> client_transaction_state_0XX( initial_req, t_data, false )
					end
					
				# T1 Retransmission
				{ :timeout, timer, :timer_A } ->
					if initial_req.transport == udp do
						# This packet uses UDP transport, resend it
						Process.send( transport_pid, { :sip_out, initial_req} )
					end,
					t_data = %{ t_data | timer_A_value: t_data[:timer_A_value]*2 }
					client_transaction_state_0XX( initial_req, t_data, true )
					
				# Session expired
				{ :timeout, timer, :timer_B } ->
					client_transaction_end( initial_req, t_data, :timer_B_timeout )
				
				
				# Someone wants to cancel the transaction. Stop timer B and fire timer D
				{ :cancel, caller } ->
					t_data = stop_timer(:timer_A, t_data),
					t_data = start_timer(:timer_D, t_data),
					t_data = sendCANCEL(initial_req, t_data),
					client_transaction_state_cancelling( initial_req, t_data )
			end
		end
		
		defp client_transaction_state_1XX( initial_req, t_data ) do
			session_pid = t_data[:session_pid]
			receive do
				{ :sip_in, packet }   ->
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_1XX( initial_req, t_data )
					
						# Handle 1xx responses. RESET timer B
						packet.response_code in 100..199 packet.getHeaderValue(:CSeq) == initial_req.getHeaderValue(:CSeq) ->
							sendPRACK(initial_req, t_data), :erlang.cancel_timer(t_data[:timer_B_ref]),
							t_data = %{ t_data | timer_B_ref: :erlang.start_timer(@timer_B_value, self(), :timer_B) },
							client_transaction_state_1XX( initial_req, t_data )
							
						# Handle other responses
						packet.response_code in 200..699 packet.getHeaderValue(:CSeq) == initial_req.getHeaderValue(:CSeq) ->
							client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
						
						# Ignore the rest
						true -> client_transaction_state_1XX( initial_req, t_data )
					end
					
				# timer B expired
				{ :timeout, timer, :timer_B } ->
					client_transaction_end( initial_req, t_data, :timer_B_timeout )
					
				# Someone wants to cancel the transaction. Stop timer B and fire timer D
				{ :cancel, caller } ->
					t_data = start_timer(:timer_D, t_data),
					t_data = sendCANCEL(initial_req, t_data),
					client_transaction_state_cancelling( initial_req, t_data )				
			end
		end
	end
	
	defp client_transaction_state_2XX( initial_req, t_data, sendack ) do
		final_reply = t_data[:resp]
		session_pid = t_data[:session_pid]

		# Handle ACK business (test on method is done inside sendACK )
		# to do: change the code to wait for application to send ACK (RFC 3261 compliance)
		if sendack do
			t_data = sendACK(initial_req, t_data)
		end
		
		receive do
				{ :sip_in, packet }   ->
					cond do
						# Handle 2xx OK retransmissions, resend ACK
						packet.isRetransmission(final_reply) ->
							client_transaction_state_2XX( initial_req, t_data, true )
						
						# Ignore the rest
						true -> client_transaction_state_2XX( initial_req, t_data, false )
					end
					
				# timer D expired - close session
				{ :timeout, timer, :timer_D }
					if session_pid != nil do: Process.send(session_pid, { :uac_transaction_close, self(), :completed } )
				
				{ :cancel, caller } -> if is_pid(caller) do: Process.send(caller, { :cancel_failed, self(), :bad_state }),
									   client_transaction_state_2XX( initial_req, t_data, false )
			end
		end
	end

	defp client_transaction_state_3XX( initial_req, t_data, sendack ) do
		final_reply = t_data[:resp]
		session_pid = t_data[:session_pid]
		
		# Handle ACK business (test on method is done inside sendACK )
		if sendack do
			t_data = sendACK(initial_req, t_data)
		end
				
		receive do
				{ :sip_in, packet }   ->
					cond do
						# Handle 3xx OK retransmissions, resend ACK
						packet.isRetransmission(final_reply) ->
							client_transaction_state_3XX( initial_req, t_data, true )
						
						# Ignore the rest
						true -> client_transaction_state_3XX( initial_req, t_data, false )
					end
					
				# timer D expired - close session
				{ :timeout, timer, :timer_D } ->
					client_transaction_end( initial_req, t_data, :complete )
				
				{ :cancel, caller } -> 
					if is_pid(caller) do: Process.send(caller, { :cancel_failed, self(),  :bad_state }),
					client_transaction_state_3XX( initial_req, t_data, false )
			end
		end
	end

	defp client_transaction_state_456XX( initial_req, t_data, sendack ) do
		final_reply = t_data[:resp]
		session_pid = t_data[:session_pid]
		
		# Handle ACK business (test on method is done inside sendACK )
		if sendack do
			t_data = sendACK(initial_req, t_data)
		end
		
		receive do
				{ :sip_in, packet } ->
					cond do
						# Handle 4xx 5xx 6xx retransmissions, resend ACK
						packet.isRetransmission(final_reply) ->
							client_transaction_state_456XX( initial_req, t_data, true )
						
						# Ignore the rest
						true -> client_transaction_state_456XX( initial_req, t_data, false )
					end
					
				# timer D expired - close session
				{ :timeout, timer, :timer_D } ->
					client_transaction_end( initial_req, t_data, :complete )
				
				{ :cancel, caller } -> if is_pid(caller) do: Process.send(caller, { :cancel_failed, self(), :bad_state }),
									   client_transaction_state_456XX( initial_req, t_data, false )
			end
		end
	end
	
	defp client_cancelling_process_resp(initial_req, resp, t_data, state_func) when resp.is_request do
		state_func.( initial_req, t_data, false )
	end
	
	defp client_cancelling_process_resp(initial_req, resp, t_data, state_func) when resp.response_code in 100..199 do
		# 1xx answer received for intial requrest, retry cancelling
		state_func.( resp, t_data, true )
	end

	defp client_cancelling_process_resp(initial_req, resp, t_data, state_func) when resp.response_code == 487 do
		t_data = stop(:timer_A, t_data )
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_ok, self(), :ok } )
		client_transition_to_2XX_to_6xx( initial_req, initial_req, t_data )
	end
	
	defp client_cancelling_process_resp(initial_req, resp, t_data, state_func) when packet.response_code in 200..699 do
		t_data = stop(:timer_A, t_data )
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_failed, self(), :too_late } )
		client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
	end
	
	defp client_transaction_state_cancelling( initial_req, t_data, restart_timer ) do

		if restart_timer and initial_req.transport == :udp do
			t_data = start_timer(:timer_A, t_data)
		end
	
		cancel = t_data[:cancel]
		receive do
			{ :sip_in, packet } ->
				cond do
					# This is an UAC, ignore incoming requests
					packet.is_request -> client_transaction_state_cancelling( initial_req, t_data, false )
					
					# This is an answer for cancel, stop timer_A and wait for final answer of the request
					cancel.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						t_data = stop_timer(:timer_A, t_data),
						client_transaction_state_cancelling( initial_req, t_data, false )
					
					initial_req.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						client_cancelling_process_resp( initial_req, packet, client_transaction_state_cancelling )

					true -> client_transaction_state_cancelling( initial_req, t_data, false )
				end
			
			# T1 Retransmission
			{ :timeout, timer, :timer_A } ->
				Process.send( transport_pid, { :sip_out, t_data[:cancel] } )
				t_data = %{ t_data | timer_A_value: t_data[:timer_A_value]*2 }
				client_transaction_state_cancelling( initial_req, t_data, true )

			# timer D expired - close session
			{ :timeout, timer, :timer_D } ->
				t_data = stop_timer(:timer_A, t_data)
				client_transaction_end(initial_req, t_data, :cancelled )
		end
	end
	
	
	defp client_transaction_end(initial_req, t_data, reason) do
		client_transaction_end(initial_req, t_data, nil)
	end
	
	defp client_transaction_end(initial_req, t_data, reason, runtime_error) do
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :uac_transaction_close, self(), reason } )
		Process.send(t_data[:transport_pid], { :uac_transaction_remove, compute_transaction_key(initial_req, "uac"), self() }
	end
	
	# --------------- Server Transaction state machine --------------------------------------
	
	defp server_transition_state_init( initial_req, t_data ) do

			# Ask transmission layer to create a transaction entry
			Process.send( t_data[:transport_pid], { :uas_transaction_add, compute_transaction_key(packet, "uas"),  self() } )
	
			# Send 100 Trying if needed
			if initial_req.method == :INVITE or initial_req.transport == :sip_udp do
				uas_reply( initial_req, true, t_data, 100, "Trying" )
			end
			
			#Start timer B
			t_data = start_timer(:timer_B, t_data)
			
			# Start FSM: waiting for response messages
			server_transaction_state_1XX( initial_req, t_data )
	end
	
	defp server_transaction_state_1XX( initial_req, t_data ) do
	
		receive do
			{ :sip_in, packet } ->
				cond do
					# Discard responses (we are an UAS)
					packet.is_request == false -> server_transaction_state_1XX( initial_req, t_data )
					
					# Discard packet which CSeq does not match the initial request
					packet.getCSeqNum() != initial_req.getCSeqNum() ->
						uas_reply( packet, false, t_data, 400, "Bad request" ),
						server_transaction_state_1XX( initial_req, t_data )
					
					# Restransmission - resend 100 trying
					packet.method == initial_req.method ->
						uas_reply( packet, true, t_data, 100, "Trying" ),
						server_transaction_state_1XX( initial_req, t_data )
					
					# Prack a 1xx response: do nothing (we should cancel a timer)
					packet.method == :PRACK ->
						server_transaction_state_1XX( initial_req, t_data )
					
					# ugh. Invalid case. Ignore 
					packet.method == :ACK ->
						server_transaction_state_1XX( initial_req, t_data )
						
					# UPDATE - not supported
					packet.method == :UPDATE ->
						if initial_req.method == :INVITE do
							uas_reply( packet, false, t_data, 501, "Not supported" ),
							server_transaction_state_1XX( initial_req, packet, t_data )
						else
							uas_reply( packet, false, t_data, 405, "Method not allowed" ),
							server_transaction_state_1XX( initial_req, packet, t_data )
						end
					
					# CANCEL a transaction
					packet.method == :CANCEL ->
						t_data = %{ t_data | cancel: packet },
						t_data = start_timer(:timer_D, t_data),
						if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :uas_transaction_cancel, self(), :ok } )
						server_transaction_state_cancelling( initial_req, t_data )
				end
			
			# Provisional responses
			{ :sip_reply, error_code, reason, body } when error_code in 100..199 ->
				t_data = uas_reply( initial_req, true, t_data, error_code, reason, body ),
				server_transaction_state_1XX( initial_req, t_data )
			
			# Final responses and redirect
			{ :sip_reply, error_code, reason, body } when error_code in 200..699 ->
				t_data = uas_reply( initial_req, true, t_data, error_code, reason, body ),
				t_data = start_timer(:timer_D, t_data),
				server_transaction_state_final_reply( initial_req, t_data )
				
			{ :timeout, :timer_B } ->
				t_data = %{ t_data | final_resp: resp, timer_B_ref: nil },
				t_data = uas_reply( initial_req, true, t_data, 408, reason, "Request timeout" )
				server_transaction_state_final_reply( initial_req, t_data, false )
		end
		
	end
	
	defp server_transaction_state_cancelling( initial_req, t_data ) do
		receive do
			{ :sip_in, packet } ->
				cond do
					# Discard responses (we are an UAS)
					packet.is_request == false -> server_transaction_state_cancelling( initial_req, t_data )
					
					# Discard packet which CSeq does not match the initial request
					packet.getCSeqNum() != initial_req.getCSeqNum() ->
						uas_reply( packet, false, t_data, 400, "Bad request" ),
						server_transaction_state_cancelling( initial_req, t_data )

					# Restransmission - resend 100
					packet.method == initial_req.method -> 
						uas_reply( packet, true, t_data, 100, "Trying" ),
						server_transaction_state_cancelling( initial_req, t_data )
						
					# Cancel restransmission
					packet.method == :CANCEL ->
						uas_reply( packet, false, t_data, 100, "Cancelling" ),
						server_transaction_state_cancelling( initial_req, t_data )
					
					# All other case - 
					true ->
						uas_reply( packet, false, t_data, 400, "Bad state" ),
						server_transaction_state_cancelling( initial_req, t_data )
				end

			
			{ :sip_reply, error_code, reason, body } when error_code in 100..199 ->
				t_data = uas_reply( initial_req, true, t_data, error_code, reason, body ),
				server_transaction_state_1XX( initial_req, t_data )
			
			# Only cancelled is processd
			:cancel ->
				t_data = uas_reply( initial_req, true, t_data, 487, "Request Terminated", nil ),
				t_data = start_timer(:timer_D, t_data),
				server_transaction_state_final_reply( initial_req, t_data )
				
			# Not cancelled on time
			{ :timeout, :timer_D } ->
				uas_reply( initial_req, true, t_data, 487, "Request terminated" ),
				uas_reply( t_data[:cancel], false, t_data, 200, "OK" ),
				t_data = start_timer(:timer_D, t_data),
				server_transaction_state_final_reply( initial_req, t_data, false )
	end
	
	defp server_transaction_state_final_reply( initial_req, t_data, resend_repl ) do
	
		if resend_repl do
			uas_resend_reply( t_data )
		end
		
		receive do
			{ :sip_in, packet } ->
				cond do
					# Discard responses (we are an UAS)
					packet.is_request == false -> server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Discard packet which CSeq does not match the initial request
					packet.getCSeqNum() != initial_req.getCSeqNum() ->
						uas_reply( packet, false, t_data, 400, "Bad request" ),
						server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Restransmission - resend reply
					packet.method == initial_req.method -> 
						server_transaction_state_final_reply( initial_req, t_data, nil, true )
					
					# Too late for cancelling - but we reply OK 
					packet.method == :CANCEL ->
						uas_reply( packet, false, t_data, 200, "OK" ),
						server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Check if method is INVITE and UPDATE then notify the application
					packet.method == :ACK ->
						if packet.initial_req in [ :INVITE, :UPDATE ] do
							if t_data[:session_pid] != nil do
								Process.send( t_data[:session_pid], { :uas_transaction_close, self(), :confirmed } )
							end
							server_transaction_end( initial_req, t_data )
						end
				end
			
			# End of transaction
			{ :timeout, :timer_D } ->
				t_data = %{ t_data | timer_D_ref: nil },
				server_transaction_end( initial_req, t_data )
		end
		
	end
	
	defp server_transaction_end( initial_req, t_data )
		Process.send(t_data[:transport_pid], { :uas_transaction_remove, compute_transaction_key(initial_req, "uac"), self() } )
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :uas_transaction_close, self(), :ok } )
	end
end	
			