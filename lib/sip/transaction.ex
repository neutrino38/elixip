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
		def start_outgoing_t( method, cseq, ruri, from, to, session_id, transport_pid, session_pid ) when is_atom(method) and is_integer(cseq) do
			p = %SIP.Packet{ method: method, ruri: ruri, is_request: true }
			
			cond do
				is_binary(from) -> from = SIP.URI.parse(from)
				from.__struct__ == "SIP.URI" -> from
				true -> raise "Invalid from"
			end
			
			cond do
				is_binary(to) -> to = SIP.URI.parse(to)
				to.__struct__ == "SIP.URI" -> to
				to == nil -> to = ruri
				true -> raise "Invalid to"
			end
				
			
			case session_id do
				{ fromtag, callid, totag } -> 
					p = p.setHeaderValue( :From, 	from.setParam("tag", fromtag )),
					p = p.setHeaderValue( :To, 		to.setParam("tag", totag )),
					p = p.setHeaderValue( "Call-ID", callid )
									
				
				# No session ID specifed ? Create one !
				nil ->
					p = p.setHeaderValue(:From, from) |> 
						SIP.Packet.setHeaderValue(:To, to) |> 
						SIP.Packet.generateTag(:From) |> 
						SIP.Packet.generateTag("Call-ID")
			end
			
			
			# Add CSeq and generage branch tag.
			p = p |> SIP.Packet.setHeaderValue(:CSeq, "#{cseq} #{method}") |> SIP.Packet.generateTag(:Via)
			
			# Other headers (contact, via, route, will be added by transmission layer)
			
			# Start the transaction. FSM will start sending the message to transmission layer
			t_id = Process.spawn(fn -> client_transaction_state_init(p, init_t_data(transport_pid, session_pid) )  end)
		end
		
		@doc """
		Given a packet, start an incoming (UAS) transaction.
		"""
		def start_incoming_t( packet, session_id, transport_pid, session_pid, ua ) do
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
		def reply_t( transaction_pid, error_code, reason, body ) when is_integer(error_code) and is_tuple(body) do
			if error_code in 100..699 do
				Process.send( transaction_pid, { :sip_reply, error_code, reason, body } )
			else
				raise "Invalid error code specified"
			end
		end

		def reply_t( transaction_pid, error_code, reason ) when is_integer(error_code) do
			if error_code in 100..699 do
				Process.send( transaction_pid, { :sip_reply, error_code, reason, nil } )
			else
				raise "Invalid error code specified"
			end
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
		defp uas_reply( initial_req, t_data, error_code, reason ) do
			uas_reply( initial_req, t_data, error_code, reason, nil )
		end
		
		# Create a reply from the initial request and send it
		defp uas_reply( initial_req, t_data, error_code, reason, body ) do
			p = initial_req.reply(error_code, reason, t_data[:ua])
			if is_tupple(body) do
				{ content_type, content_payload } = body
				p = p.setHeaderValue("Content-Type", content_type)
				p %SIP.Packet{ p | body: content_payload }
			end
			Process.send( t_data[:transport_pid], { :sip_out, p } )
			t_data = timer_stop(:timer_B, t_data)
			if error_code in 200..699 do
				%{ t_data | final_resp: p }
			end
		end
		
		# SIP timer A, B and D management
		defp start_timer( :timer_A, t_data ) do
			t_data  = %{ t_data | timer_A_ref: :erlang.start_timer( t_data[:timer_A_value], self(), :timer_A }
		end
		
		defp stop_timer( :timer_A, t_data ) do
			if t_data[:timer_A_ref] != nil do
				:erlang.stop_timer(t_data[:timer_A_ref])
				t_data  = %{ t_data | timer_A_ref: nil, timer_A_value: @t1_value }
			end
			t_data
		end
		
		defp start_timer( :timer_B, t_data ) do
			# Timer B can be restarted
			if t_data[:timer_B_ref] != nil do
				:erlang.cancel_timer(t_data[:timer_B_ref])
			end
			t_data = %{ t_data | timer_B_ref: :erlang.start_timer( t_data[:timer_B_value], self(), timer ) }
		end

		defp start_timer( :timer_F, t_data ) do
			if (t_data[:timer_B_ref] != nil do
				:erlang.cancel_timer(t_data[:timer_B_ref])
				t_data = %{ t_data | timer_B_ref: nil }
			end
			
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
					if session_pid != nil do: Process.send(session_pid, { :transaction_success, packet } ),
					client_transaction_state_2XX( initial_req, packet, t_data, true )
				
				# Handle 3xx responses
				packet.response_code in 300..399 ->
					if session_pid != nil do: Process.send(session_pid, { :transaction_redirect, packet } ),
					client_transaction_state_3XX( initial_req, packet, t_data, true )
					
				# Handle auth required
				packet.response_code in [401, 407] ->
					if session_pid != nil do: Process.send(session_pid, { :transaction_auth_required, packet } ),
					client_transaction_state_456XX( initial_req, packet, t_data, true )
					
				# Handle 4xx to 6xx errors
				packet.response_code in 400..699 ->				,
					if session_pid != nil do: Process.send(session_pid, { :transaction_error, packet } ),
					client_transaction_state_456XX( initial_req, packet, t_data, true )
				
				true ->
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :invalid_response } ),
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
							if session_pid != nil do: Process.send(session_pid, { :transaction_progress, packet } ),
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
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :completed } )
				
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
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_ok, self() } )
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
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :transaction_close, self(), reason } )
		Process.send(t_data[:transport_pid], { :uac_transaction_remove, compute_transaction_key(initial_req, "uac"), self() }
	end
	
	# --------------- Server Transaction state machine --------------------------------------
	
	defp server_transition_state_init( initial_req, t_data ) do

			# Ask transmission layer to create a transaction entry
			Process.send( t_data[:transport_pid], { :uas_transaction_add, compute_transaction_key(packet, "uas"),  self() } )
	
			resp = initial_req.reply(100, "Trying", t_data[:ua])
				# Send the message out
			Process.send( t_data[:transport_pid], :sip_out, resp, self() )
			
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
					packet.getHeaderValue(:CSeq) != initial_req.getHeaderValue(:CSeq) ->
						resp = packet.reply(400, "Bad request", t_data[:ua]),
						Process.send( t_data[:transport_pid], :sip_out ),
						server_transaction_state_1XX( initial_req, t_data )
					
					# Restransmission - resend 100 trying
					packet.method == initial_req.method -> 
						resp = initial_req.reply(100, "Trying", t_data[:ua]),
						Process.send( t_data[:transport_pid], :sip_out ),
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
							resp = packet.reply(501, "Not supported", t_data[:ua]),
							Process.send( t_data[:transport_pid], { :sip_out, resp } )
							server_transaction_state_1XX( initial_req, packet, t_data )
						else
							resp = packet.reply(405, "Method not allowed", t_data[:ua]),
							Process.send( t_data[:transport_pid], { :sip_out, resp } ),
							server_transaction_state_1XX( initial_req, packet, t_data )
						end
					
					# CANCEL a transaction
					packet.method == :CANCEL ->
						t_data = %{ t_data | cancel: packet },
						server_transaction_state_cancelling( initial_req, t_data )
			
				end
			
			{ :sip_reply, error_code, reason, body } ->
				t_data = uas_reply( initial_req, t_data, error_code, reason, body ),
				cond do
					reply.response_code in 100..199 -> server_transaction_state_1XX( initial_req, t_data )
						
					reply.response_code in 200..699 -> 
						t_data = start_timer(:timer_D, t_data),
						server_transaction_state_final_reply( initial_req, t_data )					
				end
				
			{ :timeout, :timer_B } ->
				t_data = %{ t_data | final_resp: resp, timer_B_ref: nil },
				t_data = uas_reply( initial_req, t_data, 408, reason, "Request timeout" )
				server_transaction_state_456XX( initial_req, packet, t_data )
		end
		
	end
	
	defp server_transaction_state_final_reply( initial_req, packet, t_data ) do

		receive do
			{ :sip_in, packet } ->
				cond do
					# Discard responses (we are an UAS)
					packet.is_request == false -> server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Discard packet which CSeq does not match the initial request
					packet.getHeaderValue(:CSeq) != initial_req.getHeaderValue(:CSeq) ->
						resp = packet.reply(400, "Bad request", t_data[:ua]),
						Process.send( t_data[:transport_pid], { :sip_out, resp } ),
						server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Restransmission - resend reply
					packet.method == initial_req.method -> 
						server_transaction_state_final_reply( initial_req, t_data, nil, true )
					
					# Too late for cancelling !
					packet.method == :CANCEL ->
						resp = packet.reply(200, "OK", t_data[:ua]),
						Process.send( t_data[:transport_pid], { :sip_out, resp } ),
						server_transaction_state_final_reply( initial_req, t_data, nil, false )
					
					# Check if method is INVITE and UPDATE then notify the application
					packet.method == :ACK ->
						if packet.initial_req in [ :INVITE, :UPDATE ] do
							if t_data[:session_pid] != nil do
								Process.send( t_data[:session_pid], { :transaction_close, :confirmed } )
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
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :transaction_close, self(), reason } )
	end
end	
			