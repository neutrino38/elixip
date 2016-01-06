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
		def start_incoming_t( packet, session_id, transport_pid, session_pid ) do
			if packet.is_request do
			
				if packet.method in [ :ACK, :PRACK, :CANCEL ] do
					raise "Cannot start a transaction #{packet.method}"
				end
			
				t_id = Process.spawn(fn -> server_transaction_state_init(p, init_t_data(transport_pid, session_pid) )  end)
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

		create_sip_reply( initial_req, ua, error_code, reason, body ) do
			p = initial_req.reply(error_code, reason, ua)
			if is_tupple(body) do
				{ content_type, content_payload } = body
				p = p.setHeaderValue("Content-Type", content_type)
				%SIP.Packet{ p | body: content_payload }
			end
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
			client_transaction_state_0XX( initial_req, t_data )
		end
		
		defp client_transition_to_2XX_to_6xx( initial_req, packet, t_data ) do
			:erlang.cancel_timer(timer_B_ref)
			timer_D_ref = :erlang.start_timer( @timer_D_value, self(), :timer_D )
			t_data  = %{ t_data | timer_D: timer_D_ref, resp: packet }
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
				packet.response_code >= 401 or packet.response_code == 407 ->
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
		
		defp client_transaction_state_0XX( initial_req, t_data ) do
			# Arm  timer A in case of unreliable transport
			if initial_req.transport == udp do
				timerA = :erlang.start_timer( timer_A_value, self(), t_data[:timer_A_value] )
				t_data  = %{ t_data | timer_A_ref: timerA }
			end
			session_pid = t_data[:session_pid]
			
			receive do
				# We received packet from transport completed with via and Contact headers populated
				{ :sip_out, :ok, packet} -> client_transaction_state_0XX( packet, t_data )
				
				#The packet could not be send. Kill ourselves and notify the session
				{ :sip_out, rez, packet }   ->
					:erlang.cancel_timer(timerA),
					client_transaction_end( initial_req, t_data, :tranport_error, "Transport failed to send packet. Terminating SIP transaction" )
				
				# An incoming SIP packet matches the transaction
				{ :sip_in, packet }   ->
					:erlang.cancel_timer(timerA),
					t_data  = %{ t_data | timer_A_ref: nil } ),
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_0XX( initial_req, t_data )
					
						# Handle 1xx responses. Notify session only for 180 and 183
						# Todo - handle PRACK sending here.
						packet.response_code == 180 or packet.response_code == 183 and
						packet.getHeaderValue(:CSeq) == initial_req.getHeaderValue(:CSeq) ->
							sendPRACK(initial_req, transport_pid),
							if session_pid != nil do: Process.send(session_pid, { :transaction_progress, packet } ),
							client_transaction_state_1XX( initial_req, t_data )
						
						packet.response_code in 100..199 and packet.getHeaderValue(:CSeq) == initial_req.getHeaderValue(:CSeq) ->
							sendPRACK(initial_req, t_data[:transport_pid]),
							client_transaction_state_1XX( initial_req, t_data )
						
						# Handle other responses
						packet.response_code in 200..699 packet.getHeaderValue(:CSeq) == initial_req.getHeaderValue(:CSeq) ->
							client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
							
						# Ignore the rest
						true -> client_transaction_state_0XX( initial_req, t_data )
					end
					
				# T1 Retransmission
				{ :timeout, timer, :timer_A } ->
					if initial_req.transport == udp do
						# This packet uses UDP transport, resend it
						Process.send( transport_pid, { :sip_out, initial_req} )
					end,
					t_data = %{ t_data | timer_A_value: t_data[:timer_A_value]*2 }
					client_transaction_state_0XX( initial_req, t_data )
					
				# Session expired
				{ :timeout, timer, :timer_B } ->
					client_transaction_end( initial_req, t_data, :timer_B_timeout )
				
				
				# Someone wants to cancel the transaction. Stop timer B and fire timer D
				{ :cancel, caller } ->
					timer_D_ref = :erlang.start_timer( @timer_D_value, self(), :timer_D ),
					t_data = %{ t_data | timer_A_value: @t1_value, timer_A_ref: nil, timer_D_ref: :erlang.start_timer( @timer_D_value, self(), :timer_D ) },
					client_transaction_state_cancelling_in_0XX( initial_req, t_data, true )						
							
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
							sendPRACK(initial_req, t_data),
							:erlang.cancel_timer(t_data[:timer_B_ref]),
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
					timer_D_ref = :erlang.start_timer( @timer_D_value, self(), :timer_D ),
					t_data = %{ t_data | timer_A_value: @t1_value, timer_A_ref: nil, timer_D_ref: :erlang.start_timer( @timer_D_value, self(), :timer_D ) },
					client_transaction_state_cancelling_in_0XX( initial_req, t_data, true )
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
	
	defp client_transaction_cancelling_process_response(initial_req, resp, t_data, state_func) do
		cond do
			resp.is_request -> client_transaction_state_cancelling_in_0XX( initial_req, t_data, false )
			
			# 1xx answer received for intial requrest, retry cancelling
			resp.response_code in 100..199 ->
				state_func.( resp, t_data, true )
			
			resp.response_code == 487 ->
				if timerA != nil do: :erlang.cancel_timer(timerA),
				if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_ok, self() } ),
				client_transition_to_2XX_to_6xx( initial_req, initial_req, t_data )
			
			packet.response_code in 200..299 ->
				if timerA != nil do: :erlang.cancel_timer(timerA),
				if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_failed, self(), :too_late } ),
				client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
			
			# Todo - should print a warning here
			packet.response_code in 300..699 ->
				if timerA != nil do: :erlang.cancel_timer(timerA),
				if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :cancel_ok, self()} ),
				client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
				
			true -> state_func.( resp, t_data, false )
		end	
	
	defp client_transaction_state_cancelling_in_0XX( initial_req, t_data, sendcancel ) do
		if sendcancel do
			t_data = sendCANCEL(initial_req, t_data)
			timerA = t_data[:timer_A_ref]
			if initial_req.transport == udp do
				timerA = :erlang.start_timer( timer_A_value, self(), t_data[:timer_A_value] )
				t_data  = %{ t_data | timer_A_ref: timerA }
			end
		end
		
		
		cancel = t_data[:cancel]

		receive do
			{ :sip_in, packet } ->
				cond do
					# This is an UAC, ignore incoming requests
					packet.is_request -> client_transaction_state_cancelling_in_0XX( initial_req, t_data, false )
					
					# This is an answer for cancel - wait for final answer of the request
					cancel.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						if timerA != nil do: :erlang.cancel_timer(timerA),
						client_transaction_state_cancel_received( initial_req, t_data )
					
					initial_req.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						client_transaction_state_cancelling_in_0XX( initial_req, packet, client_transaction_state_cancelling_in_0XX )

					true -> client_transaction_state_cancelling_in_0XX( initial_req, t_data, false )
				end
			
							# T1 Retransmission
			{ :timeout, timer, :timer_A } ->
				if initial_req.transport == udp do
						# This packet uses UDP transport, resend it
						Process.send( transport_pid, { :sip_out, initial_req} )
				end,
				t_data = %{ t_data | timer_A_value: t_data[:timer_A_value]*2 }
				client_transaction_state_cancelling_in_0XX( initial_req, t_data )

			# timer D expired - close session
			{ :timeout, timer, :timer_D } ->
				client_transaction_end( initial_req, t_data, :complete )
		end
	end
	
	defp client_transaction_state_cancel_received( initial_req, t_data, sendcancel ) do
		
		cancel = t_data[:cancel]

		receive do
			{ :sip_in, packet } ->
				cond do
					# This is an UAC, ignore incoming requests
					packet.is_request -> client_transaction_state_cancelling_in_0XX( initial_req, t_data, false )
					
					# This is an answer for cancel - wait for final answer of the request
					cancel.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						client_transaction_state_cancel_received( initial_req, t_data )
					
					initial_req.getHeaderValue(:CSeq) == packet.getHeaderValue(:CSeq) ->
						client_transaction_state_cancelling_in_0XX( initial_req, packet, client_transaction_state_cancel_received )

					true -> client_transaction_state_cancelling_in_0XX( initial_req, t_data, false )
				end
			
			# timer D expired - close session
			{ :timeout, timer, :timer_D } ->
				client_transaction_end( initial_req, t_data, :cancelled )
		end	
	end
	
	defp client_transaction_end(initial_req, t_data, reason) do
		client_transaction_end(initial_req, t_data, nil)
	end
	
	defp client_transaction_end(initial_req, t_data, reason, runtime_error) do
		if t_data[:session_pid] != nil do: Process.send(t_data[:session_pid], { :transaction_close, self(), reason } )
	
	# --------------- Server Transaction state machine --------------------------------------
	
	defp server_transition_init( initial_req, t_data ) do

			# Ask transmission layer to create a transaction entry
			Process.send( t_data[:transport_pid], { :transaction_add, initial_req.getTransactionId(), self() } )
	
			resp = initial_req.reply(100, "Trying", t_data[:ua])
				# Send the message out
			Process.send( t_data[:transport_pid], :sip_out, resp, self() )
			
			#Start timer B
			t_data = %{ t_data | timer_B_ref: :erlang.start_timer(@timer_B_value, self(), :timer_B) }
			
			# Start waiting for response messages
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
						Process.send( t_data[:transport_pid], :sip_out )
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
							resp = packet.reply(405, "Mrthod not allowed", t_data[:ua]),
							Process.send( t_data[:transport_pid], { :sip_out, resp } ),
							server_transaction_state_1XX( initial_req, packet, t_data )
						end
					
					# CANCEL a transaction
					packet.method == :CANCEL ->
						t_data = %{ t_data | cancel: packet },
						server_transaction_state_cancelling( initial_req, t_data )
			
				end
			
			{ :sip_reply, error_code, reason, body } ->
				reply = create_sip_reply( initial_req, error_code, reason, body )
				cond do
				
					reply.response_code in [ 180, 183 ] ->
						Process.send( t_data[:transport_pid], { :sip_out, reply } ),
						server_transaction_state_1XX( initial_req, t_data )
						
					reply.response_code in 200..299 ->
						t_data = %{ t_data | final_resp: reply },
						server_transaction_state_final_reply( initial_req, t_data, reply, true )
						
					reply.response_code in 300..399 ->
						t_data = %{ t_data | final_resp: reply },
						server_transaction_state_final_reply( initial_req, t_data, reply, true )

					reply.response_code in 400..699 ->
						t_data = %{ t_data | final_resp: reply },
						server_transaction_state_final_reply( initial_req, t_data, reply, true )
					
				end
				
			{ :timeout, :timer_B } ->
				resp = packet.reply(408, "Request timeout", t_data[:ua]),
				t_data = %{ t_data | final_resp: resp, timer_B_ref: nil },
				Process.send( t_data[:transport_pid], { :sip_out, reply } ),
				server_transaction_state_456XX( initial_req, packet, t_data )
		end
		
	end
	
	defp server_transaction_state_final_reply( initial_req, packet, t_data, sendpacket ) do
		if t_data[:timer_B_ref] != nil do
			:erlang.cancel_timer(t_data[:timer_B_ref)
			t_data = %{ t_data | timer_B_ref: nil, timer_D_ref: :erlang.start_timer( @timer_D_value, self(), :timer_D ) },
		end
				
		if sendpacket do
			Process.send( t_data[:transport_pid], { :sip_out, packet } )
		end

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
						end
				end
			
			# End of transaction
			{ :timeout, :timer_D } ->
		end
		
	end
	
	defp server_transaction_state_cancelling( initial_req, t_data ) do
	end
	

end	
			