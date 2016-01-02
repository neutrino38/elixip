#---------------- SIP TRANSACTION LAYER ---------------------
defmodule SIP.Transaction do
		@moduledoc """
		SIP transaction layer. Each transaction is a process (and a state machine). It communcate
		with two other processes: a transport process that is in charge of sending or receiveing
		packets and a session level process that receives SIP messages once processed by the transaction
		layer. It handles the retransmission in case on unreliable transport
		"""
		

		@t1_value 		500
				
		@doc """
		Starts an outgoing transaction
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
				{ fromtag, callid, totag } -> { fromtag, callid, totag }
				nil -> { fromtag, callid } = { genTag( [from.user, from.domain, :rand.uniform() ] ), genTag( :rand.uniform() ) }
			end
			
			hlist = [ 
				{ "From", SIP.URI.setParam(from, "tag", fromtag) },
				{ "To", (if totag != nil, do: SIP.URI.setParam(to, "tag", totag), else: to) },
				{ "CSeq", "#{cseq} #{method}" }
			]
			
			p = SIP.Packet.setHeaderValues(p, hlist)
			p = %SIP.Packet{p | branch: genTag( :rand.uniform() ) }
			# Other headers (contact, via, route, will be added by transport layer)
			
			Process.send( transport_pid, :sip_out, p, session_pid )
			p
		end
		
		def start_incoming_t( packet ) do
		end
		
		def message_match?( packet, transaction_id ) do
		end
		
		def message_match?( packet, cseq  ) do
		end
		
		@doc """
		Call this function for to process any message related to this transaction
		"""
		def process_message_t( pid, packet ) do
		end
		
		def reply_t( transaction_pid, error_code, reason ) do
		end
		
		def cancel_t( transaction_pid ) do
			Process.send( transaction_pid, :cancel )
		end
		
		defp genTag( src ) do
			:crypto.hash(:md5, src) |> Base.encode64 |> String.strip ?=
		end
		
		# Send a prack message given a transaction - if PRACK is required
		defp sendPRACK(initial_req, transport_pid)
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
		defp sendCANCEL(initial_req, transport_pid) do
			if initial_req.method == :INVITE do
				cancel = %SIP.Packet{initial_req | method: :CANCEL }
				Process.send(transport_pid, { :sip_out, cancel } )
				cancel
			end
		end

		
		# --------------- Client Transaction state machine --------------------------------------
		defp client_transition_to_2XX_to_6xx( initial_req, packet, t_data ) do
			Erlang.cancel_timer(timer_B_ref)
			timer_D_ref = Erlang.start_timer( @timer_D_value, self(), :timer_D )
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
				timerA = Erlang.start_timer( timer_A_value, self(), t_data[:timer_A_value] )
				t_data  = %{ t_data | timer_A_ref: timerA }
			end
			session_pid = t_data[:session_pid]
			
			receive do
				# We received packet from transport completed with via and Contact headers populated
				{ :sip_out, :ok, packet} -> client_transaction_state_0XX( packet, t_data )
				
				#The packet could not be send. Kill ourselves and notify the session
				{ :sip_out, rez, packet }   -> 
					if session_pid != nil do: Process.send(session_pid, { :transaction_error, :tranport_error, rez } ),
					raise "Transport failed to send packet. Terminating SIP transaction"
				
				# An incoming SIP packet matches the transaction
				{ :sip_in, packet }   ->
					Erlang.cancel_timer(timerA),
					t_data  = %{ t_data | timer_A_ref: nil } ),
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_0XX( initial_req, t_data )
					
						# Handle 1xx responses. Notify session only for 180 and 183
						# Todo - handle PRACK sending here.
						packet.response_code == 180 or packet.response_code == 183 ->
							sendPRACK(initial_req, transport_pid),
							if session_pid != nil do: Process.send(session_pid, { :transaction_progress, packet } ),
							client_transaction_state_1XX( initial_req, t_data )
						
						packet.response_code in 100..199 ->
							sendPRACK(initial_req, t_data[:transport_pid]),
							client_transaction_state_1XX( initial_req, t_data )
						
						# Handle other responses
						packet.response_code in 200..699 ->
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
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :expired } ),
					raise "SIP transaction expired.  Terminating SIP transaction"
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
						packet.response_code in 100..199 ->
							sendPRACK(initial_req, t_data),
							Erlang.cancel_timer(t_data[:timer_B_ref]),
							t_data = %{ t_data | timer_B_ref: Erlang.start_timer(@timer_B_value) },
							client_transaction_state_1XX( initial_req, t_data )
							
						# Handle other responses
						packet.response_code in 200..699 ->
							client_transition_to_2XX_to_6xx( initial_req, packet, t_data )
						
						# Ignore the rest
						true -> client_transaction_state_1XX( initial_req, t_data )
					end
					
				# timer B expired
				{ :timeout, timer, :timer_B } -> cond do -> 
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :timer_B_timeout, 408 } ),
			end
		end
	end
	
	defp client_transaction_state_2XX( initial_req, t_data, sendack ) do
		final_reply = t_data[:resp]
		session_pid = t_data[:session_pid]

		# Handle ACK business (test on method is done inside sendACK )
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
				{ :timeout, timer, :timer_D }
					if session_pid != nil do: Process.send(t_data[:session_pid], { :transaction_close, :completed } )
					
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
				{ :sip_in, packet }   ->
					cond do
						# Handle 4xx 5xx 6xx retransmissions, resend ACK
						packet.isRetransmission(final_reply) ->
							client_transaction_state_456XX( initial_req, t_data, true )
						
						# Ignore the rest
						true -> client_transaction_state_456XX( initial_req, t_data, false )
					end
					
				# timer D expired - close session
				{ :timeout, timer, :timer_D }
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :completed } )
					
			end
		end
	end
	
	defp client_transaction_state_cancelling( initial_req, t_data, sendack ) do
end	
			
		
			
	