#---------------- SIP TRANSACTION LAYER ---------------------
defmodule SIP.Transaction do
		@moduledoc """
		SIP transaction layer. Each transaction is a process (and a state machine). It communcate
		with two other processes: a transport process that is in charge of sending or receiveing
		packets and a session level process that receives SIP messages once processed by the transaction
		layer. It handles the retransmission in case on unreliable transport
		"""
		
		@t1_timer 		30000
		@t1_timer_start 500
		@t2_timer		1800000
		
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
		end
		
		defp genTag( src ) do
			:crypto.hash(:md5, src) |> Base.encode64 |> String.strip ?=
		end
		
		
		# --------------- Client Transaction state machine --------------------------------------
		defp client_transaction_state_0XX( initial_req, t1_value, session_pid, transport_pid ) do
			receive do
				# We received packet from transport completed with via and Contact headers populated
				{ :sip_out, :ok, packet} -> client_transaction_state_0XX( packet, t1_value )
				
				#The packet could not be send. Kill ourselves and notify the session
				{ :sip_out, rez, packet }   -> 
					if session_pid != nil do: Process.send(session_pid, { :transaction_error, :tranport_error, rez } ),
					raise "Transport failed to send packet. Terminating SIP transaction"
				
				# 
				{ :sip_in, packet }   ->
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_0XX( initial_req, t1_value, session_pid, transport_pid )
					
						# Handle 1xx responses. Notify session only for 180 and 183
						# Todo - handle PRACK sending here.
						packet.response_code == 180 or packet.response_code == 183 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_progress, packet } ),
							client_transaction_state_1XX( initial_req, @t2_timer, session_pid, transport_pid )
						
						packet.response_code >= 100 and packet.response_code < 200 ->
							client_transaction_state_1XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						# Handle 2xx responses
						packet.response_code >= 200 and packet.response_code < 300 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_success, packet } ),
							client_transaction_state_2XX( initial_req, @t2_timer, session_pid, transport_pid )
						
						# Handle 3xx responses
						packet.response_code >= 300 and packet.response_code < 400 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_redirect, packet } ),
							client_transaction_state_3XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						# Handle 4xx to 6xx errors  (transaction rejected or auth required)
						packet.response_code >= 401 or packet.response_code == 407 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_auth_required, packet } ),
							client_transaction_state_456XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						packet.response_code >= 400 and packet.response_code < 700 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_error, packet } ),
							client_transaction_state_456XX( initial_req, @t2_timer, session_pid, transport_pid )
						
						# Ignore the rest
						true -> client_transaction_state_0XX( initial_req, t1_value, session_pid, transport_pid )
					end
					
				# T1 Retransmission
				until t1_value -> cond do
					# T1 expired
					t1_value >= @t1_timer_max ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_close, :t1_timeout, 408 } ),
							raise "T1 timer expired.  Terminating SIP transaction"
						
					# This packet uses UDP transport, resend it
					initial_req.transport == udp ->
							Process.send( transport_pid, { :sip_out, initial_req} ),
							client_transaction_state_0XX( packet, t1_value*2 )
							
					# Other cases ? run T1 timer
					true -> client_transaction_state_0XX( packet, t1_value*2 )
				end
		end
		
		defp client_transaction_state_1XX( initial_req, t2_value, session_pid, transport_pid ) do
		
			receive do
				{ :sip_in, packet }   ->
					cond do
						#Ignore requests matching this transaction (we are in a client transaction) ( recutsion )
						packet.is_request -> client_transaction_state_1XX( initial_req, t2_value, session_pid, transport_pid )
					
						# Handle 1xx responses. RESET t2 timer
						# Todo - handle PRACK sending here.						
						packet.response_code >= 100 and packet.response_code < 200 ->
							client_transaction_state_1XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						# Handle 2xx responses
						packet.response_code >= 200 and packet.response_code < 300 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_success, packet } ),
							client_transaction_state_2XX( initial_req, @t2_timer, session_pid, transport_pid )
						
						# Handle 3xx responses
						packet.response_code >= 300 and packet.response_code < 400 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_redirect, packet } ),
							client_transaction_state_3XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						# Handle 4xx to 6xx errors  (transaction rejected or auth required)
						packet.response_code >= 401 or packet.response_code == 407 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_auth_required, packet } ),
							client_transaction_state_456XX( initial_req, @t2_timer, session_pid, transport_pid )
							
						packet.response_code >= 400 and packet.response_code < 700 ->
							if session_pid != nil do: Process.send(session_pid, { :transaction_error, packet } ),
							client_transaction_state_456XX( initial_req, @t2_timer, session_pid, transport_pid )
						
						# Ignore the rest
						true -> client_transaction_state_0XX( initial_req, t1_value, session_pid, transport_pid )
					end
					
				# T2 expired
				until t2_value -> 
					if session_pid != nil do: Process.send(session_pid, { :transaction_close, :t2_timeout, 408 } ),
					client_transaction_state_456XX( initial_req, @t2_timer, session_pid, transport_pid )
					
				true -> client_transaction_state_0XX( packet, t1_value*2 )
			end
		end		
end	
			
		
			
	