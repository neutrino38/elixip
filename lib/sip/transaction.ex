#---------------- SIP TRANSACTION LAYER ---------------------
defmodule SIP.Transaction do
		@moduledoc """
		SIP transaction layer. Each transaction is a process (and a state machine). It communcate
		with two other processes: a transport process that is in charge of sending or receiveing
		packets and a session level process that receives SIP messages once processed by the transaction
		layer. It handles the retransmission in case on unreliable transport
		"""
		
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
			
			via = %SIP.URI{}
			
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
		
		def message_match?( packet, cseqs  ) do
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
end	
			
		
			
	