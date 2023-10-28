defmodule SIPMsgOps do
	@moduledoc "Operation on SIM message"

  defp build_via_addr( local_ip , 5060, "UDP" ) do
    "SIP/2.0/UDP " <> local_ip
  end

  defp build_via_addr( local_ip , 5060, "TCP" ) do
    "SIP/2.0/TCP " <> local_ip
  end

  defp build_via_addr( local_ip , 5061, "TLS" ) do
    "SIP/2.0/TLS " <> local_ip
  end

  defp build_via_addr( local_ip , local_port, transport ) when is_integer(local_port) do
    if local_port < 1000 or local_port > 65535 do
      # Un port non privilegié UDP ou TCP est compris entre 1000 et 65535
      raise "Invalid port #{local_port} for via header"
    end

    if String.capitalize(transport) not in ["UDP", "TCP", "TLS", "WS", "WSS"] do
      raise "Invalid transport #{transport} for via header"
    end

    "SIP/2.0/" <> String.capitalize(transport) <> " " <> local_ip <> ":" <> Integer.to_string(local_port)
  end

  @doc "Add a tomost via"
  def add_via(sipmsg, { local_ip, local_port, transport }, branch_id, additional_params \\ nil) when is_bitstring(branch_id) do
    via = build_via_addr(local_ip, local_port, transport)
    via = cond do
      is_bitstring(additional_params) -> via <> additional_params <> ";branch=" <> branch_id
      additional_params == nil -> via <> ";branch=" <> branch_id
      #To do add, list of tuples and maps
    end

    Map.put(sipmsg, :via, [ via | sipmsg.via ])
  end

  @doc "Génère une valeur aléatoire pour le paramètre branch"
  def generate_branch_value() do
    # Génère une chaîne aléatoire de 20 caractères en ajoutant le numéro aléatoire
    random_branch = :crypto.strong_rand_bytes(10) |> Base.encode16
    branch_value = String.replace(random_branch, ~r/[^a-f0-9]/, "")

    # Assurez-vous que la chaîne commence par "z9hG4bK" comme requis par RFC 3261
    "z9hG4bK" <> branch_value
  end

  @doc "Met a jour ou ajout des champs dans un message SIP"
  def update_sip_msg(sipmsg, fields) when is_list(fields) do
    Enum.reduce(fields, sipmsg, fn {header, value}, acc ->
      update_sip_msg(acc, { header, value})
    end)
  end

  # Ignore update
  def update_sip_msg(sipmsg, { _header, :ignore }) do
    sipmsg
  end

  def update_sip_msg(sipmsg, { header, value }) do
    sipmsg |> Map.put(header, value)
  end

  @doc "Crée un message CANCEL à partir d'une requête existante"
  def cancel_request(sipmsg) when is_map(sipmsg) and is_atom(sipmsg.method) do
    cancel_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    fieldlist = [
      {:method, :CANCEL},
      {:contentlength, 0},
      {:body, []}]

    sipmsg |> update_sip_msg(fieldlist) |> Map.filter(cancel_filter)
  end

  def cancel_request(sipmsg) do
    raise "passed argument is not a SIP request"
    sipmsg
  end

  @doc "Build a SIP reply given a SIP request"
  def reply_to_request(req, resp_code, reason) when is_atom(req.method) and resp_code in 100..199 do
    resp_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    fieldlist = [
      {:method, false},
      {:contentlength, 0},
      {:reason, reason},
      {:response_code, resp_code},
      {:body, []}]

    req |> update_sip_msg(fieldlist) |> Map.filter(resp_filter)
  end

  def reply_to_request(req, resp_code, reason) when is_atom(req.method) and resp_code in 400..699 do
    resp_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    fieldlist = [
      {:method, false},
      {:contentlength, 0},
      {:reason, reason},
      {:response_code, resp_code},
      {:body, []}]

    req |> update_sip_msg(fieldlist) |> Map.filter(resp_filter)
  end

  @doc "Crée un message ACK à partir d'une requête existante"
  def ack_request(sipmsg, remote_contact, routeset \\ :ignore , body \\ []) when is_map(sipmsg) and sipmsg.method in [:INVITE, :UPDATE] do
    ack_filter = fn { k, _v } ->
      k in [ :via, :to, :from, :route, "Max-Forward", :cseq, :callid, :contentlength ]
    end

    # update fields
    fieldlist = [
      {:method, :ACK},
      {:ruri, remote_contact},
      {:route, routeset},
      {:contentlength, 0},
      {:body, body}]

    # Update message
    sipmsg |> update_sip_msg(fieldlist) |> Map.filter(ack_filter)
  end

  defmacro is_1xx_resp(msg) do
    quote do
      unquote(msg).method == false and unquote(msg).response_code in 100..199
    end
  end

  defmacro is_2xx_resp(msg) do
    quote do
      unquote(msg).method == false and unquote(msg).response_code in 200..299
    end
  end

  defmacro is_3xx_resp(msg) do
    quote do
      unquote(msg).method == false and unquote(msg).response_code in 300..399
    end
  end

  defmacro is_failure_resp(msg) do
    quote do
      unquote(msg).method == false and unquote(msg).response_code in 400..699
    end
  end

end
