defmodule SIP.MsgTemplate do
  require EEx
  require SIP.NetUtils

  defp add_default_bindings( bindings) do
    bindings
  end

  @doc "Generate a SIP message string from a template"
  def apply(msgemplate, bindings \\ []) do
    bindings = add_default_bindings( bindings)

    # Split headers an bodies. Compute content length
    [ headers, body, clen ] = case String.split(msgemplate, "\n\n", parts: 2) do
      [ headers, body ] ->
        body = EEx.eval_string( body, bindings )
        body = Regex.replace(~r/\n(?<!\r\n)/, body, "\r\n")
        [ headers, body, Kernel.byte_size(body) + 2 ]

      [ headers ] -> [ headers, nil, 0 ]
    end

    # Apply header template
    headers = EEx.eval_string( headers, bindings ++ [ :content_length, clen ] )
    headers = Regex.replace(~r/\n(?<!\r\n)/, headers, "\r\n")
    if is_nil(body) do
      headers
    else
      headers <> "\r\n\r\n" <> body
    end
  end

  def apply_and_build(msgemplate, fn_parse_cb, bindings \\ []) do
    apply(msgemplate, bindings) |> SIPMsg.parse(fn_parse_cb)
  end
end
