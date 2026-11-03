defmodule SIP.Test.MsgRedactor do
  @moduledoc """
  `SIPMsg.register_redactor/2`: a body type whose traces must not show it in
  clear, hidden at the one place every trace reads a message through.
  """
  use ExUnit.Case, async: false

  @type_ "application/x-secret+xml"

  setup do
    on_exit(fn -> SIPMsg.unregister_redactor(@type_) end)

    {:ok, raw} = File.read(Path.join(__DIR__, "SIP-INVITE-LVP.txt"))
    {:ok, invite} = SIPMsg.parse(raw, fn _c, _m, _l, _line -> nil end)
    part = %{contenttype: @type_ <> ";charset=utf-8", data: "<s>hunter2</s>"}
    resp = SIP.Msg.Ops.reply_to_request(%{invite | method: :INFO}, 200, "OK", body: [part])
    %{resp: resp, wire: SIPMsg.serialize(resp)}
  end

  defp shown(resp, wire) do
    [
      SIPMsg.loggable(wire),
      elem(SIPMsg.readable(resp), 0),
      elem(SIPMsg.readable(wire), 0),
      SIPMsg.serialize(SIPMsg.redacted(resp))
    ]
  end

  test "without a redactor, the body shows as it is", %{resp: resp, wire: wire} do
    for text <- shown(resp, wire), do: assert(text =~ "hunter2")
  end

  test "a registered redactor hides it everywhere, its type kept", %{resp: resp, wire: wire} do
    :ok =
      SIPMsg.register_redactor("Application/X-Secret+XML", &String.replace(&1, "hunter2", "***"))

    for text <- shown(resp, wire) do
      refute text =~ "hunter2"
      assert text =~ "<s>***</s>"
      assert text =~ @type_
    end

    # Other types are left alone, and so is the wire itself.
    assert SIPMsg.serialize(resp) =~ "hunter2"
  end

  test "a redactor that raises shows a placeholder, never the clear body", %{
    resp: resp,
    wire: wire
  } do
    :ok = SIPMsg.register_redactor(@type_, fn _ -> raise "boom" end)

    for text <- shown(resp, wire) do
      refute text =~ "hunter2"
      assert text =~ "<content not recorded: #{@type_}"
    end
  end

  test "unregistered, it shows again", %{resp: resp, wire: wire} do
    :ok = SIPMsg.register_redactor(@type_, fn _ -> "***" end)
    :ok = SIPMsg.unregister_redactor(@type_)
    assert SIPMsg.loggable(wire) =~ "hunter2"
    assert elem(SIPMsg.readable(resp), 0) =~ "hunter2"
  end
end
