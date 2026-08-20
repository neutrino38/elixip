defmodule Kelix.Mod.McuControlRestTest do
  @moduledoc """
  The MCU control surface as a **client** meets it: the real `Kelix.ControlAPI`
  routing the real `Kelix.Mod.Mcu` declarations (docs/design/DESIGN-KELIXIP.md#7-the-module-system
  + FW-4).

  It lives with the module because it needs both halves — the core frontal and the
  module that declares the resource tree — and it is what proves the two agree:
  the canonical URLs, the `201 Created` + `Location`, the `409` on an exhausted
  range, and the flat form still answering (§8.3.5).
  """
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  alias Kelix.Mcu.TestStub
  alias Kelix.Mod.Mcu
  alias Kelix.Mod.Mcu.{Client, Config}

  # The media servers the module drives now come from [mediaserver.pool.*], decoded
  # by Kelix.Config; the registry takes the resulting list directly so a test needs
  # no config file.
  @mediaservers [%{name: "mcu1", url: "http://127.0.0.1:18080"}]

  @opts Kelix.ControlAPI.init([])
  @domain "example.com"

  setup do
    prev = Application.get_env(:kelixip, :control_api)
    Application.put_env(:kelixip, :control_api, %{auth: "none"})

    {:ok, config} =
      Config.parse(%{
        "did_range" => "8000-8001"
      })

    start_supervised!({Mcu, config: config, module_name: "mcu", mediaservers: @mediaservers})

    start_supervised!(
      {Client,
       name: "mcu1",
       base_url: "http://127.0.0.1:18080",
       transport: TestStub.transport(self()),
       register: {Mcu, "mcu1"},
       reconnect_ms: 0},
      id: :client_mcu1
    )

    # the module is reachable by its configured name, and its declared commands are
    # published exactly as Kelix.ModuleSupervisor would at boot
    Kelix.Test.Fixtures.with_module("mcu", Mcu)
    :ok = Kelix.Control.Registry.register("mcu", Mcu.describe_control())

    wait_for_client()

    on_exit(fn ->
      Kelix.Control.Registry.deregister("mcu")

      if prev,
        do: Application.put_env(:kelixip, :control_api, prev),
        else: Application.delete_env(:kelixip, :control_api)
    end)

    :ok
  end

  defp wait_for_client(attempts \\ 100) do
    case Mcu.mediaserver("mcu1") do
      {:ok, %{status: :up, client: pid}} when is_pid(pid) ->
        :ok

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_for_client(attempts - 1)

      _ ->
        flunk("the mcu1 client never came up")
    end
  end

  defp call(conn), do: Kelix.ControlAPI.call(conn, @opts)
  defp body(conn), do: Jason.decode!(conn.resp_body)
  defp result(conn), do: body(conn)["result"]

  defp post_json(path, params) do
    conn(:post, path, Jason.encode!(params))
    |> put_req_header("content-type", "application/json")
    |> call()
  end

  defp create_conference(params \\ %{domain: @domain}) do
    conn = post_json("/modules/mcu/conferences", params)
    {conn, result(conn)}
  end

  test "POST /modules/mcu/conferences answers 201 + Location and the effective DID" do
    {conn, result} = create_conference(%{domain: @domain, name: "Sales weekly"})

    assert conn.status == 201
    uid = result["uid"]
    assert get_resp_header(conn, "location") == ["/modules/mcu/conferences/#{uid}"]
    # the response always carries the DID the client must dial (§8.3.3)
    assert result["did"] == "8000"
    assert result["conf_id"] == 42
    assert result["mcu"] == "mcu1"
  end

  test "GET the collection, then the item, then DELETE it" do
    {_conn, %{"uid" => uid}} = create_conference()

    listing = call(conn(:get, "/modules/mcu/conferences"))
    assert listing.status == 200
    assert [%{"uid" => ^uid, "did" => "8000"}] = result(listing)

    shown = call(conn(:get, "/modules/mcu/conferences/#{uid}"))
    assert shown.status == 200
    assert result(shown)["participants"] == []

    deleted = call(conn(:delete, "/modules/mcu/conferences/#{uid}"))
    assert deleted.status == 200

    assert call(conn(:get, "/modules/mcu/conferences/#{uid}")).status == 404
  end

  test "the DID filter is a query parameter, not a second URL (§8.3.3)" do
    {_conn, %{"uid" => uid}} = create_conference()
    {_conn, _other} = create_conference(%{domain: "other.example.com", did: "9001"})

    filtered = call(conn(:get, "/modules/mcu/conferences?domain=#{@domain}&did=8000"))
    assert filtered.status == 200
    assert [%{"uid" => ^uid}] = result(filtered)

    assert [] = result(call(conn(:get, "/modules/mcu/conferences?did=7777")))
  end

  test "an exhausted allocation range is a 409, a duplicate DID a 400" do
    assert {%{status: 201}, _} = create_conference()
    assert {%{status: 201}, _} = create_conference()

    exhausted = post_json("/modules/mcu/conferences", %{domain: @domain})
    assert exhausted.status == 409
    assert body(exhausted)["error"] == "no_did_available"

    duplicate = post_json("/modules/mcu/conferences", %{domain: @domain, did: "8000"})
    assert duplicate.status == 400
    assert body(duplicate)["error"] == "did_in_use"
  end

  # The same conference through the other frontal: `kelictl mcu conference.list`
  # is a table of the declared columns, `conference.show` a labelled detail view
  # with the enum integers translated (hd720p, 3x3…) — not an inspect/1 dump.
  test "kelictl renders the list as a table and the detail with human enum names" do
    {_conn, %{"uid" => uid}} = create_conference(%{domain: @domain, name: "Sales weekly"})

    {0, out} = Kelix.Control.CLI.run(["mcu", "conference.list"], node())
    [header, row] = String.split(out, "\n")
    assert header =~ ~r/^name\s+domain\s+did\s+uid\s+max_participants\s+created_at$/
    assert row =~ ~r/^Sales weekly\s+example\.com\s+8000\s+#{uid}\s+20\s+\d{4}-\d\d-\d\d /

    {0, out} = Kelix.Control.CLI.run(["mcu", "conference.show", "uid=#{uid}"], node())
    assert out =~ ~r/^Name:\s+Sales weekly$/m
    assert out =~ ~r/^Domain:\s+example\.com$/m
    # the wire integers read as what they mean (video/layout sizes, mosaic, vad)
    assert out =~ ~r/^Video:\s+.*size=hd720p/m
    assert out =~ ~r/^Layout:\s+auto=true comp=2x2 size=hd720p$/m
    assert out =~ ~r/^Vad:\s+basic$/m
    # what the conference answers, which is what the codec lists used to say sideways
    assert out =~ ~r/^Medias:\s+audio, video, text$/m
    assert out =~ ~r/^Dtmf:\s+true$/m
  end

  # The CLI render hints ride the same declaration the REST discovery serves: they
  # must stay JSON-encodable (string paths, string enum keys) or GET /modules dies.
  test "GET /modules/mcu publishes the render hints, JSON-encodable" do
    conn = call(conn(:get, "/modules/mcu"))
    assert conn.status == 200

    commands = body(conn)["commands"]
    list = Enum.find(commands, &(&1["name"] == "conference.list"))
    show = Enum.find(commands, &(&1["name"] == "conference.show"))

    assert list["render"]["kind"] == "table"
    assert list["render"]["columns"] == ~w(name domain did uid max_participants created_at)
    assert show["render"]["labels"]["video.size"]["6"] == "hd720p"
    assert show["render"]["labels"]["layout.comp"]["2"] == "3x3"
  end

  test "an unknown mediaserver name is a 400, a missing domain too" do
    assert post_json("/modules/mcu/conferences", %{domain: @domain, mcu: "ghost"}).status == 400
    assert post_json("/modules/mcu/conferences", %{}).status == 400
  end

  test "deleting an unknown conference is a 404" do
    assert call(conn(:delete, "/modules/mcu/conferences/c-ghost")).status == 404
  end

  test "the reserved sub-resources answer 404 (§8.3.3: never half-working)" do
    {_conn, %{"uid" => uid}} = create_conference()

    for path <- ["mosaics", "mosaics/0", "mixers", "mixers/0", "listeners"] do
      assert call(conn(:get, "/modules/mcu/conferences/#{uid}/#{path}")).status == 404
    end

    # the participant collection, by contrast, is served — and empty
    listing = call(conn(:get, "/modules/mcu/conferences/#{uid}/participants"))
    assert listing.status == 200
    assert result(listing) == []
  end

  test "the flat form of every command is live alongside the canonical URL (§8.3.5)" do
    flat = post_json("/modules/mcu/conference.create", %{domain: @domain})
    assert flat.status == 201
    uid = result(flat)["uid"]

    shown = call(conn(:get, "/modules/mcu/conference.show?uid=#{uid}"))
    assert shown.status == 200
    assert result(shown)["uid"] == uid
  end

  test "a method the resource does not answer is a 405 with Allow" do
    conn = call(conn(:put, "/modules/mcu/conferences"))
    assert conn.status == 405
    assert ["POST" <> _] = get_resp_header(conn, "allow")
  end
end
