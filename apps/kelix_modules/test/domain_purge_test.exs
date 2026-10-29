defmodule Kelix.DomainPurgeTest do
  # async: false — the registrar, presence, Kelix.Domains and the module registry
  # are singletons.
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias Kelix.Control
  alias Kelix.Mod.{Presence, Registrar}

  @domains """
  [[domain]]
  name = "kept.example"

  [[domain]]
  name = "gone.example"
  aliases = ["alias.example"]
  """

  # A registrar that is loaded but whose purge fails, as a module that times out.
  defmodule FailingRegistrar do
    def purge_domain(_domain), do: {:error, :timeout}
  end

  setup do
    %{path: path} = Kelix.Test.Fixtures.serve_domains(@domains)
    prev = Application.get_env(:kelixip, :domains_path)
    Application.put_env(:kelixip, :domains_path, path)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:kelixip, :domains_path, prev),
        else: Application.delete_env(:kelixip, :domains_path)
    end)

    start_supervised!({Registrar, []})
    start_supervised!({Presence, []})
    Kelix.Test.Fixtures.with_module("registrar", Registrar)
    Kelix.Test.Fixtures.with_module("presence", Presence)

    for domain <- ["gone.example", "kept.example"] do
      {:registered, _} = Registrar.save(register("bob", domain), domain)
      {:ok, _, _} = Presence.publish(domain, publication("bob", domain))
    end

    %{path: path}
  end

  defp register(user, domain) do
    %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: user, domain: domain},
      ruri: %SIP.Uri{
        userpart: user,
        domain: domain,
        destip: {1, 2, 3, 4},
        destport: 5060,
        destproto: "UDP",
        tp_pid: self()
      },
      contact: %SIP.Uri{userpart: user, domain: "10.0.0.9", port: 5060},
      expires: 3600,
      callid: "call-#{domain}"
    }
  end

  defp publication(user, domain) do
    %SIP.Publication{
      username: user,
      domain: domain,
      event: "presence",
      operation: :initial,
      content_type: "application/pidf+xml",
      body: "<presence/>",
      doc: SIP.Presence.Doc.new("sip:#{user}@#{domain}", :open),
      sender: "sip:#{user}@#{domain}"
    }
    |> SIP.Publication.grant(3600)
  end

  defp invite(domain),
    do: %{method: :INVITE, ruri: %SIP.Uri{userpart: "bob", domain: domain}, callid: "x"}

  defp held?(domain),
    do: Registrar.bindings(domain, "bob") != [] or Presence.presentities(domain) != []

  test "a delete drops the domain's bindings and published states, and only them" do
    :ok = Registrar.subscribe_registrations("gone.example", self())

    capture_log(fn ->
      assert {:ok, %{purged: %{"registrar" => {:ok, 1}, "presence" => {:ok, 1}}}} =
               Control.delete_domain("gone.example", actor: "alice")
    end)

    refute held?("gone.example")
    assert Registrar.lookup(invite("gone.example")) == :notfound
    assert_receive {:kelix_registrations, "gone.example", {:remove, "bob"}}

    assert held?("kept.example")
  end

  test "a domain created again starts empty, even after a purge that failed" do
    Kelix.Test.Fixtures.with_module("registrar", FailingRegistrar)

    capture_log(fn ->
      assert {:ok, %{purged: %{"registrar" => {:error, :timeout}, "presence" => {:ok, 1}}}} =
               Control.delete_domain("gone.example")
    end)

    # the leftover the failed purge kept
    assert Registrar.bindings("gone.example", "bob") != []

    Kelix.Test.Fixtures.with_module("registrar", Registrar)

    capture_log(fn ->
      assert {:ok, %{created: true}} = Control.put_domain(%{"name" => "gone.example"})
    end)

    refute held?("gone.example")
  end

  test "a reload that removes the domain purges it as a delete does", %{path: path} do
    File.write!(path, ~s([[domain]]\nname = "kept.example"\n))
    capture_log(fn -> assert :ok = Control.reload_domains() end)

    refute held?("gone.example")
    assert held?("kept.example")
  end

  test "replacing a domain keeps its state" do
    capture_log(fn ->
      assert {:ok, %{created: false}} =
               Control.put_domain(%{"name" => "gone.example", "max_calls" => 2})
    end)

    assert held?("gone.example")
  end
end
