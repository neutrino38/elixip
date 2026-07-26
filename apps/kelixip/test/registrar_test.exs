defmodule Kelix.Mod.RegistrarTest do
  # async: false — Kelix.Mod.Registrar is a named singleton, shared with
  # registrar_script_test; serialize to avoid concurrent start_supervised.
  use ExUnit.Case, async: false

  alias Kelix.Mod.Registrar
  alias Kelix.Mod.Registrar.Contact

  @domain "example.com"

  # An inbound REGISTER: the R-URI carries the REAL transport info (destip/port/
  # proto/tp_pid, attached by the stack), the Contact carries the UA's announced
  # (possibly private) address, and To is the AOR.
  defp register(user, contact_host, opts \\ []) do
    %{
      method: :REGISTER,
      to: %SIP.Uri{userpart: user, domain: @domain},
      ruri: %SIP.Uri{
        userpart: user,
        domain: @domain,
        destip: Keyword.get(opts, :destip, {1, 2, 3, 4}),
        destport: Keyword.get(opts, :destport, 5060),
        destproto: "UDP",
        tp_pid: Keyword.get(opts, :flow, self())
      },
      contact: %SIP.Uri{userpart: user, domain: contact_host, port: 5060},
      expires: Keyword.get(opts, :expires, 3600),
      callid: Keyword.get(opts, :callid, "call-1")
    }
  end

  setup do
    pid = start_supervised!({Registrar, max_contacts_per_aor: 2})
    %{pid: pid}
  end

  describe "save/4" do
    test "registers a contact and returns the granted expires" do
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert granted.aor == "alice"
      assert granted.expires == 3600
      assert [%Contact{}] = Registrar.bindings(@domain, "alice")
    end

    test "AOR is the To user-part, case-insensitive" do
      assert {:ok, _} = Registrar.save(register("Bob", "10.0.0.9"), @domain)
      assert [%Contact{}] = Registrar.bindings(@domain, "bob")
    end

    test "clamps a too-long expires to the max" do
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.9", expires: 99_999), @domain)
      assert granted.expires == 3600
    end

    test "rejects an expires below the minimum" do
      assert {:error, {423, _}} = Registrar.save(register("alice", "10.0.0.9", expires: 30), @domain)
    end

    test "a refresh of the same contact does not duplicate the binding" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert [_one] = Registrar.bindings(@domain, "alice")
    end

    test "a second distinct contact adds a binding" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.42"), @domain)
      assert length(Registrar.bindings(@domain, "alice")) == 2
    end

    test "exceeding max_contacts_per_aor is rejected" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.2"), @domain)
      assert {:error, {403, _}} = Registrar.save(register("alice", "10.0.0.3"), @domain)
    end

    test "unregister (expires 0) removes the AOR" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.9", expires: 0), @domain)
      assert granted.expires == 0
      assert Registrar.bindings(@domain, "alice") == []
    end

    test "domains are stored separately" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), "example.com")
      assert {:ok, _} = Registrar.save(%{register("alice", "10.0.0.9") | to: %SIP.Uri{userpart: "alice", domain: "other.net"}}, "other.net")
      assert length(Registrar.bindings("example.com", "alice")) == 1
      assert length(Registrar.bindings("other.net", "alice")) == 1
      # removing from one leaves the other
      Registrar.save(register("alice", "10.0.0.9", expires: 0), "example.com")
      assert Registrar.bindings("example.com", "alice") == []
      assert length(Registrar.bindings("other.net", "alice")) == 1
    end
  end

  describe "lookup/1 — NAT/flow rewrite" do
    test "rewrites the R-URI to the contact with the real received dest + flow" do
      flow = self()
      Registrar.save(register("alice", "10.0.0.9", destip: {8, 8, 8, 8}, destport: 6000, flow: flow), @domain)

      invite = %{method: :INVITE, ruri: %SIP.Uri{userpart: "alice", domain: @domain}}
      assert {:ok, [rewritten]} = Registrar.lookup(invite)
      # R-URI is now the stored Contact...
      assert rewritten.ruri.domain == "10.0.0.9"
      # ...but destination is the REAL received source + flow, not the Contact host
      assert rewritten.ruri.destip == {8, 8, 8, 8}
      assert rewritten.ruri.destport == 6000
      assert rewritten.ruri.tp_pid == flow
    end

    test "returns one rewritten request per contact" do
      Registrar.save(register("alice", "10.0.0.9"), @domain)
      Registrar.save(register("alice", "10.0.0.42"), @domain)
      assert {:ok, reqs} = Registrar.lookup(%{method: :INVITE, ruri: %SIP.Uri{userpart: "alice", domain: @domain}})
      assert length(reqs) == 2
    end

    test "unknown AOR → :notfound" do
      assert :notfound = Registrar.lookup(%{method: :INVITE, ruri: %SIP.Uri{userpart: "ghost", domain: @domain}})
    end
  end

  describe "subscribe_register_event/2" do
    test "delivers registered / unregistered events" do
      uri = %SIP.Uri{userpart: "alice", domain: @domain}
      assert :ok = Registrar.subscribe_register_event(uri, self())

      Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert_receive {:registrar, :registered, "alice@example.com"}

      Registrar.save(register("alice", "10.0.0.9", expires: 0), @domain)
      assert_receive {:registrar, :unregistered, "alice@example.com"}
    end

    test "can subscribe before the AOR exists, and unsubscribe stops events" do
      uri = %SIP.Uri{userpart: "bob", domain: @domain}
      Registrar.subscribe_register_event(uri, self())
      Registrar.unsubscribe_register_event(uri, self())
      Registrar.save(register("bob", "10.0.0.9"), @domain)
      refute_receive {:registrar, :registered, _}, 100
    end
  end

  describe "auto-invalidation" do
    test "a dropped connected flow (dead dialog) invalidates the binding + emits :disconnected" do
      uri = %SIP.Uri{userpart: "alice", domain: @domain}
      Registrar.subscribe_register_event(uri, self())

      flow = spawn(fn -> Process.sleep(:infinity) end)
      Registrar.save(register("alice", "10.0.0.9"), @domain, flow)
      assert [_one] = Registrar.bindings(@domain, "alice")

      Process.exit(flow, :kill)
      assert_receive {:registrar, :disconnected, "alice@example.com"}, 1000
      assert Registrar.bindings(@domain, "alice") == []
    end

    test "the periodic sweep removes expired bindings + emits :expired" do
      # a dedicated registrar with a low minimum and a fast sweep
      stop_supervised!(Registrar)
      start_supervised!({Registrar, min_expires: 1, sweep_ms: 150})

      uri = %SIP.Uri{userpart: "carol", domain: @domain}
      Registrar.subscribe_register_event(uri, self())
      Registrar.save(register("carol", "10.0.0.9", expires: 1), @domain)
      assert [_one] = Registrar.bindings(@domain, "carol")

      assert_receive {:registrar, :expired, "carol@example.com"}, 2000
      assert Registrar.bindings(@domain, "carol") == []
    end
  end
end
