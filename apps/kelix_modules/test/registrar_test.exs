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
        destproto: Keyword.get(opts, :destproto, "UDP"),
        tp_pid: Keyword.get(opts, :flow, self()),
        tp_module: Keyword.get(opts, :tp_module)
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

    # SIPMsg parses `:ruri` and `:contact` into %SIP.Uri{} but leaves `:to` as the
    # RAW header string — so this, not the struct above, is the shape a REGISTER
    # coming off the wire actually has. Matching only the struct made every real
    # registration fail with "400 Missing To user-part".
    test "AOR is extracted from a raw To header string (the on-the-wire shape)" do
      req = %{
        register("carol", "10.0.0.9")
        | to: "<sip:Carol@#{@domain}>;tag=abc123"
      }

      assert {:ok, granted} = Registrar.save(req, @domain)
      assert granted.aor == "carol"
      assert [%Contact{}] = Registrar.bindings(@domain, "carol")
    end

    test "clamps a too-long expires to the max" do
      assert {:ok, granted} =
               Registrar.save(register("alice", "10.0.0.9", expires: 99_999), @domain)

      assert granted.expires == 3600
    end

    test "rejects an expires below the minimum" do
      assert {:error, {423, _}} =
               Registrar.save(register("alice", "10.0.0.9", expires: 30), @domain)
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

    test "a wildcard Contact with Expires: 0 removes every binding" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.2"), @domain)

      wildcard = %{register("alice", "unused") | contact: :*, expires: 0}
      assert {:ok, granted} = Registrar.save(wildcard, @domain)
      assert granted.expires == 0
      assert Registrar.bindings(@domain, "alice") == []
    end

    test "a wildcard Contact without Expires: 0 is refused, bindings untouched" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      wildcard = %{register("alice", "unused") | contact: :*, expires: 3600}
      assert {:error, {400, _}} = Registrar.save(wildcard, @domain)
      assert length(Registrar.bindings(@domain, "alice")) == 1
    end

    test "a wildcard mixed with a real Contact is refused" do
      mixed = %{
        register("alice", "unused")
        | contact: [:*, %SIP.Uri{userpart: "alice", domain: "10.0.0.1"}],
          expires: 0
      }

      assert {:error, {400, _}} = Registrar.save(mixed, @domain)
    end

    test "unregister (expires 0) removes the AOR" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), @domain)
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.9", expires: 0), @domain)
      assert granted.expires == 0
      assert Registrar.bindings(@domain, "alice") == []
    end

    test "domains are stored separately" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.9"), "example.com")

      assert {:ok, _} =
               Registrar.save(
                 %{
                   register("alice", "10.0.0.9")
                   | to: %SIP.Uri{userpart: "alice", domain: "other.net"}
                 },
                 "other.net"
               )

      assert length(Registrar.bindings("example.com", "alice")) == 1
      assert length(Registrar.bindings("other.net", "alice")) == 1
      # removing from one leaves the other
      Registrar.save(register("alice", "10.0.0.9", expires: 0), "example.com")
      assert Registrar.bindings("example.com", "alice") == []
      assert length(Registrar.bindings("other.net", "alice")) == 1
    end
  end

  describe "min_expires/1" do
    test "reports the configured bound, so the script can send Min-Expires" do
      assert Registrar.min_expires() == 60
    end

    test "falls back to the default when the store is down" do
      stop_supervised!(Registrar)
      assert Registrar.min_expires() == 60
    end
  end

  describe "per-domain expiry bounds ([domain.registrar])" do
    # domains.toml's [domain.registrar] keys were parsed and validated but read by
    # nobody: the store applied its global bounds to every domain (design §16 #8).
    setup do
      dir = Path.join(System.tmp_dir!(), "kelix_bounds_#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      path = Path.join(dir, "domains.toml")
      empty = Path.join(dir, "empty.toml")
      File.write!(empty, "")

      File.write!(path, """
      [[domain]]
      name = "strict.example.com"

        [domain.registrar]
        script = "registrar.exs"
        min_expires = 120
        default_expires = 600

      [[domain]]
      name = "lax.example.com"

        [domain.registrar]
        script = "registrar.exs"
      """)

      :ok = Kelix.Domains.reload(path)
      on_exit(fn -> Kelix.Domains.reload(empty) && File.rm_rf(dir) end)
      :ok
    end

    test "the domain's min_expires overrides the store-wide one" do
      assert Registrar.min_expires("strict.example.com") == 120
      # no override on this domain → the [module.registrar] value
      assert Registrar.min_expires("lax.example.com") == 60
      # unknown domain → the store-wide value, never a crash
      assert Registrar.min_expires("nope.example.com") == 60
    end

    test "a request under the domain's min_expires is refused there and granted elsewhere" do
      req = fn domain ->
        %{
          register("alice", "10.0.0.9", expires: 100)
          | to: %SIP.Uri{userpart: "alice", domain: domain}
        }
      end

      assert {:error, {423, _}} = Registrar.save(req.("strict.example.com"), "strict.example.com")
      assert {:ok, _} = Registrar.save(req.("lax.example.com"), "lax.example.com")
    end

    test "the domain's default_expires caps what is granted" do
      req = %{
        register("alice", "10.0.0.9", expires: 3600)
        | to: %SIP.Uri{userpart: "alice", domain: "strict.example.com"}
      }

      assert {:ok, granted} = Registrar.save(req, "strict.example.com")
      assert granted.expires == 600
    end
  end

  describe "granted contacts (RFC 3261 §10.3-8)" do
    test "the 200 OK material lists every current binding, not just the refreshed one" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.2"), @domain)

      hosts = Enum.map(granted.contacts, & &1.domain) |> Enum.sort()
      assert hosts == ["10.0.0.1", "10.0.0.2"]
    end

    test "each contact carries its own remaining lifetime" do
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      assert [contact] = granted.contacts
      assert {:ok, value} = SIP.Uri.get_uri_param(contact, "expires")
      # 3600 granted, allow a second of clock drift through the GenServer call
      assert String.to_integer(value) in 3599..3600
    end

    test "an un-REGISTER grants no contact at all" do
      assert {:ok, _} = Registrar.save(register("alice", "10.0.0.1"), @domain)
      assert {:ok, granted} = Registrar.save(register("alice", "10.0.0.1", expires: 0), @domain)
      assert granted.contacts == []
    end
  end

  describe "validate_config/1" do
    test "accepts a known block" do
      assert Registrar.validate_config(%{"max_contacts_per_aor" => 5}) == :ok
    end

    test "rejects an unknown key rather than silently ignoring it" do
      assert {:error, reason} = Registrar.validate_config(%{"max_contact_per_aor" => 5})
      assert reason =~ "max_contact_per_aor"
    end
  end

  describe "lookup/1 — NAT/flow rewrite" do
    test "rewrites the R-URI to the contact with the real received dest + flow" do
      flow = self()

      Registrar.save(
        register("alice", "10.0.0.9", destip: {8, 8, 8, 8}, destport: 6000, flow: flow),
        @domain
      )

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

      assert {:ok, reqs} =
               Registrar.lookup(%{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: "alice", domain: @domain}
               })

      assert length(reqs) == 2
    end

    test "unknown AOR → :notfound" do
      assert :notfound =
               Registrar.lookup(%{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: "ghost", domain: @domain}
               })
    end

    test "the rewritten R-URI carries the flow's transport module, so it can be sent on" do
      # An inbound WSS/TCP/TLS connection: the pid alone is not enough — the
      # Selector needs to know which transport it is (§6.4).
      Registrar.save(register("alice", "10.0.0.9", tp_module: SIP.Transport.WSS), @domain)

      assert {:ok, [rewritten]} =
               Registrar.lookup(%{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: "alice", domain: @domain}
               })

      assert rewritten.ruri.tp_module == SIP.Transport.WSS
    end

    test "the Selector sends over that flow as-is — no DNS on the private contact" do
      # A browser behind NAT: nothing can be dialed *toward* it and its contact host
      # is private/unresolvable, so the binding must route onto the connection it
      # registered from. With no `received` (an inbound R-URI carries no destproto),
      # the stamped module is the only thing naming the transport.
      flow = self()

      req =
        register("alice", "192.168.1.42",
          flow: flow,
          tp_module: SIP.Transport.WSS,
          destip: nil,
          destproto: nil
        )

      Registrar.save(req, @domain)

      assert {:ok, [rewritten]} =
               Registrar.lookup(%{
                 method: :INVITE,
                 ruri: %SIP.Uri{userpart: "alice", domain: @domain}
               })

      selected = SIP.Transport.Selector.select_transport(rewritten.ruri)

      assert selected.tp_pid == flow
      assert selected.tp_module == SIP.Transport.WSS
      assert selected.destproto == "WSS"
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
