defmodule Kelix.Mod.DialogStateTest do
  @moduledoc """
  The call occupancy of a served AOR (docs/design/dialog-state-plan.md, DS5):
  what a stamped dialog's transitions become — a dialog row pushed to the ACD,
  and two documents reported to presence — and the resync after either side
  restarts.

  The dialogs are stand-in processes pushing what `SIP.Dialog.Events` pushes,
  except for the resync, which reads a real dialog over the mockup transport.
  The watcher is the test process, registered on the resources the way a
  notifier instance is: what presence pushes to it is what a SUBSCRIBE dialog
  would be NOTIFYed.
  """
  use ExUnit.Case, async: false
  import SIP.Test.Wait

  alias Kelix.Mod.{DialogState, Presence}
  alias SIP.Test.Peers.Manual
  alias SIP.Test.Transport.Mockup

  @domain "dialogstate.example"
  @bob_calls {"bob", @domain, "dialog"}
  @bob_presence {"bob", @domain, "presence"}

  setup do
    Kelix.Test.Fixtures.serve_domains("""
    [[domain]]
    name = "dialogstate.example"
    aliases = ["dialogstate.example.org"]

      [[domain.presence]]
      event-package = "presence"
      subscribe = "presence-subscribe.exs"

      [[domain.presence]]
      event-package = "dialog"
      subscribe = "presence-subscribe.exs"
    """)

    Application.put_env(:kelixip, :authdb_ha1_lookup, fn
      user, @domain when user in ["alice", "bob"] -> {:ok, "0123456789abcdef0123456789abcdef"}
      _user, _realm -> :notfound
    end)

    on_exit(fn -> Application.delete_env(:kelixip, :authdb_ha1_lookup) end)
    start_supervised!(Presence)
    :ok
  end

  defp start_module(opts \\ []),
    do: start_supervised!({DialogState, Keyword.merge([retry_ms: 20], opts)})

  # ── stand-in dialogs ─────────────────────────────────────────────────────────

  defp fake_dialog() do
    pid = spawn(fn -> Process.sleep(:infinity) end)
    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end

  # What SIP.Dialog.Events pushes. `:inbound` is a call the AOR placed (it
  # reached us), `:outbound` one it receives (we dialled it).
  defp info(callid, direction, state, opts \\ []) do
    aor = Keyword.get(opts, :aor, "bob")

    %{
      callid: callid,
      fromtag: "ftag-" <> callid,
      totag: if(state == :trying, do: nil, else: "ttag-" <> callid),
      direction: direction,
      method: :INVITE,
      state: state,
      event: Keyword.get(opts, :event),
      remote_aor: %SIP.Uri{
        scheme: "sip:",
        userpart: aor,
        domain: Keyword.get(opts, :domain, @domain)
      },
      from: %SIP.Uri{userpart: Keyword.get(opts, :from, "alice"), domain: @domain},
      to: %SIP.Uri{userpart: Keyword.get(opts, :to, aor), domain: @domain},
      ruri: nil,
      created_at: Keyword.get(opts, :created_at, DateTime.utc_now()),
      confirmed_at: if(state == :confirmed, do: DateTime.utc_now())
    }
  end

  defp push(dialog, info), do: send(DialogState, {:sip_dialog, dialog, info})

  # A round trip through the module, so every push sent before it is handled.
  defp settle(), do: DialogState.dialogs(@domain)

  # ── the watcher ──────────────────────────────────────────────────────────────

  defp watch(user, package) do
    sub =
      %SIP.Subscription{
        callid: "watch-#{user}-#{package}",
        event: package,
        presentity_uri: "sip:#{user}@#{@domain}",
        watcher_username: "carol",
        watcher_domain: @domain
      }
      |> SIP.Subscription.put_status(:active)
      |> SIP.Subscription.grant(3600)

    {:ok, doc} = Presence.watch(@domain, sub)
    doc
  end

  defp states(%SIP.DialogInfo.Doc{dialogs: dialogs}), do: Enum.map(dialogs, & &1.state)

  describe "a dialog's transitions" do
    test "become one dialog-info document, and on-the-phone while confirmed" do
      start_module()
      assert %SIP.DialogInfo.Doc{dialogs: []} = watch("bob", "dialog")
      assert watch("bob", "presence") == nil

      dlg = fake_dialog()
      push(dlg, info("c1", :outbound, :trying))
      assert_receive {:presence, :state, @bob_calls, doc}
      assert states(doc) == [:trying]
      assert [%SIP.DialogInfo.Dialog{} = d] = doc.dialogs
      assert d.direction == :recipient
      assert d.call_id == "c1"
      assert d.local_tag == nil
      assert d.remote_tag == "ftag-c1"
      assert d.local.identity == "sip:bob@dialogstate.example"
      assert d.remote.identity == "sip:alice@dialogstate.example"

      # ringing is not on the phone: the presence is not touched
      push(dlg, info("c1", :outbound, :early))
      assert_receive {:presence, :state, @bob_calls, doc}
      assert states(doc) == [:early]
      refute_receive {:presence, :state, @bob_presence, _}, 100

      push(dlg, info("c1", :outbound, :confirmed))
      assert_receive {:presence, :state, @bob_calls, doc}
      assert states(doc) == [:confirmed]
      assert_receive {:presence, :state, @bob_presence, presence}
      assert SIP.Presence.Doc.status(presence) == :open
      assert presence.activity == :on_the_phone

      # the end: the empty document of an idle subscriber, and no presence of ours
      push(dlg, info("c1", :outbound, :terminated, event: :remote_bye))
      assert_receive {:presence, :state, @bob_calls, %SIP.DialogInfo.Doc{dialogs: []}}
      assert_receive {:presence, :state, @bob_presence, nil}
      assert settle() == []
    end

    test "a call the AOR placed reads initiator, the callee as the remote party" do
      start_module()
      watch("bob", "dialog")

      push(fake_dialog(), info("c2", :inbound, :early, from: "bob", to: "dave"))
      assert_receive {:presence, :state, @bob_calls, %{dialogs: [d]}}
      assert d.direction == :initiator
      assert d.local_tag == "ftag-c2"
      assert d.remote_tag == "ttag-c2"
      assert d.remote.identity == "sip:dave@dialogstate.example"
    end

    # Decision 5: presence keeps one reported document per source, so the module
    # aggregates — "latest wins" would drop the waiting call.
    test "two calls of one AOR are two dialogs of one document" do
      start_module()
      watch("bob", "dialog")
      t0 = DateTime.utc_now()

      push(fake_dialog(), info("c1", :outbound, :confirmed, created_at: t0))
      assert_receive {:presence, :state, @bob_calls, _one}

      second = fake_dialog()
      push(second, info("c2", :outbound, :early, created_at: DateTime.add(t0, 1)))
      assert_receive {:presence, :state, @bob_calls, doc}
      assert Enum.map(doc.dialogs, & &1.id) == ["c1", "c2"]
      assert states(doc) == [:confirmed, :early]

      push(second, info("c2", :outbound, :terminated, event: :cancelled))
      assert_receive {:presence, :state, @bob_calls, doc}
      assert Enum.map(doc.dialogs, & &1.id) == ["c1"]
    end

    test "a transition that changes no document costs no report" do
      start_module()
      watch("bob", "presence")
      first = fake_dialog()
      push(first, info("c1", :outbound, :confirmed))
      assert_receive {:presence, :state, @bob_presence, %{activity: :on_the_phone}}

      # a second confirmed call leaves bob on the phone: nothing to say
      push(fake_dialog(), info("c2", :inbound, :confirmed))
      refute_receive {:presence, :state, @bob_presence, _}, 100
    end

    test "a call state never goes back" do
      start_module()
      watch("bob", "dialog")
      dlg = fake_dialog()
      push(dlg, info("c1", :outbound, :confirmed))
      assert_receive {:presence, :state, @bob_calls, _}

      push(dlg, info("c1", :outbound, :early))
      refute_receive {:presence, :state, @bob_calls, _}, 100
      assert [%{state: "confirmed"}] = settle()
    end

    # Decision 9: a dialog that crashes emits no terminated.
    test "a dialog that dies is a terminated one, by error" do
      start_module()
      {:ok, %{dialogs: []}} = DialogState.subscribe_dialogs(@domain, self())
      watch("bob", "dialog")
      dlg = fake_dialog()
      push(dlg, info("c1", :outbound, :confirmed))
      assert_receive {:presence, :state, @bob_calls, _}
      assert_receive {:kelix_dialogs, @domain, {:upsert, %{state: :confirmed}}}

      Process.exit(dlg, :kill)
      assert_receive {:kelix_dialogs, @domain, {:upsert, %{state: :terminated, event: :error}}}
      assert_receive {:kelix_dialogs, @domain, {:remove, "c1"}}
      assert_receive {:presence, :state, @bob_calls, %SIP.DialogInfo.Doc{dialogs: []}}
    end

    test "a stamp on a domain this node does not serve is not followed" do
      start_module()
      push(fake_dialog(), info("c1", :outbound, :confirmed, domain: "elsewhere.example"))
      assert settle() == []
      assert DialogState.dialogs("elsewhere.example") == []
    end

    test "a stamp naming an alias is followed under the served domain's name" do
      start_module()
      watch("bob", "dialog")
      push(fake_dialog(), info("c1", :outbound, :early, domain: "dialogstate.example.org"))
      assert_receive {:presence, :state, @bob_calls, %{entity: "sip:bob@dialogstate.example"}}
    end

    test "a domain outside the configured ones is not reported" do
      start_module(domains: MapSet.new(["other.example"]))
      watch("bob", "dialog")
      push(fake_dialog(), info("c1", :outbound, :confirmed))
      refute_receive {:presence, :state, @bob_calls, _}, 100
      assert settle() == []
    end
  end

  describe "the ACD push" do
    test "the rows as they stand, then every transition, then the removal" do
      start_module()
      dlg = fake_dialog()
      push(dlg, info("c1", :outbound, :early))

      assert {:ok, %{owner: owner, dialogs: [row]}} =
               DialogState.subscribe_dialogs(@domain, self())

      assert owner == Process.whereis(DialogState)

      assert %{
               domain: @domain,
               aor: "sip:bob@dialogstate.example",
               id: "c1",
               direction: :recipient,
               state: :early,
               remote: "sip:alice@dialogstate.example"
             } = row

      push(dlg, info("c1", :outbound, :confirmed))
      assert_receive {:kelix_dialogs, @domain, {:upsert, %{id: "c1", state: :confirmed}}}

      push(dlg, info("c1", :outbound, :terminated, event: :local_bye))

      assert_receive {:kelix_dialogs, @domain,
                      {:upsert, %{id: "c1", state: :terminated, event: :local_bye}}}

      assert_receive {:kelix_dialogs, @domain, {:remove, "c1"}}
    end

    # Registered by name as Kelix.ModuleSupervisor registers it — which this node
    # would refuse to start, its config.toml declaring no presence module.
    test "Kelix.Control reaches it by its configured name, alias included" do
      start_module()
      :ok = Kelix.ModuleRegistry.register("dialog_state", DialogState, %{})
      on_exit(fn -> Kelix.ModuleRegistry.unregister("dialog_state") end)

      assert {:ok, %{domain: @domain, owner: owner, dialogs: []}} =
               Kelix.Control.subscribe_dialogs(self(), "dialogstate.example.org")

      assert is_pid(owner)
      push(fake_dialog(), info("c1", :outbound, :trying))
      assert_receive {:kelix_dialogs, @domain, {:upsert, %{id: "c1"}}}

      :ok = Kelix.Control.unsubscribe_dialogs(self(), @domain)
      push(fake_dialog(), info("c2", :outbound, :trying))
      refute_receive {:kelix_dialogs, @domain, _}, 100
    end

    test "Kelix.Control answers an empty list when the module is not loaded" do
      assert {:ok, %{owner: nil, dialogs: []}} = Kelix.Control.subscribe_dialogs(self(), @domain)
      assert {:error, :not_found} = Kelix.Control.subscribe_dialogs(self(), "nowhere.example")
    end

    test "a subscriber that dies is dropped" do
      start_module()
      sub = spawn(fn -> Process.sleep(:infinity) end)
      {:ok, _} = DialogState.subscribe_dialogs(@domain, sub)
      Process.exit(sub, :kill)

      assert until(fn -> :sys.get_state(DialogState).subs == %{} end)
    end
  end

  describe "either side restarting" do
    test "a presence restart is a full re-report" do
      start_module()
      push(fake_dialog(), info("c1", :outbound, :confirmed))
      settle()

      stop_supervised!(Presence)
      start_supervised!(Presence)

      assert until(fn ->
               match?(%SIP.DialogInfo.Doc{dialogs: [_]}, watch("bob", "dialog")) and
                 match?(%SIP.Presence.Doc{activity: :on_the_phone}, watch("bob", "presence"))
             end)
    end

    test "presence coming up after the module is caught up with" do
      stop_supervised!(Presence)
      start_module()
      push(fake_dialog(), info("c1", :outbound, :confirmed))
      settle()

      start_supervised!(Presence)
      assert until(fn -> match?(%SIP.DialogInfo.Doc{dialogs: [_]}, watch("bob", "dialog")) end)
    end

    # The module restarted: every event before it is lost, the live dialogs are not.
    test "a module restart resyncs from the live dialogs" do
      tp = peer!("ds1")
      aor = %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain}

      {:ok, dlg, _id} =
        SIP.Dialog.start_dialog(invite_to("ds1"), 60, :outbound, false,
          tag: :outbound,
          remote_aor: aor
        )

      assert_receive {:sip_mockup, {:request_sent, :INVITE, _req}}, 2_000
      Manual.simulate(tp, 180, 0)
      assert until(fn -> SIP.Dialog.info(dlg).state == :early end)

      start_module()
      assert [%{aor: "sip:bob@dialogstate.example", state: "early"}] = settle()
      assert %SIP.DialogInfo.Doc{dialogs: [%{state: :early}]} = watch("bob", "dialog")

      # and it is followed from there: the live dialog is monitored
      Process.exit(dlg, :kill)
      assert until(fn -> settle() == [] end)
    end
  end

  describe "the control surface and the configuration" do
    test "list renders the live dialogs with the presence of their AOR" do
      start_module()
      push(fake_dialog(), info("c1", :outbound, :confirmed))

      assert {:ok, [row]} = DialogState.handle_control("list", %{"domain" => @domain})

      assert %{
               aor: "sip:bob@dialogstate.example",
               callid: "c1",
               direction: "recipient",
               state: "confirmed",
               remote: "sip:alice@dialogstate.example",
               presence: "on_the_phone"
             } = row

      assert is_binary(row.since)

      assert {:ok, [^row]} =
               DialogState.handle_control("list", %{"domain" => "DIALOGSTATE.example.org"})
    end

    test "the declared command set is routable" do
      assert :ok = Kelix.Control.Route.check_conflicts(DialogState.describe_control())
    end

    # This test node's config.toml declares no module at all.
    test "refuses a block when presence is not configured" do
      assert {:error, msg} = DialogState.validate_config(%{})
      assert msg =~ "needs the presence module"
      refute DialogState.presence_missing?(["presence"])
      assert DialogState.presence_missing?(["mcu"])
    end

    test "refuses an unknown key and a malformed domain list" do
      assert {:error, msg} = DialogState.validate_config(%{"domain" => "dialogstate.example"})
      assert msg =~ "unknown key(s): domain"

      assert {:error, msg} = DialogState.validate_config(%{"domains" => "dialogstate.example"})
      assert msg =~ "list"
    end
  end

  # ── a real dialog, over the mockup transport ─────────────────────────────────

  defp target(name) do
    %SIP.Uri{scheme: "sip:", userpart: "bob", domain: "#{name}.dialogstate.example", port: 5060}
    |> SIP.Uri.set_uri_param("unittest", name)
  end

  defp peer!(name) do
    tp = SIP.Transport.Selector.select_transport(target(name)).tp_pid
    :ok = Mockup.set_peer(tp, Manual)
    :ok = Mockup.attach_probe(tp)
    tp
  end

  defp invite_to(name) do
    %{
      "Max-Forwards" => "70",
      method: :INVITE,
      ruri: target(name),
      from: %SIP.Uri{scheme: "sip:", userpart: "alice", domain: @domain},
      to: %SIP.Uri{scheme: "sip:", userpart: "bob", domain: @domain},
      contact: %SIP.Uri{userpart: "alice", domain: "0.0.0.0", params: %{}},
      useragent: "Elixipp-test",
      callid: nil,
      contentlength: 0
    }
  end
end
