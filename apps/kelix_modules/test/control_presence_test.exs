defmodule Kelix.ControlPresenceTest do
  @moduledoc """
  Functional test of the **core ↔ module** pair behind kelescope's live presence
  panel: `Kelix.Control.subscribe_presence/2` driven through the real
  `Kelix.Mod.Presence`, reached by its configured name through
  `Kelix.ModuleRegistry.facade/4` — the model of `subscribe_registrations/2`.
  """
  # async: false — Kelix.Mod.Presence is a named singleton, and the domains are
  # the app's Domains singleton.
  use ExUnit.Case, async: false

  alias Kelix.Control
  alias Kelix.Mod.Presence

  @domain "example.com"

  setup do
    Kelix.Test.Fixtures.serve_domains("""
    [[domain]]
    name = "example.com"
    aliases = ["example.org"]

      [[domain.presence]]
      event-package = "presence"
      subscribe = "presence-subscribe.exs"
    """)

    start_supervised!(
      {Kelix.ModuleSupervisor,
       name: :"modsup_presence_#{System.unique_integer([:positive])}",
       modules: %{"presence" => %{}}}
    )

    assert %{module: Presence} = Kelix.ModuleRegistry.lookup("presence")
    on_exit(fn -> Kelix.ModuleRegistry.unregister("presence") end)
    :ok
  end

  test "returns the current presentities, matched by name or alias, then pushes changes" do
    {:ok, _etag, _} = Presence.publish(@domain, publication("alice", :open, note: "at desk"))

    assert {:ok, %{domain: "example.com", presentities: [row]}} =
             Control.subscribe_presence(self(), "example.org")

    assert %{
             aor: "alice",
             presentity_uri: "sip:alice@example.com",
             status: "open",
             note: "at desk",
             states: [%{event: "presence", etag: etag}],
             watchers: []
           } = row

    assert is_binary(etag)

    {:ok, _etag, _} = Presence.publish(@domain, publication("bob", :closed))

    assert_receive {:kelix_presence, "example.com",
                    {:upsert, %{aor: "bob", status: "closed", states: [_]}}},
                   500
  end

  test "a watcher is a row of its own, and goes with the instance that held it" do
    Control.subscribe_presence(self(), @domain)

    watcher = watcher_instance(subscription("carol", "alice"))
    assert_receive {:kelix_presence, "example.com", {:upsert, row}}, 500
    assert %{aor: "carol", states: [], watchers: [%{watcher: "sip:alice@example.com"}]} = row

    Process.exit(watcher, :kill)
    assert_receive {:kelix_presence, "example.com", {:remove, "carol"}}, 500
  end

  test "a publication that goes leaves the row while someone still watches" do
    Control.subscribe_presence(self(), @domain)

    {:ok, etag, _} = Presence.publish(@domain, publication("bob", :open))
    assert_receive {:kelix_presence, _, {:upsert, %{aor: "bob", status: "open"}}}, 500

    _watcher = watcher_instance(subscription("bob", "alice"))
    assert_receive {:kelix_presence, _, {:upsert, %{aor: "bob", watchers: [_]}}}, 500

    {:ok, nil, 0} = Presence.publish(@domain, removal("bob", etag))

    # no registrar on this domain: nothing left to say about bob's status
    assert_receive {:kelix_presence, _, {:upsert, %{aor: "bob", states: [], status: nil}}}, 500
  end

  test "kelictl presence remove is pushed as a removal" do
    {:ok, _etag, _} = Presence.publish(@domain, publication("bob", :open))
    Control.subscribe_presence(self(), @domain)

    assert {:ok, _} =
             Control.module_command("presence", "remove", %{"domain" => @domain, "aor" => "bob"})

    assert_receive {:kelix_presence, "example.com", {:remove, "bob"}}, 500
  end

  test "an unserved domain answers :not_found" do
    assert Control.subscribe_presence(self(), "ghost.example.org") == {:error, :not_found}
  end

  test "unsubscribe_presence/2 stops the pushes" do
    Control.subscribe_presence(self(), @domain)
    assert Control.unsubscribe_presence(self(), "example.org") == :ok

    Presence.publish(@domain, publication("carol", :open))
    refute_receive {:kelix_presence, _, _}, 100
  end

  test "a subscriber that dies is dropped" do
    panel = spawn(fn -> Process.sleep(:infinity) end)
    {:ok, _} = Control.subscribe_presence(panel, @domain)
    Process.exit(panel, :kill)

    assert eventually(fn -> :sys.get_state(Presence).panel_subs == %{} end)
  end

  test "without the presence module, the panel is empty, not an error" do
    Kelix.ModuleRegistry.unregister("presence")

    assert Control.subscribe_presence(self(), @domain) ==
             {:ok, %{domain: "example.com", presentities: []}}
  end

  # ── fixtures ────────────────────────────────────────────────────────────────

  defp publication(user, status, opts \\ []) do
    %SIP.Publication{
      username: user,
      domain: @domain,
      event: "presence",
      operation: :initial,
      content_type: "application/pidf+xml",
      body: "<presence/>",
      doc: SIP.Presence.Doc.new("sip:#{user}@#{@domain}", status, opts),
      sender: "sip:#{user}@#{@domain}"
    }
    |> SIP.Publication.grant(3600)
  end

  defp removal(user, etag) do
    %{publication(user, :closed) | operation: :remove, etag: etag}
    |> SIP.Publication.grant(0)
  end

  defp subscription(presentity, watcher) do
    %SIP.Subscription{
      callid: "call-#{presentity}-#{watcher}",
      to_tag: "totag",
      from_tag: "fromtag",
      event: "presence",
      presentity_uri: "sip:#{presentity}@#{@domain}",
      watcher_username: watcher,
      watcher_domain: @domain,
      to_user: presentity,
      to_domain: @domain
    }
    |> SIP.Subscription.put_status(:active)
    |> SIP.Subscription.grant(3600)
  end

  # A notifier instance: it watches, then lives until killed.
  defp watcher_instance(sub) do
    test = self()

    pid =
      spawn(fn ->
        {:ok, _doc} = Presence.watch(@domain, sub)
        send(test, :watching)
        Process.sleep(:infinity)
      end)

    assert_receive :watching, 500
    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end

  defp eventually(fun, attempts \\ 50) do
    cond do
      fun.() -> true
      attempts == 0 -> false
      true -> Process.sleep(10) && eventually(fun, attempts - 1)
    end
  end
end
