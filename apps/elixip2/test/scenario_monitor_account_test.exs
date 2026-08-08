defmodule SIP.Test.ScenarioMonitorAccount do
  use ExUnit.Case, async: false

  @moduledoc """
  What the monitor's `account` column holds when a scenario says nothing about it
  (`SIP.Scenario.Runner`, feeding `kelictl monitor` and `elixipp --monitor`).

  The rule applies to **UAS instances only**: an instance spawned with the request
  that created it shows the identity that request asserts, because its own `config`
  username — if it even has one — is the same string on every row and answers
  nothing. A UAC keeps showing its own account.

  "UAS" is decided on the inbound request rather than on the `uas` annotation: the
  annotation is what makes `elixipp` open listeners, and the kelixip server scripts
  (mcu.exs, registrar.exs, …) carry none — the server knows they serve inbound
  traffic from `domains.toml`. Hence the fixtures below: the same scenario, with
  and without an inbound request.
  """

  defmodule Fixture do
    use SIP.Scenario

    # a local account, as a UAC scenario has — the point is that a UAS instance of
    # this same scenario does NOT show it
    config(username: "alice", domain: "example.com")

    state initial_state do
      scenario_success("done")
    end
  end

  # A UAS scenario that names the identity it serves itself, as the registrar
  # (the AOR it bound) and an MCU call (the conference DID) do.
  defmodule Noting do
    use SIP.Scenario

    config(username: "alice", domain: "example.com")

    state initial_state do
      SIP.Scenario.Monitor.note_account("900012345")
      goto(next)
    end

    state second do
      scenario_success("done")
    end
  end

  setup do
    {:ok, _pid} = SIP.Scenario.Monitor.start()
    slot = System.unique_integer([:positive])
    on_exit(fn -> SIP.Scenario.Monitor.clear(slot) end)
    {:ok, slot: slot}
  end

  defp account(slot) do
    Enum.find_value(SIP.Scenario.Monitor.calls(), fn row ->
      if row.slot == slot, do: row.account
    end)
  end

  defp invite(fields), do: Map.merge(%{method: :INVITE, ruri: %SIP.Uri{}}, Map.new(fields))

  test "a UAC instance shows its own account", %{slot: slot} do
    assert :ok = SIP.Scenario.Runner.run_instance(Fixture, slot_id: slot)
    assert account(slot) == "alice"
  end

  test "a UAS instance shows the identity the inbound request asserts", %{slot: slot} do
    req = invite(%{"P-Asserted-Identity" => "sip:+33970260233@example.com"})

    assert :ok = SIP.Scenario.Runner.run_instance(Fixture, slot_id: slot, inbound_request: req)
    assert account(slot) == "+33970260233"
  end

  test "a UAS instance whose request asserts nothing falls back to the local account",
       %{slot: slot} do
    req = invite(%{from: "sip:example.com"})

    assert :ok = SIP.Scenario.Runner.run_instance(Fixture, slot_id: slot, inbound_request: req)
    assert account(slot) == "alice"
  end

  # The identity is resolved ONCE, at spawn: what the script notes afterwards is
  # what the operator sees. Reporting the resolved identity again on every
  # transition would silently undo note_account/1 one state later.
  test "what the script notes survives the transitions that follow", %{slot: slot} do
    req = invite(%{"P-Asserted-Identity" => "sip:+33970260233@example.com"})

    assert :ok = SIP.Scenario.Runner.run_instance(Noting, slot_id: slot, inbound_request: req)
    assert account(slot) == "900012345"
  end

  # Only a request names a sender. Nothing hands a response to a UAS instance
  # today; the guard is there so that a caller passing something else degrades to
  # the local account instead of raising inside the runner's first report.
  test "anything that is not a request is ignored", %{slot: slot} do
    not_a_request = %{from: "sip:mallory@example.com"}

    assert :ok =
             SIP.Scenario.Runner.run_instance(Fixture,
               slot_id: slot,
               inbound_request: not_a_request
             )

    assert account(slot) == "alice"
  end
end
