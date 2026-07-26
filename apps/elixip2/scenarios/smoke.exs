defmodule Smoke do
  @moduledoc """
  Minimal self-contained scenario (no SIP traffic) used to validate the runner,
  the `mix scenario` task and the `elixipp` escript end to end. Always succeeds.
  """
  use SIP.Scenario

  config username: "smoke", domain: "example.com"

  state initial_state do
    appdata_set(:hops, 0)
    goto next
  end

  state bounce do
    n = appdata_get(:hops)
    appdata_set(:hops, n + 1)

    if n < 3 do
      goto loop, "hop #{n}"
    else
      goto done
    end
  end

  state done do
    scenario_success("bounced #{appdata_get(:hops)} times")
  end
end
