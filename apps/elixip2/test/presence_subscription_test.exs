defmodule SIP.Test.PresenceSubscription do
  @moduledoc """
  The same subscription suite, over `SIP.EventPackage.Presence`: `Event:
  presence`, `application/pidf+xml`, and a `%SIP.Presence.Doc{}` where the dummy
  package had a string.

  This file is P4's "done when" (docs/design/presence-basic-plan.md): not a
  second set of tests but the *same* ones, and what it proves is that the
  subscription layer holds nothing about any particular package. A line of it
  that knew about PIDF would pass over there and fail here, or the reverse.
  """

  use SIP.Test.SubscriptionSuite, traits: SIP.Test.SubscriptionTraits.Presence
end
