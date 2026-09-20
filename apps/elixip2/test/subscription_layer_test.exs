defmodule SIP.Test.SubscriptionLayer do
  @moduledoc """
  The subscription layer (RFC 6665) over `SIP.Test.EventPackages.Dummy`, whose
  document is a line of text — no PIDF, no XML parser, no `presence` package.

  That is what the behaviour is *for* (docs/design/presence-basic-plan.md, P2):
  the layer is exercised end to end — negotiation, 423, 406, 489, the refresh,
  the final NOTIFY, the NOTIFY that overtakes its 200 — by a package that models
  nothing. The same suite runs over the real one in `presence_subscription_test.exs`.
  """

  use SIP.Test.SubscriptionSuite, traits: SIP.Test.SubscriptionTraits.Dummy
end
