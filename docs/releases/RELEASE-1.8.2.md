# Release 1.8.2

2026-10-24 — since 1.8.1 (2026-10-24). Theme: the From and the To of a call
forwarded to a SIP server.

## SIP servers

- **A call forwarded to a `sip-trunk` carries the trunk's identity.** The From
  is the trunk account, without the caller's display name, and the To is at the
  trunk's domain: its `ext_domain`, else the host of its primary URI. The tag of
  the From is kept. For example, with the account `0123456789` and
  `ext_domain = "visioassistance.net"`:

  ```
  INVITE sip:0624765453@visioassistance.net SIP/2.0
  From: <sip:0123456789@visioassistance.net>;tag=13808781841555634
  To: sip:0624765453@visioassistance.net
  ```

  1.8.1 sent the R-URI at the trunk but kept the From and the To as the caller
  wrote them: `From: "Manu" <sip:emmanuel.buu@weshwesh.eu>` and
  `To: sip:0624765453@weshwesh.eu`.
- **A call forwarded to a `sip-proxy` carries its `ext_domain` in the To**, as
  in the R-URI, when the caller addressed it to our domain.

Both rewrites were written and tested, but only on requests built by hand. A
request received from the network keeps From and To as the raw header text,
and the rewrite did nothing on it.

## Framework

- `SIP.Msg.Ops.header_uri/2` gives the From or the To of a message as a
  `%SIP.Uri{}`, whether the parser left it as text or not. Code that rewrites
  one of these headers reads it through this function.

## Upgrading

- `dnf upgrade kelixip kelixip-mod-sip_servers` from 1.8.1. Upgrade both: the
  1.8.2 module calls a function of the 1.8.2 core, and fails on every forward
  to a trunk or a proxy with an older core. No configuration change.
- User-Agent: `Kelixip/1.8.2`, `Elixipp-1.8.2`.
