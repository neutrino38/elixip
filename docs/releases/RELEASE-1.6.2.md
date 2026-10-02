# Release 1.6.2

Unreleased — since 1.6.1 (2026-09-27). Theme: the presence of a user with
several devices.

## Presence — the composite state

A watcher is told one document per presentity, composed from all its devices,
instead of the state of the device that changed last. See
[presence.md](../kelixip/modules/presence.md#the-composite-state).

- **Tuples** are the union of the devices: each live publication's, plus one open
  tuple per registered device that publishes nothing. Bob is reachable on the
  desk phone that only registers while his mobile publishes.
- **The activity and note** are the presentity's: the last ones a publication
  expressed. They survive the device that set them — Bob sets *away* on his
  phone and closes it, he stays *away*. A publication with no activity, which is
  how Linphone and Trix say "available", clears them.
- A device republishing what it was told, a refresh, or a refreshing REGISTER
  sends no NOTIFY. A registered device leaving while another stays now does: one
  tuple fewer, still open.
- `kelictl presence show` lists one `registrar` row per registered device, and a
  `ruid` column: the stable key each device's tuples are named after.

Limitation kept: several devices relayed by a proxy over one connection are one
publisher, and replace each other's publication.
