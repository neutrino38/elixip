# Release 1.6.3

2026-10-03 — 1 fix since 1.6.2 (2026-10-02). Theme: presence, a client's own
activity marks.

## Fixes

- **The composite person keeps the elements a client adds to its activity.** A
  client may put elements of its own namespace in `<rpid:activities>` beside the
  RPID activity: Trix says "do not disturb" as `<rpid:busy/><trix:dnd/>`, and "set
  by a rule" as `<trix:auto/>`. The composite state kept the activity and lost
  them, so a Trix watching its own presence read DND back as plain busy, took it
  for another device's choice, and replaced DND with busy on the next page load.

  Such an element is now a mark, not an activity: it is carried by the composite
  person and written back in its own namespace after the activity, at most eight
  per document. Before, it was also mis-read as an activity and re-emitted as
  `<rpid:dnd/>`.
