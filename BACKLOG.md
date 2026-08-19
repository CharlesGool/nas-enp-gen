# Backlog

The requirement list. Everything that was asked for, most important first,
ticked off as it gets done. `STATUS.md`'s `Next:` field is the topmost unticked
item, copied verbatim.

---

## Items

- [ ] 2026-08-17 revisit the Windows `.exe` build — `.github/workflows/release-installers.yml` has never run on a real tag push, and the local `pyinstaller packaging\nas-enp-gen.spec` attempt never completed
- [ ] 2026-08-17 regenerate and redeploy this host's own live client — it was generated before the v0.1.3 CIFS-option fix, so it still mounts with the old `soft,actimeo=1` behaviour (mount details in `../.local-notes.md`)
- [ ] 2026-08-16 visually confirm the GUI language switcher and the binding controls on a real display — only offscreen/logic-tested here (`QT_QPA_PLATFORM=offscreen`)
- [ ] 2026-08-16 add automated tests for the generator's non-crypto paths — GUI widget behaviour beyond smoke tests, and `packaging/`
- [ ] 2026-08-19 **deferred, not scheduled** — investigate a mediation layer that withholds the decrypted credentials from a root user on the client, closing the gap README's "Honest security note" admits (today root can recover the key material the client derives, machine binding or not). Starts as a design question, not code: which mechanism actually holds against local root — TPM 2.0 sealing, a kernel keyring with a non-dumpable policy, or a privileged helper that performs the mount and never hands the password back — and what each costs in setup and in recovery when the hardware changes. The user's call on 2026-08-19: worth doing eventually, too much work for now.
- [x] 2026-08-19 add `THIRD_PARTY_NOTICES.md` and state the LGPL-3.0 terms for the released `.deb`/`.exe` — see `DECISIONS.md` 2026-08-19
- [x] 2026-08-19 migrate `STATUS.md` to the front-matter format and split the requirement list out into this file
- [x] 2026-08-17 fix the generator's suggested default CIFS mount options (`hard,actimeo=30`) — shipped in `v0.1.3`
- [x] 2026-08-17 document the bootstrap-circularity trap — shipped in `v0.1.2`
- [x] 2026-08-16 write generated client/collector scripts as UTF-8 explicitly — shipped in `v0.1.1`
- [x] 2026-08-16 add machine-fingerprint binding (`binding.mode: "machine"`) — shipped in `v0.1.0`

<!--
Tick, do not delete. A ticked item is the evidence that the requirement was
heard and handled.

  here            every requirement, open or ticked
  DECISIONS.md    considered and rejected, with the reason
  CHANGELOG.md    what shipped in each version, written for whoever uses it
  STATUS.md       the topmost unticked item, plus current state

This is a public repository: no Notion URLs, no local/NAS absolute paths, no
internal hostnames. Those live in ../.local-notes.md, outside repo/.
-->
