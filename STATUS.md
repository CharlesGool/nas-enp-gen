---
project: nas-enp-gen
version: v0.1.3
status: active
branch: main
updated: 2026-08-19
---

# Status

**Notion:** private mirror (not published)
**Repo:** https://github.com/CharlesGool/nas-enp-gen (public)
**Snapshots:** maintained privately (not published) — v0.1.0 through v0.1.3 cut and verified (v0.1.1: 16/16 files; v0.1.2: 16/16 files; v0.1.3: 17/17 files, archive manifest matched)
**In progress:** nothing. `v0.1.3` is tagged, pushed and released; the open items in `BACKLOG.md` are post-release follow-ups, not blockers. The generator is a bilingual (English/中文) PySide6 GUI with `--config`/`--cli`/`--emit-collector` for headless use, packaged as `.deb`/`.exe` via PyInstaller + GitHub Actions. Client language is **pure Python** — see the 2026-08-16 "final decision" entry in `DECISIONS.md`, do not revisit without a genuinely new constraint.
**Next:** revisit the Windows `.exe` build — `.github/workflows/release-installers.yml` has never run on a real tag push, and the local `pyinstaller packaging\nas-enp-gen.spec` attempt never completed
**Known issues:**
- Test coverage is crypto-only: `tests/test_binding.py` (15 cases — cross-machine failure, multi-slot, tamper detection, entropy gate, no-plaintext-leak, KDF timing, legacy-mode compatibility, plus the v0.1.1 UTF-8 regression test) and `tests/test_defaults.py`. The generator's non-crypto paths (GUI behaviour beyond smoke tests, packaging) have no automated tests.
- The GUI's base form has been visually verified on a real Windows display by the user, but the language switcher and the binding controls have only been offscreen/logic-tested here (`QT_QPA_PLATFORM=offscreen`). Not a release blocker as of 2026-08-16 — the CLI/headless paths are tested end-to-end independently of the GUI.
- The `.exe` build is CI-only (`windows-latest`) and has never actually run. The `.deb` path is fully verified locally: `packaging/build-deb.sh` produces a working ~67MB package and `dpkg -c` confirms the layout, but its `Depends:` list was derived by `ldd` against the Qt xcb plugin built on an Ubuntu 22.04 dev host — not verified on every Debian/Ubuntu release.
- Real NAS mounting is confirmed working on a real host by the user: `--selftest`, `--install-service`, `--uninstall`, both `binding.mode: "none"` and `"machine"`, tamper detection, `--emit-collector`, and the `--config` → client-script → `--selftest` pipeline all pass.
- This host's own live client predates the v0.1.3 CIFS-option fix and has not been regenerated — tracked as an open item in `BACKLOG.md`.
- Hardware changes (disk swap, BIOS/DMI updates) invalidate a machine-bound client by design (strict mode) — see README "What if the hardware changes?" and `DECISIONS.md` 2026-08-16. Not a bug, but a real operational cost before choosing `binding.mode: "machine"` on machines with frequent hardware churn.
**Blocked on:** nothing.
