# Status — updated 2026-08-16

**Version:** unreleased · **Branch:** main
**Notion:** not yet synced
**Repo:** https://github.com/CharlesGool/nas-enp-gen (public)
**Snapshots:** maintained privately (not published) — none yet, first snapshot is cut at v0.1.0
**In progress:** replaced the Go client with a pure-Python client, added a PySide6 GUI to the generator (kept `--config`/`--cli` for headless use), and set up `.deb`/`.exe` packaging via PyInstaller + GitHub Actions CI. See `DECISIONS.md` 2026-08-16 entries for the full rationale.
**Next:** get real visual/interactive verification of the GUI on an actual display (only headless/offscreen construction has been smoke-tested so far), then a real NAS mount test end-to-end, then push a tag to dry-run the CI-built `.exe` before trusting it.
**Known issues:**
- no automated tests.
- GUI has only been construction-smoke-tested with `QT_QPA_PLATFORM=offscreen` (window builds, form → validate → encrypt → fill_template pipeline runs correctly). It has **not** been visually verified on a real display — no display exists in this dev environment.
- `.exe` build is CI-only (`windows-latest` via `.github/workflows/release-installers.yml`) and has never actually run — this dev host has no Windows environment. Unverified until a real tag is pushed.
- `.deb` build **was** tested locally end-to-end: `packaging/build-deb.sh` produces a working `.deb` (~67MB, trimmed PyInstaller bundle excluding unused Qt subsystems like QML/Multimedia/SQL), `dpkg -c` confirms the expected file layout (`/usr/bin/nas-enp-gen` + `.desktop` entry). The `Depends:` runtime-library list is derived from `ldd` against the actual built Qt xcb platform plugin on this dev host (Ubuntu 22.04) — not verified across every Debian/Ubuntu release.
- The pure-Python client's crypto roundtrip, `--selftest`/`--status`/`--help`/tamper-detection, and the generator's `--config` → client-script → `--selftest` pipeline are all tested and passing. Real mounting against an actual NAS is not tested (no NAS reachable from this dev host).
**Blocked on:** real-display GUI verification, a real NAS to mount against, and a pushed tag to validate the CI `.exe` build — none of these are available in this dev environment. Do not cut `v0.1.0` until at least the first two are done by the user on a real machine.
