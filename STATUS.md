# Status — updated 2026-08-16

**Version:** unreleased · **Branch:** main
**Notion:** not yet synced
**Repo:** https://github.com/CharlesGool/nas-enp-gen (public)
**Snapshots:** maintained privately (not published) — none yet, first snapshot is cut at v0.1.0
**In progress:** replaced the Go client with a pure-Python client, added a bilingual (English/中文) PySide6 GUI to the generator (kept `--config`/`--cli` for headless use), and set up `.deb`/`.exe` packaging via PyInstaller + GitHub Actions CI. See `DECISIONS.md` 2026-08-16 entries for the full rationale.
**Next:** user needs to actually build `dist/nas-enp-gen.exe` on their Windows machine (README now documents `pyinstaller packaging/nas-enp-gen.spec`, and the `python -m PyInstaller` fallback for the Microsoft Store Python PATH gotcha they hit) and confirm it runs; then a real NAS mount test end-to-end; then push a tag to dry-run the CI-built `.exe` before trusting it.
**Known issues:**
- no automated tests.
- GUI **has now been visually verified on a real Windows display by the user** — it launches and the form is usable. The bilingual language-switching added afterward (language dropdown, live retranslate) has only been offscreen/logic-tested here (`QT_QPA_PLATFORM=offscreen`) — not yet re-confirmed visually by the user on Windows.
- `.exe` build is CI-only (`windows-latest` via `.github/workflows/release-installers.yml`) and has never actually run — unverified until a real tag is pushed. The user's local Windows build attempt via `pyinstaller packaging\nas-enp-gen.spec` also hasn't completed yet (their first attempt used the wrong invocation, `python pyinstaller ...`; corrected instructions are now in the README).
- `.deb` build **was** tested locally end-to-end: `packaging/build-deb.sh` produces a working `.deb` (~67MB, trimmed PyInstaller bundle excluding unused Qt subsystems like QML/Multimedia/SQL), `dpkg -c` confirms the expected file layout (`/usr/bin/nas-enp-gen` + `.desktop` entry). The `Depends:` runtime-library list is derived from `ldd` against the actual built Qt xcb platform plugin on this dev host (Ubuntu 22.04) — not verified across every Debian/Ubuntu release.
- The pure-Python client's crypto roundtrip, `--selftest`/`--status`/`--help`/tamper-detection, and the generator's `--config` → client-script → `--selftest` pipeline are all tested and passing. Real mounting against an actual NAS is not tested (no NAS reachable from this dev host).
**Blocked on:** a successful local or CI Windows `.exe` build, a real NAS to mount against, and visual confirmation of the new language switcher on Windows. Do not cut `v0.1.0` until those are done by the user on a real machine.
