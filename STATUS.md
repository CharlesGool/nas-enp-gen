# Status — updated 2026-08-16

**Version:** unreleased · **Branch:** main
**Notion:** not yet synced
**Repo:** https://github.com/CharlesGool/nas-enp-gen (public)
**Snapshots:** maintained privately (not published) — none yet, first snapshot is cut at v0.1.0
**In progress:** client language is now **finalized as pure Python** (see `DECISIONS.md` 2026-08-16 "final decision" entry — this was reverted 3x today; do not revisit without a genuinely new constraint). Generator has a bilingual (English/中文) PySide6 GUI (kept `--config`/`--cli` for headless use), packaged as `.deb`/`.exe` via PyInstaller + GitHub Actions CI.
**Next:** user needs to actually build `dist/nas-enp-gen.exe` on their Windows machine (README documents `pyinstaller packaging/nas-enp-gen.spec`, and the `python -m PyInstaller` fallback for the Microsoft Store Python PATH gotcha they hit) and confirm it runs; then push a tag to dry-run the CI-built `.exe` before trusting it.
**Known issues:**
- no automated tests.
- GUI's base form **has been visually verified on a real Windows display by the user**. The bilingual language-switching (language dropdown, live retranslate) has only been offscreen/logic-tested here (`QT_QPA_PLATFORM=offscreen`) — not yet re-confirmed visually by the user on Windows.
- `.exe` build is CI-only (`windows-latest` via `.github/workflows/release-installers.yml`) and has never actually run — unverified until a real tag is pushed. The user's local Windows build attempt via `pyinstaller packaging\nas-enp-gen.spec` also hasn't completed yet (their first attempt used the wrong invocation, `python pyinstaller ...`; corrected instructions are in the README).
- `.deb` build **was** tested locally end-to-end: `packaging/build-deb.sh` produces a working `.deb` (~67MB, trimmed PyInstaller bundle excluding unused Qt subsystems like QML/Multimedia/SQL), `dpkg -c` confirms the expected file layout (`/usr/bin/nas-enp-gen` + `.desktop` entry). The `Depends:` runtime-library list is derived from `ldd` against the actual built Qt xcb platform plugin on this dev host (Ubuntu 22.04) — not verified across every Debian/Ubuntu release.
- **Real NAS mounting is confirmed working**: user deployed the client to a real host (`AHHome-Ubuntu-Server`), ran `--selftest`/`--install-service`/`--uninstall` successfully, service and mount cleanly removed on request. The pure-Python client's crypto roundtrip, `--selftest`/`--status`/`--help`/tamper-detection, and the generator's `--config` → client-script → `--selftest` pipeline are all tested and passing.
**Blocked on:** a successful local or CI Windows `.exe` build, and visual confirmation of the language switcher on Windows. Do not cut `v0.1.0` until those are done by the user on a real machine.
