# Changelog

Newest version first. Only changes a user can perceive — internal refactors do
not need an entry. Draft from `git log <previous-tag>..HEAD --oneline`, then
rewrite in user-facing terms.

## v0.1.2 — document the bootstrap-circularity trap

### Changed
- `DESIGN.md` / `DESIGN.zh.md`: documented a deployment trap hit on this project's own host — keeping the only copy of the config (or of the generated client) on a share that this tool itself mounts deadlocks recovery, because unmounting that share makes the config needed to remount it unreadable. Recovery then requires re-cloning the repo, re-running `--emit-collector` on the target machine, and regenerating the client from scratch. Documentation only; no behavior change to the generator or the client.

## v0.1.1 — fix invalid UTF-8 in generated scripts

### Fixed
- Generated client scripts and `--emit-collector` output could contain invalid UTF-8 bytes when generated on a machine whose default locale/codepage isn't UTF-8 (e.g. Windows with a non-English codepage). This happened because the generator wrote files via `open(path, "w")` with no explicit encoding, and one code comment contained a non-ASCII em dash. On the target machine, Python then refused to parse the script at all (`SyntaxError: Non-UTF-8 code ... but no encoding declared`). All file writes now specify `encoding="utf-8"` explicitly, and the stray non-ASCII character has been removed. Added a regression test (`tests/test_binding.py::test_generated_client_is_valid_utf8`).

## v0.1.0 — first release

### Added
- Generator (`nas-enp-gen.py`): collects NAS connection details and mount mappings, AES-256-GCM encrypts them, and writes a self-contained Python client script — no compile step.
- Bilingual (English/中文) PySide6 GUI, auto-detecting system locale with a manual language switch; `--cli` for terminal prompts and `--config`/`--out` for headless/scripted use.
- Generator packaged as installable `.deb` (Linux, built and verified locally) and `.exe` (Windows, built via GitHub Actions CI on tag push).
- Generated client: CIFS and NFS mount support, idempotent `--oneshot` with retry/backoff, `--install-service`/`--uninstall` for a boot-time systemd unit that never blocks boot on a dead NAS, `--status`, `--selftest`.
- **Machine binding** (`binding.mode: "machine"`): the client's decryption key is derived at runtime from the target machine's own hardware fingerprint (Scrypt-derived, multi-recipient envelope) instead of being embedded in the file — a leaked script is computationally useless off its bound machine(s). See `DESIGN.md` "Envelope format".
- `--emit-collector`: writes a standalone, dependency-free script to collect a machine's fingerprint ahead of generation.
- `binding.mode: "none"` compatibility path (XOR-split key, pre-existing scheme) for targets where fingerprints can't be pre-collected — no leak protection, documented as such.
- Generation-time self-check: scans the written client script for plaintext/base64 leaks of host/username/password and aborts + deletes the output if found.
- `tests/test_binding.py`: automated coverage of the machine-binding crypto (cross-machine failure, multi-slot, tamper detection, entropy gate, no-plaintext-leak, KDF timing, legacy-mode compatibility).

### Security
- Dedicated NAS account recommended in README's "Honest security note", which now documents machine binding's real leak protection vs. the structural limit (no protection against root already on a bound machine) separately from the `binding.mode: "none"` obfuscation-only path.
