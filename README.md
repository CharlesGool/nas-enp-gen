# nas-enp-mount

**English** | [简体中文](README.zh.md)

A two-part tool for auto-mounting NAS shares on Linux clients without leaving the NAS IP / account / password as plaintext on the client.

## What it does

- **`nas-enp-gen.py`** (the *generator*, runs on your workstation) — takes NAS connection details and mount mappings, AES-256-GCM encrypts them, and compiles a single stripped static Go binary that embeds the ciphertext. Run it with no arguments for a **GUI form** (PySide6, switchable **English / 中文** via the language dropdown in the top-left corner — defaults to your system locale), or `--config`/`--cli` for headless/scripted use. Also shipped as installable **`.deb`** (Linux) and **`.exe`** (Windows) desktop apps — see Install.
- **The generated binary** (the *client*) — drop it on each Linux box (Debian/Ubuntu), run as root; it mounts the configured shares and can install itself as a systemd boot service. No runtime dependencies — it's a static binary.

Non-goals: this does not make credentials unrecoverable on a client that has root access — see the security note below. It is not a general-purpose secrets manager.

## Honest security note (read this)

The goal "the credentials can't be reverse-engineered on the client" **cannot be fully achieved** — any client able to mount the share must present the credentials, so a root user on that client can always recover them (RAM dump, `strace` on the mount, packet capture of the SMB auth). What this tool actually does:

- Credentials are **AES-256-GCM encrypted** and embedded in the client binary; the key is split/XOR-obfuscated. No plaintext config file is ever written to the client disk, and `strings` on the binary reveals nothing but base64 ciphertext.
- That's **obfuscation, not unbreakable secrecy** — it stops casual inspection and accidental leakage, and raises the bar for a determined attacker. The client is a stripped, compiled Go binary rather than a script, which keeps that bar meaningfully higher than plaintext source would — see `DECISIONS.md` for why this was worth reverting a same-day pure-Python experiment.

**Do this too:** create a **dedicated, least-privilege (read-only where possible), revocable** account on the NAS for these clients. If it ever leaks, the damage is contained and you kill it by changing one password on the NAS.

## Requirements

- OS / runtime (generator machine): Python 3.8+ with `cryptography` (GUI also needs `PySide6`, auto-installed via pip on first GUI launch if missing), plus a Go toolchain to compile the client (or use `--no-build`/the GUI's "emit Go source only" checkbox to skip this and compile elsewhere) — or just use the packaged `.deb`/`.exe`, which bundle the generator's own Python/GUI deps (you still need Go, or `--no-build`, to produce a client).
- Client machine: Debian/Ubuntu Linux, root access. No runtime dependencies — the binary is static.

## Install

Either run from source, or grab the packaged installer from the release page (built by CI on each tagged version — see `.github/workflows/release-installers.yml`):

```bash
# Always clone a tag, not the default branch — the branch tip may be mid-work.
# Latest release tag: git ls-remote --tags <repo-url>
git clone --branch v0.1.0 --depth 1 <repo-url> nas-enp-gen
cd nas-enp-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # then fill in real NAS details, see Configuration
```

**Note:** the `.deb`/`.exe` are installers for the *generator app* only — they're generic and safe to attach to a GitHub Release. The *client binary* (`nas-enp-mount`) is not: every copy embeds one specific user's own encrypted NAS credentials, so it can't be pre-built and published generically. Each user runs the generator themselves to produce their own client binary.

## Building the installers locally

CI (`.github/workflows/release-installers.yml`) builds both installers automatically on every `v*.*.*` tag. To build one yourself instead:

```bash
pip install -r requirements.txt pyinstaller
pyinstaller packaging/nas-enp-gen.spec
```

Output: `dist/nas-enp-gen` (Linux) or `dist/nas-enp-gen.exe` (Windows). On Linux, wrap it into a `.deb` with `packaging/build-deb.sh`.

**Windows gotcha:** run `pyinstaller`, not `python pyinstaller` — it's a standalone console command installed by `pip`, not a script you pass to `python`. If `pyinstaller` isn't found on `PATH` (common with the Microsoft Store Python alias, whose `Scripts` folder often isn't on `PATH`), use `python -m PyInstaller packaging\nas-enp-gen.spec` instead — that always works regardless of `PATH`.

## Quick start

```bash
# GUI form (no args)
python3 nas-enp-gen.py

# headless, from a JSON config file (see config.example.json)
python3 nas-enp-gen.py --config config.json

# interactive terminal prompts instead of the GUI
python3 nas-enp-gen.py --cli

# cross-compile for multiple client architectures
python3 nas-enp-gen.py --config config.json --arch amd64,arm64

# no Go toolchain here? emit source instead, compile on any Linux box
python3 nas-enp-gen.py --config config.json --no-build

# custom output path
python3 nas-enp-gen.py --config config.json --out nas-enp-mount
```

## Verify it works

You should see a `nas-enp-mount` binary written to the current directory (GUI mode shows the same info in a result dialog). Copy it to a test client and run `--selftest`:

```bash
./nas-enp-mount --selftest
```

Expect output confirming the embedded config decrypts successfully, with no secrets printed.

## Deploy on each client (as root)

```bash
mkdir -p /root/nas-enp-mount
cp nas-enp-mount /root/nas-enp-mount/
chmod +x /root/nas-enp-mount/nas-enp-mount
/root/nas-enp-mount/nas-enp-mount --selftest         # verify config decrypts
/root/nas-enp-mount/nas-enp-mount --oneshot          # mount now
/root/nas-enp-mount/nas-enp-mount --install-service  # enable at boot
```

Client modes:

| command | effect |
|---|---|
| `--oneshot` (default) | mount all shares once, with internal retries |
| `--install-service` | write + enable the systemd unit, start it |
| `--uninstall` | stop/remove service, unmount shares |
| `--status` | show which shares are mounted |
| `--selftest` | confirm the embedded config decrypts (no secrets printed) |

Check logs any time with: `journalctl -u nas-enp-mount.service`

## Why this won't break boot

- `Type=oneshot`, `Wants=network-online.target`, `After=network-online.target`.
- Nothing else `Requires=` this unit, and it is only `WantedBy=multi-user.target` — so even if it fails, boot proceeds normally.
- `TimeoutStartSec=150` bounds the whole attempt; retries/backoff happen *inside* that budget, so it can never wait forever on an unreachable NAS.
- The client is idempotent: it checks `/proc/mounts` and skips already-mounted targets, creates missing mount points, and (optionally) installs `cifs-utils`.

## Rotating credentials / changing the NAS

The credentials live only inside the binary. When the NAS IP or password changes, re-run the generator to produce a new binary and copy it over (`--uninstall` first if you want a clean swap). There is no editable config on the client to get out of sync.

## Configuration

See `config.example.json` for the full shape. Full reference: see `DESIGN.md` → Configuration reference.

## License

Apache License 2.0 — see `LICENSE`.
