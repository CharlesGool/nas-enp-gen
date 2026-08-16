# nas-enp-mount

**English** | [简体中文](README.zh.md)

A two-part tool for auto-mounting NAS shares on Linux clients without leaving the NAS IP / account / password as plaintext on the client.

## What it does

- **`nas-enp-gen.py`** (the *generator*, runs on your workstation) — takes NAS connection details and mount mappings, AES-256-GCM encrypts them, and writes a self-contained Python client script that embeds the ciphertext. Run it with no arguments for a **GUI form** (PySide6), or `--config`/`--cli` for headless/scripted use. Also shipped as installable **`.deb`** (Linux) and **`.exe`** (Windows) desktop apps — see Install.
- **The generated script** (the *client*) — drop it on each Linux box (Debian/Ubuntu), run as root with `python3`; it mounts the configured shares and can install itself as a systemd boot service.

Non-goals: this does not make credentials unrecoverable on a client that has root access — see the security note below. It is not a general-purpose secrets manager.

## Honest security note (read this)

The goal "the credentials can't be reverse-engineered on the client" **cannot be fully achieved** — any client able to mount the share must present the credentials, so a root user on that client can always recover them (RAM dump, `strace` on the mount, packet capture of the SMB auth). What this tool actually does:

- Credentials are **AES-256-GCM encrypted** and embedded in the client script; the key is split/XOR-obfuscated. No plaintext config file is ever written to the client disk.
- That's **obfuscation, not unbreakable secrecy** — it stops casual inspection and accidental leakage, and raises the bar for a determined attacker. Since the client is a plain, readable `.py` file rather than a compiled binary, that bar is a bit lower than a stripped executable would be — see `DECISIONS.md`.

**Do this too:** create a **dedicated, least-privilege (read-only where possible), revocable** account on the NAS for these clients. If it ever leaks, the damage is contained and you kill it by changing one password on the NAS.

## Requirements

- OS / runtime (generator machine): Python 3.8+ with `cryptography` (GUI also needs `PySide6`, auto-installed via pip on first GUI launch if missing) — or just use the packaged `.deb`/`.exe`, which bundle everything.
- Client machine: Debian/Ubuntu Linux, root access, Python 3.8+. `cryptography` and `cifs-utils` are both auto-installed by the client script on first run if missing.

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

## Quick start

```bash
# GUI form (no args)
python3 nas-enp-gen.py

# headless, from a JSON config file (see config.example.json)
python3 nas-enp-gen.py --config config.json

# interactive terminal prompts instead of the GUI
python3 nas-enp-gen.py --cli

# custom output path
python3 nas-enp-gen.py --config config.json --out nas-enp-mount.py
```

## Verify it works

You should see a `nas-enp-mount.py` script written to the current directory (GUI mode shows the same info in a result dialog). Copy it to a test client and run `--selftest`:

```bash
python3 nas-enp-mount.py --selftest
```

Expect output confirming the embedded config decrypts successfully, with no secrets printed.

## Deploy on each client (as root)

```bash
mkdir -p /root/nas-enp-mount
cp nas-enp-mount.py /root/nas-enp-mount/
python3 /root/nas-enp-mount/nas-enp-mount.py --selftest         # verify config decrypts
python3 /root/nas-enp-mount/nas-enp-mount.py --oneshot          # mount now
python3 /root/nas-enp-mount/nas-enp-mount.py --install-service  # enable at boot
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

The credentials live only inside the script. When the NAS IP or password changes, re-run the generator to produce a new script and copy it over (`--uninstall` first if you want a clean swap). There is no editable config on the client to get out of sync.

## Configuration

See `config.example.json` for the full shape. Full reference: see `DESIGN.md` → Configuration reference.

## License

Apache License 2.0 — see `LICENSE`.
