# nas-enp-gen

**English** | [简体中文](README.zh.md)

A two-part tool for auto-mounting NAS shares on Linux clients without leaving the NAS IP / account / password as plaintext on the client.

## What it does

- **`nas-enp-gen.py`** (the *generator*, runs on your workstation) — takes NAS connection details and mount mappings, AES-256-GCM encrypts them, and writes a self-contained Python client script that embeds the ciphertext. Run it with no arguments for a **GUI form** (PySide6, switchable **English / 中文** via the language dropdown in the top-left corner — defaults to your system locale), or `--config`/`--cli` for headless/scripted use. Also shipped as installable **`.deb`** (Linux) and **`.exe`** (Windows) desktop apps — see Install.
- **The generated script** (the *client*) — drop it on each Linux box (Debian/Ubuntu), run as root with `python3`; it mounts the configured shares and can install itself as a systemd boot service.
- **Machine binding (optional but recommended)** — `binding.mode: "machine"` derives the client's decryption key from each target machine's own hardware fingerprint instead of embedding a recoverable key. A generated file that leaks off its bound machine(s) — group chat, backup, retired hardware, accidental public commit — is computationally useless. See "Honest security note" below for exactly what this does and doesn't protect against.

Non-goals: this does not make credentials unrecoverable on a client that has root access — see the security note below. It is not a general-purpose secrets manager.

## Honest security note (read this)

The goal "the credentials can't be reverse-engineered on the client" **cannot be fully achieved** — any client able to mount the share must present the credentials, so a root user on that client can always recover them (RAM dump, `strace` on the mount, packet capture of the SMB auth). This is true regardless of `binding.mode`. What this tool actually does, split by mode:

**`binding.mode: "machine"` (recommended) — real protection against the file leaking:**
- The client's actual decryption key is never stored anywhere. It's derived at runtime from a Scrypt hash of the machine's own hardware fingerprint (`product_uuid` + other DMI/disk identifiers — see `DESIGN.md` "Envelope format"). A copy of the script on any other machine has no way to reach that key — not "hard to find", structurally absent.
- Still true on a **bound** machine: root there can recover everything, the same as any mode (RAM dump, `strace`, packet capture). Binding raises the bar for *exfiltration*, not for a local root attacker.

**`binding.mode: "none"` (compatibility mode) — obfuscation only:**
- Credentials are AES-256-GCM encrypted with a key split/XOR-obfuscated in the same file. No plaintext config file is ever written to the client disk.
- That's **obfuscation, not unbreakable secrecy** — it stops casual inspection and accidental leakage, but the key is recoverable by anyone who obtains the script, on any machine. Use this only when fingerprints can't be pre-collected for a target.

**Do this too, regardless of mode:** create a **dedicated, least-privilege (read-only where possible), revocable** account on the NAS for these clients. If it ever leaks, the damage is contained and you kill it by changing one password on the NAS.

## Requirements

- OS / runtime (generator machine): Python 3.8+ with `cryptography` (GUI also needs `PySide6`, auto-installed via pip on first GUI launch if missing) — or just use the packaged `.deb`/`.exe`, which bundle everything.
- Client machine: Debian/Ubuntu Linux, root access, Python 3.8+. `cryptography` and `cifs-utils` are both auto-installed by the client script on first run if missing.

## Install

Either run from source, or grab the packaged installer from the release page (built by CI on each tagged version — see `.github/workflows/release-installers.yml`):

```bash
# Always clone a tag, not the default branch — the branch tip may be mid-work.
# Latest release tag: git ls-remote --tags https://github.com/CharlesGool/nas-enp-gen.git
git clone --branch v0.1.3 --depth 1 https://github.com/CharlesGool/nas-enp-gen.git nas-enp-gen
cd nas-enp-gen
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # then fill in real NAS details, see Configuration
```

## Building the installers locally

CI (`.github/workflows/release-installers.yml`) builds both installers automatically on every `v*.*.*` tag. To build one yourself instead:

```bash
pip install -r requirements.txt pyinstaller
pyinstaller packaging/nas-enp-gen.spec
```

Output: `dist/nas-enp-gen` (Linux) or `dist/nas-enp-gen.exe` (Windows). On Linux, wrap it into a `.deb` with `packaging/build-deb.sh`.

**Windows gotcha:** run `pyinstaller`, not `python pyinstaller` — it's a standalone console command installed by `pip`, not a script you pass to `python`. If `pyinstaller` isn't found on `PATH` (common with the Microsoft Store Python alias, whose `Scripts` folder often isn't on `PATH`), use `python -m PyInstaller packaging\nas-enp-gen.spec` instead — that always works regardless of `PATH`.

## Step 0: collect fingerprints from target machines (`binding.mode: "machine"` only)

Skip this if you're using `binding.mode: "none"`. Otherwise, on **each** target
machine (as root):

```bash
python3 nas-enp-gen.py --emit-collector          # writes nas-enp-fingerprint.py
# copy nas-enp-fingerprint.py to the target machine, then on that machine:
python3 nas-enp-fingerprint.py
```

It prints a 64-hex-char fingerprint and which hardware fields it used —
paste that fingerprint into `config.json`'s `binding.fingerprints` array (or
the GUI's fingerprint box). One file with N fingerprints can bind an entire
fleet — see `DESIGN.md` "Envelope format".

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

## What if the hardware changes? (`binding.mode: "machine"` only)

The fingerprint is one hash over *all* valid hardware components combined
(strict mode, by design — see `DECISIONS.md`). A disk swap, a BIOS/DMI
field change from a firmware update, or similar hardware maintenance on a
bound machine will change its fingerprint, and the existing client will
start failing with:

```
fingerprint mismatch: this client was not generated for this machine
(or the hardware changed). Regenerate it with nas-enp-gen using this
machine's current fingerprint. Run --selftest for details.
```

This is a fail-closed design choice, not a bug — see `DECISIONS.md` "Strict
mode, not fault-tolerant, for hardware changes". Recovery: re-run
`--emit-collector` on the changed machine, get its new fingerprint, and
regenerate the client with that fingerprint in `binding.fingerprints`.
`--selftest` on the failing client will show which components it collected
and confirm the slot lookup failed, before you regenerate anything.

## Configuration

See `config.example.json` for the full shape, including the `binding`
field (`{"mode": "machine", "fingerprints": [...]}` or `{"mode": "none"}` —
required, no default, see "Honest security note" above). Full reference:
see `DESIGN.md` → Configuration reference.

## License

Apache License 2.0 — see `LICENSE`.

The packaged `.deb`/`.exe` on the release page bundle third-party components,
notably **PySide6 and the Qt 6 libraries, used under the GNU LGPL version 3**,
and a statically linked OpenSSL inside `cryptography`. Sources, attributions and
the LGPL relinking terms are listed in `THIRD_PARTY_NOTICES.md` — read it before
redistributing a binary. Running from source pulls those packages from PyPI
under their own licenses and creates no combined distribution.
