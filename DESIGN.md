# nas-enp-gen — Design

**English** | [简体中文](DESIGN.zh.md)

> Success criterion for this document: someone else, on a different machine,
> can rebuild this project from it. Assume the reader cannot see your machine.

## Goals & non-goals

**Goals**
- Let a Linux client auto-mount NAS (CIFS/NFS) shares at boot without a plaintext credentials file on that client's disk.
- Make credential rotation a one-step process: regenerate the binary, redeploy it.
- Fail safe: an unreachable NAS must never hang or break boot on the client.

**Non-goals**
- True secrecy against a root-privileged attacker on the *bound* client — impossible by construction, since that machine must itself recover the credentials to mount the share. See README's "Honest security note." This is a two-layer claim: the file is computationally useless off the machine(s) it was generated for, but on a bound machine, root still recovers everything.
- Cross-platform clients (Windows/macOS) — Debian/Ubuntu Linux only.
- A general secrets-management or config-distribution system.
- TPM-backed key storage (noted as a possible future enhancement, not implemented).

## Architecture

```
config.json (real secrets, never committed)
        |
        v
nas-enp-gen.py                      nas-enp-gen.py --config config.json
  (no args -> PySide6 GUI form)       (headless / scripted, or --cli for
        |                              terminal prompts)
        |  1. validates config, incl. binding.mode ("machine" | "none")
        |  2a. binding.mode = "none":
        |        AES-256-GCM encrypts the JSON blob, splits/XOR-obfuscates
        |        the key (legacy scheme, unchanged since v0.1.0)
        |  2b. binding.mode = "machine":
        |        random DEK encrypts the JSON blob once (AES-256-GCM);
        |        DEK is wrapped once per target-machine fingerprint via
        |        Scrypt-derived KEK + AES-256-GCM — see "Envelope format"
        |  3. fills the chosen blob into the Python client template
        |  4. writes the filled template to disk — no build/compile step
        |  5. self-check: greps the written file for plaintext/base64
        |     leaks of host/username/password; aborts + deletes on a hit
        v
nas-enp-mount.py (plain Python script, embeds ciphertext + key material)
        |
        |  copied to each client, run as root (python3 nas-enp-mount.py ...)
        |  binding.mode = "machine": client recollects its own hardware
        |  fingerprint at runtime and must match a slot to decrypt
        v
client script
        |  --selftest      decrypt in memory, verify, print nothing sensitive
        |  --oneshot        mount each configured share (idempotent, retries)
        |  --install-service  write systemd unit, enable, start
        v
mounted CIFS/NFS shares on the client
```

`nas-enp-gen.py --emit-collector` produces a third, separate artifact: a
zero-dependency fingerprint-collection script the operator copies onto each
*target* machine ahead of generation (chicken-and-egg fix — see "Envelope
format" below) to obtain the hex fingerprints that go into `binding.fingerprints`.

The generator itself is also packaged as installable `.deb` (Linux) and `.exe`
(Windows) desktop apps — see "Packaging & CI" below — for people who'd rather
double-click a form than run a CLI. The deployed mount client is never
packaged this way; it stays a plain script driven by systemd, with no GUI.

## Tech stack

| Layer | Choice | Version | Why |
|---|---|---|---|
| Generator | Python | 3.8+ (tested on 3.10) | Scripting the encrypt-and-template step; `cryptography` gives audited AES-GCM |
| Generator crypto | `cryptography` (pyca) | 3.4.8 | Audited, standard choice for AES-256-GCM in Python |
| Generator GUI | PySide6 (Qt for Python) | latest | LGPLv3 — compatible with staying permissively (Apache-2.0) licensed, unlike GPL/commercial PyQt. See `DECISIONS.md` 2026-08-16. |
| Generator packaging | PyInstaller + `dpkg-deb` (Linux), PyInstaller (Windows, via CI) | latest | Single-file executables wrapped into installers; Windows build runs on GitHub Actions `windows-latest` since this project has no local Windows environment |
| Client | Python | 3.8+ | All deployment targets guarantee a Python environment (confirmed by user); removes the Go-toolchain requirement entirely. See `DECISIONS.md` 2026-08-16. |
| Client crypto | `cryptography` (pyca) | same as generator | Same library, same AES-256-GCM scheme, on both sides — one dependency to track instead of two toolchains |
| Machine-binding KDF | `cryptography.hazmat...kdf.scrypt.Scrypt` | same as generator | Already ships in `cryptography`, the project's sole runtime dependency — chosen over Argon2id specifically to avoid adding `argon2-cffi` or raising the `cryptography` version floor. See `DECISIONS.md` 2026-08-16 "KDF: Scrypt over Argon2id". |

Rejected alternatives and reasoning live in `DECISIONS.md`.

## Envelope format (`binding.mode = "machine"`)

Threat model: a client script that leaks (group chat, backup, retired
hardware, accidental public commit) must be computationally useless to
whoever finds it, unless they also possess one of the bound machines. This
does **not** defend against an attacker who already has root on a bound
machine — see Non-goals.

**Key principle:** the machine's identity is key-derivation material, not a
stored value compared against. Nothing in the file lets you check a guess
without paying the full Scrypt cost, and the fingerprint itself is never
written to disk anywhere.

```
generation time (operator's workstation)
  fingerprint (pre-collected on each target machine, see --emit-collector)
        |
        +-- selector = SHA256(fingerprint || "nas-enp/selector/v2")[:8 bytes]
        |
        +-- KEK = Scrypt(password=fingerprint, salt=random16, n=2^15, r=8, p=1, dklen=32)
                    |
  DEK (random 32B) -+-> wrapped_dek = AES-256-GCM(KEK, DEK, aad="nas-enp/slot/v2")
        |
        +-> payload = AES-256-GCM(DEK, json(nas_config), aad="nas-enp/payload/v2")

file contains only: selector, salt, nonce, wrapped_dek (per slot) + payload
(no KEK, no DEK, no fingerprint)

runtime (client)
  recollect fingerprint -> selector -> find slot -> Scrypt -> KEK
  -> unwrap DEK -> decrypt payload -> mount
```

One random DEK is shared across all slots (multi-recipient envelope) so one
generated file can target an entire fleet; each slot only proves membership
via its own machine's Scrypt-derived KEK. A machine not in the fingerprint
list has no path to any KEK and cannot even attempt the payload decrypt.

**Wire format** (base64-embedded JSON in the client script):

```json
{
  "v": 2,
  "kdf": {"algo": "scrypt", "n": 32768, "r": 8, "p": 1, "dklen": 32},
  "slots": [
    {"selector": "<16 hex>", "salt": "<b64, 16B>", "nonce": "<b64, 12B>", "wrapped_dek": "<b64>"}
  ],
  "payload": {"nonce": "<b64, 12B>", "ct": "<b64>"}
}
```

- Each slot has its own random salt — salts are never shared.
- AAD strings (`"nas-enp/slot/v2"`, `"nas-enp/payload/v2"`) are fixed and
  domain-separate the two AES-GCM uses so a slot ciphertext can't be
  replayed as a payload ciphertext or vice versa.
- Slots carry no identifying metadata (no hostname, no notes, no IP) and are
  shuffled at generation time — position leaks nothing.
- `n=2^15` costs ~32MB RAM and ~0.1s per attempt on this class of hardware,
  comfortably inside the client's `TimeoutStartSec=150` systemd budget even
  for a 100-slot file with the `selector` fast-path (see below).

**`selector`** lets the client jump straight to its own slot instead of
attempting Scrypt against all N slots (worst case ~10s at N=100). It costs
letting an attacker who has *already guessed the right fingerprint* verify
that guess without paying the Scrypt cost first. This is accepted **only**
because the entropy gate (below) guarantees the primary fingerprint
component, `product_uuid`, carries ~128 bits of entropy — brute-forcing a
correct guess remains infeasible regardless of the selector shortcut. **These
two are coupled:** removing the entropy gate without also removing `selector`
(falling back to try-every-slot) would silently reopen this shortcut against
a now-guessable fingerprint. See `DECISIONS.md`.

`binding.mode = "none"` keeps the original XOR-split scheme byte-for-byte (random
key XOR-split across two halves stored alongside the ciphertext) — no
Scrypt, no fingerprint, no leak protection. It exists for targets where
fingerprints can't be pre-collected. The client template contains both code
paths; a `CONFIG_MODE` constant baked in at generation time selects which
one runs — see "Data model / file layout" for where this lives in the source.

### Fingerprint collection

Read as root, in this priority order, from the *target* machine:

| Order | Source | Notes |
|---|---|---|
| 1 (required) | `/sys/class/dmi/id/product_uuid` | primary anchor, ~128 bits, root-only |
| 2 | `/sys/class/dmi/id/board_serial` | |
| 3 | `/sys/class/dmi/id/product_serial` | |
| 4 | `/sys/block/<root-disk>/device/serial` | disk backing `/`, resolved via `/proc/mounts` |

Explicitly excluded: MAC address (~24 bits of real entropy, trivially
spoofable) and `/etc/machine-id` (just a file — it travels with a copied
script, so alone it binds nothing).

Placeholder values (`""`, `"None"`, `"0"`, `"Default string"`, `"To be
filled by O.E.M."`, `"Not Specified"`, `"Not Applicable"`, `"System Serial
Number"`, `"Unknown"`, `"INVALID"`, an all-zero UUID — compared
case-insensitively, trimmed) are discarded, not hashed.

**Entropy gate (hard requirement):** if `product_uuid` is missing or a
placeholder, collection fails fast — it never silently degrades to a
lower-entropy combination of the optional fields. A silent degrade here
would be invisible until someone bothered to check, which is the worst kind
of failure for a security control.

Valid components are joined as `key=value` lines, sorted by key, UTF-8
encoded, and SHA-256'd to a 64-hex-char fingerprint. The collection logic is
written once (`FINGERPRINT_LOGIC_SRC` in `nas-enp-gen.py`) and spliced
verbatim into both `--emit-collector`'s output and the client template at
generation time — see "Data model / file layout".

## Packaging & CI

- `packaging/nas-enp-gen.spec` — PyInstaller spec for the generator GUI/CLI single-file executable.
- `packaging/build-deb.sh` — runs PyInstaller, assembles a `DEBIAN/control` tree, and calls `dpkg-deb --build` to produce `nas-enp-gen_<version>_amd64.deb`. Runs and is testable on this Linux host.
- `.github/workflows/release-installers.yml` — triggers on `v*.*.*` tag pushes. Builds the `.deb` on `ubuntu-latest` and the `.exe` on `windows-latest`, uploads both as GitHub Release assets. The `.exe` build is CI-only — it cannot be produced or verified on this (Linux) development host.

## Reproduction requirements

**The most important section. Everything a different machine needs.**

### Environment

- OS (generator machine): any OS with Python 3.8+ — Linux, Windows, or macOS. GUI mode needs a display; `--config`/`--cli` modes don't.
- OS (client machine): Debian/Ubuntu Linux, root access, Python 3.8+
- Runtime + version: Python 3.8+, `cryptography` package (both generator and client; auto-installed via `pip` if missing on either side)
- Optional (dev/CI only, not needed to run the project): PyInstaller + `dpkg-deb` to build the `.deb` installer locally; GitHub Actions `windows-latest` runner builds the `.exe`
- Dependency restore command: `pip install -r requirements.txt`

### External dependencies

| Item | Source | Placed at |
|---|---|---|
| NAS credentials (host/user/password) | your NAS admin panel | `config.json` (gitignored, never committed) |
| `cifs-utils` (client, optional) | client's package manager | auto-installed by the client script when `install_deps: true` |
| `cryptography` (client) | PyPI | auto-installed via `pip` on client first run if missing |

Use placeholders, never real values, in anything committed — see `config.example.json`.

### Paths & mounts

Every path below is *supplied by the user's own `config.json`*, not hardcoded in the script:

| Path | Provided by | Purpose |
|---|---|---|
| `mounts[].remote` | user, in config | path on the NAS to mount |
| `mounts[].local` | user, in config | mount point on the client |
| `--out` | CLI flag, default `nas-enp-mount.py` | where the generator writes the filled client script |

The client hardcodes its own install location, `/root/nas-enp-mount`, as a fixed convention documented in the README — this is a client-side install path, not a generator-machine path, so it does not need to be templated.

### Configuration reference

Fields of the JSON config consumed by `nas-enp-gen.py --config <file>` (see `config.example.json`):

| Field | Meaning | Default | Required |
|---|---|---|---|
| `protocol` | `cifs` or `nfs` | — | yes |
| `host` | NAS IP or hostname | — | yes |
| `username` | NAS account | — | yes (CIFS) |
| `password` | NAS account password | — | yes (CIFS) |
| `domain` | Windows domain, if any | `""` | no |
| `default_options` | mount options applied to every share unless overridden | CIFS: `vers=3.0,iocharset=utf8,uid=0,gid=0,file_mode=0644,dir_mode=0755,hard,actimeo=30` · NFS: `vers=4,soft,timeo=50,retrans=3` | yes |
| `mounts` | array of `{remote, local, options}` | — | yes, at least one |
| `retry_attempts` | client-side mount retry count | — | yes |
| `retry_delay_sec` | seconds between retries | — | yes |
| `install_deps` | let the client `apt install cifs-utils` if missing | — | yes |
| `binding.mode` | `"machine"` or `"none"` — see "Envelope format" | — | yes, no default |
| `binding.fingerprints` | array of 64-hex-char fingerprints (from `--emit-collector`), one per target machine | `[]` | yes if `mode: "machine"`, must be non-empty |

`binding` has no default — a config missing it is rejected with an error
naming both options, on both the `--config`/`--cli` and GUI paths. This is
deliberate: silently defaulting either way (auto-binding, or silently
falling back to unprotected) would be a surprising, security-relevant
choice made on the user's behalf.

**Why the CIFS default sets `hard,actimeo=30` explicitly (added v0.1.3):**
leaving these unset is not "no opinion" — the kernel's `cifs.ko` silently
applies `soft` and `actimeo=1` (see `man mount.cifs`), and that exact
combination caused a real incident: under heavy `git` metadata churn on a
soft-mounted share, a transient server-side lease-break ack delay made a
`rename()` on `.git/index` return `EACCES` permanently instead of the
kernel retrying, wedging the file until the mount was refreshed. `hard`
makes transient hiccups block-and-retry instead of erroring out;
`actimeo=30` cuts down on-the-wire attribute checks during rapid git
operations. See `DECISIONS.md` 2026-08-17 "Default CIFS mount options"
for the full incident writeup and alternatives considered.

CLI flags of the generator itself: `--config` (headless/scripted), `--cli` (force the old terminal-prompt flow instead of the GUI), `--out`, `--save-config` (writes the collected config back out — contains the password in cleartext, guard it), `--emit-collector [--out PATH]` (writes a standalone, dependency-free fingerprint-collection script for a target machine; default `nas-enp-fingerprint.py`). No arguments launches the PySide6 GUI. `--arch` and `--no-build` were removed — there is no build/compile step anymore.

## Setup from scratch

1. On the generator machine: `pip install -r requirements.txt` — verify: `python3 -c "import cryptography, PySide6"` prints nothing / no error.
2. Copy `config.example.json` to `config.json`, fill in real NAS details — verify: `python3 -m json.tool config.json` parses without error.
3. Run `python3 nas-enp-gen.py --config config.json` (or launch the GUI with no args and fill the form) — verify: a `nas-enp-mount.py` script appears in the working directory.
4. Copy the script to a test client, run `python3 nas-enp-mount.py --selftest` — verify: it reports the config decrypted successfully (auto-installs `cryptography` on the client if missing).
5. Run `--oneshot` on the client — verify: `mount | grep <local path>` shows the share mounted.
6. Run `--install-service` — verify: `systemctl is-enabled nas-enp-mount.service` reports `enabled`.

This project is not deployed with Docker — no docker skill reference needed.

## Data model / file layout

```
repo/
├── nas-enp-gen.py           # the generator — GUI/CLI, reads config.json, drives the whole pipeline
├── config.example.json      # placeholder shape of the config file (safe to commit)
├── requirements.txt         # pinned generator + client Python dependencies
├── packaging/
│   ├── nas-enp-gen.spec     # PyInstaller spec for the generator executable
│   └── build-deb.sh         # local .deb build (control file + dpkg-deb)
├── .github/workflows/
│   └── release-installers.yml  # CI: builds .deb (ubuntu-latest) + .exe (windows-latest) on tag push
└── (config.json, nas-enp-mount.py, dist/ — generator/build outputs, all gitignored)
```

The Python client source lives base64-embedded inside `nas-enp-gen.py` (`PY_CLIENT_TEMPLATE_B64`), so the generator stays single-file and self-contained. There is no `--no-build`-equivalent flag needed for inspection — the filled script written to `--out` *is* the real source, plaintext, readable directly.

`FINGERPRINT_LOGIC_SRC` (plain text, not base64) holds the one canonical copy
of the fingerprint-collection function. It is spliced as-is into the decoded
client template (replacing a `# __FINGERPRINT_LOGIC__` marker) and into the
`--emit-collector` output, so both places that read hardware identifiers run
identical code — see `DECISIONS.md` for why a second, hand-copied version
would be a latent fleet-wide outage waiting to happen.

## Known limitations & gotchas

- `config.example.json` previously held **real production credentials** committed under an "example" filename — this has been corrected (placeholders only, see `DECISIONS.md` 2026-08-16). Real values now live in a gitignored `config.json` outside version control, and the actual working config used on this host is kept at `../nas.local.json` (project root, outside `repo/`, never committed).
- Security is obfuscation, not encryption-that-matters against a root-privileged attacker on the client — see README. Moving the client from a compiled binary to a plaintext-readable `.py` script (2026-08-16) makes casual inspection slightly easier than before; this was never relied upon as real secrecy.
- `tests/test_binding.py` (added `v0.1.0`) covers the envelope crypto and fingerprint-placeholder logic directly (unit-level, no real hardware needed). The generator's non-crypto paths (GUI, packaging) still have no automated tests.
- Hardware changes (disk replacement, BIOS/DMI field changes) invalidate a machine-bound client by design — see README "What if the hardware changes?". This is a deliberate strict-mode tradeoff, not a bug — see `DECISIONS.md`.
- The `.exe` installer is built exclusively by GitHub Actions CI (`windows-latest`) — this project has no Windows development environment, so that build path is unverified until a real tag triggers it.
- The GUI's interactive behavior (widget layout, form validation feedback) has only been smoke-tested headless (`QT_QPA_PLATFORM=offscreen`) — it has not been visually verified on a real display.
- **Bootstrap circularity — never keep the only copy of the config (or of the generated client) on a share this tool itself mounts.** Doing so deadlocks recovery: the moment that share is unmounted, the config needed to remount it is unreadable, and if the deployed client (which carries the credentials in encrypted form) also lived only there, both routes back are gone at once. Observed on this project's own host on 2026-08-17: `../nas.local.json` sat on the very CIFS share it mounts, so unmounting that share — to try to clear an unrelated stuck server-side lock — left the machine unable to remount at all. Recovery required re-cloning this repo from GitHub, re-running `--emit-collector` on the target machine to recover its fingerprint, and regenerating the client from scratch. **Keep the deployed client on local disk outside any mounted tree** (`--install-service` already does this, installing to `/root/nas-enp-mount/`), and keep a copy of the config somewhere that does not depend on the mount succeeding.

## How to extend

- New client platforms beyond Debian/Ubuntu: the Python client template would need OS-specific mount logic (this one shells out to `mount.cifs`/`mount -t nfs`, both Linux-specific); Windows/macOS clients are an explicit non-goal for now.
- New mount protocols beyond CIFS/NFS: extend the config schema and validation in both the Python client template and `validate()` in `nas-enp-gen.py` together — they must stay in sync since there is no shared schema.
- New generator platforms for the packaged installer (e.g. macOS `.dmg`): add a third GitHub Actions job on `macos-latest` following the same PyInstaller pattern as the `.exe` job.
