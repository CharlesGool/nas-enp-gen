# nas-enp-mount — Design

**English** | [简体中文](DESIGN.zh.md)

> Success criterion for this document: someone else, on a different machine,
> can rebuild this project from it. Assume the reader cannot see your machine.

## Goals & non-goals

**Goals**
- Let a Linux client auto-mount NAS (CIFS/NFS) shares at boot without a plaintext credentials file on that client's disk.
- Make credential rotation a one-step process: regenerate the binary, redeploy it.
- Fail safe: an unreachable NAS must never hang or break boot on the client.

**Non-goals**
- True secrecy against a root-privileged attacker on the client — impossible by construction, since the client must itself recover the credentials to mount the share. See README's "Honest security note."
- Cross-platform clients (Windows/macOS) — Debian/Ubuntu Linux only.
- A general secrets-management or config-distribution system.

## Architecture

```
config.json (real secrets, never committed)
        |
        v
nas-enp-gen.py                      nas-enp-gen.py --config config.json
  (no args -> PySide6 GUI form)       (headless / scripted, or --cli for
        |                              terminal prompts)
        |  1. validates config
        |  2. AES-256-GCM encrypts the JSON blob
        |  3. splits/XOR-obfuscates the key, fills it into the Go client template
        |  4. `go build` (or emits .go source with --no-build / the GUI checkbox)
        v
nas-enp-mount (per-arch static binary, embeds ciphertext + obfuscated key)
        |
        |  copied to each client, run as root
        v
client binary
        |  --selftest      decrypt in memory, verify, print nothing sensitive
        |  --oneshot        mount each configured share (idempotent, retries)
        |  --install-service  write systemd unit, enable, start
        v
mounted CIFS/NFS shares on the client
```

The generator itself is also packaged as installable `.deb` (Linux) and `.exe`
(Windows) desktop apps — see "Packaging & CI" below — for people who'd rather
double-click a form than run a CLI. The deployed mount client is never
packaged this way; it stays a plain static binary driven by systemd, with no GUI.

## Tech stack

| Layer | Choice | Version | Why |
|---|---|---|---|
| Generator | Python | 3.8+ (tested on 3.10) | Scripting the encrypt-and-template step; `cryptography` gives audited AES-GCM |
| Generator crypto | `cryptography` (pyca) | 3.4.8 | Audited, standard choice for AES-256-GCM in Python |
| Generator GUI | PySide6 (Qt for Python) | latest | LGPLv3 — compatible with staying permissively (Apache-2.0) licensed, unlike GPL/commercial PyQt. See `DECISIONS.md` 2026-08-16. |
| Generator packaging | PyInstaller + `dpkg-deb` (Linux), PyInstaller (Windows, via CI) | latest | Single-file executables wrapped into installers; Windows build runs on GitHub Actions `windows-latest` since this project has no local Windows environment |
| Client | Go | any toolchain from go.dev | Compiles to a single static, stripped binary — no runtime deps on the client, small attack surface, cross-compiles trivially. Reverted from a pure-Python client (2026-08-16, same day) after real deployment testing showed a plaintext `.py` client is too easy to inspect/de-obfuscate; a PyInstaller-repackaged Python client was considered and rejected as not meaningfully more opaque. See `DECISIONS.md` 2026-08-16 (both entries). |
| Client crypto | Go stdlib `crypto/aes`, `crypto/cipher` | stdlib | No third-party Go modules — nothing to vendor or license-track |

Rejected alternatives and reasoning live in `DECISIONS.md`.

## Packaging & CI

- `packaging/nas-enp-gen.spec` — PyInstaller spec for the generator GUI/CLI single-file executable.
- `packaging/build-deb.sh` — runs PyInstaller, assembles a `DEBIAN/control` tree, and calls `dpkg-deb --build` to produce `nas-enp-gen_<version>_amd64.deb`. Runs and is testable on this Linux host.
- `.github/workflows/release-installers.yml` — triggers on `v*.*.*` tag pushes. Builds the `.deb` on `ubuntu-latest` and the `.exe` on `windows-latest`, uploads both as GitHub Release assets. The `.exe` build is CI-only — it cannot be produced or verified on this (Linux) development host.

## Reproduction requirements

**The most important section. Everything a different machine needs.**

### Environment

- OS (generator machine): any OS with Python 3.8+ — Linux, Windows, or macOS. GUI mode needs a display; `--config`/`--cli` modes don't.
- OS (client machine): Debian/Ubuntu Linux, root access
- Runtime + version: Python 3.8+ with `cryptography` on the generator machine
- Go toolchain (https://go.dev/dl/) on the generator machine to compile, OR use `--no-build` (CLI) / the "emit Go source only" checkbox (GUI) to emit `.go` source and compile on any Linux box instead
- Optional (dev/CI only, not needed to run the project): PyInstaller + `dpkg-deb` to build the generator's `.deb` installer locally; GitHub Actions `windows-latest` runner builds the generator's `.exe`
- Dependency restore command: `pip install -r requirements.txt`

### External dependencies

| Item | Source | Placed at |
|---|---|---|
| NAS credentials (host/user/password) | your NAS admin panel | `config.json` (gitignored, never committed) |
| Go toolchain | https://go.dev/dl/ | system `PATH` on the generator machine (not needed on clients — the output is a static binary) |
| `cifs-utils` (client, optional) | client's package manager | auto-installed by the client binary when `install_deps: true` |

Use placeholders, never real values, in anything committed — see `config.example.json`.

### Paths & mounts

Every path below is *supplied by the user's own `config.json`*, not hardcoded in the script:

| Path | Provided by | Purpose |
|---|---|---|
| `mounts[].remote` | user, in config | path on the NAS to mount |
| `mounts[].local` | user, in config | mount point on the client |
| `--out` | CLI flag, default `nas-enp-mount` | where the generator writes the built binary (or `.go` source with `--no-build`) |

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
| `default_options` | mount options applied to every share unless overridden | — | yes |
| `mounts` | array of `{remote, local, options}` | — | yes, at least one |
| `retry_attempts` | client-side mount retry count | — | yes |
| `retry_delay_sec` | seconds between retries | — | yes |
| `install_deps` | let the client `apt install cifs-utils` if missing | — | yes |

CLI flags of the generator itself: `--config` (headless/scripted), `--cli` (force the old terminal-prompt flow instead of the GUI), `--arch` (comma-separated Go arches, default `amd64`), `--out`, `--no-build` (emit `.go` source instead of compiling), `--save-config` (writes the collected config back out — contains the password in cleartext, guard it). No arguments launches the PySide6 GUI, which has equivalent controls (an arch field, an "emit Go source only" checkbox).

## Setup from scratch

1. On the generator machine: `pip install -r requirements.txt` — verify: `python3 -c "import cryptography, PySide6"` prints nothing / no error. Also install a Go toolchain (or plan to use `--no-build`).
2. Copy `config.example.json` to `config.json`, fill in real NAS details — verify: `python3 -m json.tool config.json` parses without error.
3. Run `python3 nas-enp-gen.py --config config.json` (or launch the GUI with no args and fill the form) — verify: a `nas-enp-mount` binary appears in the working directory.
4. Copy the binary to a test client, run `--selftest` — verify: it reports the config decrypted successfully.
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
└── (config.json, nas-enp-mount, *.go, dist/ — generator/build outputs, all gitignored)
```

The Go client source lives base64-embedded inside `nas-enp-gen.py` (`GO_TEMPLATE_B64`) rather than as a separate `.go` file, so the generator is single-file and self-contained. Use `--no-build` (or the GUI's "emit Go source only" checkbox) to dump the real `.go` source for inspection.

## Known limitations & gotchas

- `config.example.json` previously held **real production credentials** committed under an "example" filename — this has been corrected (placeholders only, see `DECISIONS.md` 2026-08-16). Real values now live in a gitignored `config.json` outside version control, and the actual working config used on this host is kept at `../nas.local.json` (project root, outside `repo/`, never committed).
- Security is obfuscation, not encryption-that-matters against a root-privileged attacker on the client — see README.
- No automated tests exist yet for the generator or the embedded Go client.
- The `.exe` **generator** installer is built exclusively by GitHub Actions CI (`windows-latest`) — this project has no Windows development environment, so that build path is unverified until a real tag triggers it. (This is separate from the client binary, which compiles fine on this Linux dev host — see below.)
- The GUI's interactive behavior has been visually verified by the user on a real Windows display for the base form; the bilingual language switcher and the new arch/emit-source controls added afterward have only been smoke-tested headless (`QT_QPA_PLATFORM=offscreen`) here, not yet re-confirmed visually.
- The **real `go build` path is now verified** on this dev host (Go 1.18 via `apt-get install golang-go`): single-arch build, multi-arch cross-compile (`amd64,arm64`), and `--no-build` source emission were all exercised end-to-end, producing a stripped static ELF binary whose `--selftest`/`--help` both work correctly. Not yet verified: building on a non-Debian/Ubuntu generator OS, or arches beyond amd64/arm64.

## How to extend

- New client platforms: the Go template in `GO_TEMPLATE_B64` would need a second variant; consider externalizing it to a real `.go` file with build tags before doing this — the base64-blob-in-Python approach does not scale past one target OS.
- New mount protocols beyond CIFS/NFS: extend `MountSpec`/`Config` in the Go template and `validate()` in `nas-enp-gen.py` together — they must stay in sync since there is no shared schema.
- New generator platforms for the packaged installer (e.g. macOS `.dmg`): add a third GitHub Actions job on `macos-latest` following the same PyInstaller pattern as the `.exe` job.
