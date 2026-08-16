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
nas-enp-gen.py  --config config.json  --arch amd64,arm64
        |  1. validates config
        |  2. AES-256-GCM encrypts the JSON blob
        |  3. splits/XOR-obfuscates the key, fills it into the Go template
        |  4. `go build` (or emits .go source with --no-build)
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

## Tech stack

| Layer | Choice | Version | Why |
|---|---|---|---|
| Generator | Python | 3.8+ (tested on 3.10) | Scripting the encrypt-and-template step; `cryptography` gives audited AES-GCM |
| Generator crypto | `cryptography` (pyca) | 3.4.8 | Audited, standard choice for AES-256-GCM in Python |
| Client | Go | any toolchain from go.dev | Compiles to a single static, stripped binary — no runtime deps on the client, small attack surface, cross-compiles trivially |
| Client crypto | Go stdlib `crypto/aes`, `crypto/cipher` | stdlib | No third-party Go modules — nothing to vendor or license-track |

Rejected alternatives and reasoning live in `DECISIONS.md`.

## Reproduction requirements

**The most important section. Everything a different machine needs.**

### Environment

- OS (generator machine): any OS with Python 3.8+; Linux recommended since the build target is Linux
- OS (client machine): Debian/Ubuntu Linux, root access
- Runtime + version: Python 3.8+, `cryptography` package
- Optional: Go toolchain, for local compilation (`--no-build` avoids this requirement)
- Dependency restore command: `pip install -r requirements.txt`

### External dependencies

| Item | Source | Placed at |
|---|---|---|
| NAS credentials (host/user/password) | your NAS admin panel | `config.json` (gitignored, never committed) |
| Go toolchain (optional) | https://go.dev/dl/ | system `PATH` |
| `cifs-utils` (client, optional) | client's package manager | auto-installed by the client binary when `install_deps: true` |

Use placeholders, never real values, in anything committed — see `config.example.json`.

### Paths & mounts

Every path below is *supplied by the user's own `config.json`*, not hardcoded in the script:

| Path | Provided by | Purpose |
|---|---|---|
| `mounts[].remote` | user, in config | path on the NAS to mount |
| `mounts[].local` | user, in config | mount point on the client |
| `--out` | CLI flag, default `nas-enp-mount` | where the generator writes the built binary |

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

CLI flags of the generator itself: `--config`, `--arch` (comma-separated, e.g. `amd64,arm64`), `--out`, `--no-build`, `--save-config` (writes the collected config back out — contains the password in cleartext, guard it).

## Setup from scratch

1. On the generator machine: `pip install -r requirements.txt` — verify: `python3 -c "import cryptography"` prints nothing / no error.
2. Copy `config.example.json` to `config.json`, fill in real NAS details — verify: `python3 -m json.tool config.json` parses without error.
3. Run `python3 nas-enp-gen.py --config config.json` — verify: a `nas-enp-mount` binary appears in the working directory.
4. Copy the binary to a test client, run `--selftest` — verify: it reports the config decrypted successfully.
5. Run `--oneshot` on the client — verify: `mount | grep <local path>` shows the share mounted.
6. Run `--install-service` — verify: `systemctl is-enabled nas-enp-mount.service` reports `enabled`.

This project is not deployed with Docker — no docker skill reference needed.

## Data model / file layout

```
repo/
├── nas-enp-gen.py       # the generator — reads config.json, drives the whole pipeline
├── config.example.json  # placeholder shape of the config file (safe to commit)
├── requirements.txt      # pinned generator-side Python dependency
└── (config.json, nas-enp-mount, *.go — build inputs/outputs, all gitignored)
```

The Go client source lives base64-embedded inside `nas-enp-gen.py` (`GO_TEMPLATE_B64`) rather than as a separate `.go` file, so the generator is single-file and self-contained. Use `--no-build` to dump the real `.go` source for inspection.

## Known limitations & gotchas

- `config.example.json` previously held **real production credentials** committed under an "example" filename — this has been corrected (placeholders only, see `DECISIONS.md` 2026-08-16). Real values now live in a gitignored `config.json` outside version control, and the actual working config used on this host is kept at `../nas.local.json` (project root, outside `repo/`, never committed).
- The prebuilt `nas-enp-mount` binary embeds real encrypted credentials for this host's NAS and must never be committed — it is kept at the project root (outside `repo/`), never tracked by git.
- Security is obfuscation, not encryption-that-matters against a root-privileged attacker on the client — see README.
- No automated tests exist yet for the generator or the embedded Go client.
- **`--no-build` currently still requires the `go` binary.** `build()` calls `subprocess.run(["go", "mod", "init", ...])` unconditionally before checking `do_build`, so the documented no-Go-toolchain path (`--no-build`) fails with `FileNotFoundError` when Go isn't installed. Verified on this host. See `STATUS.md` — not yet fixed.

## How to extend

- New client platforms: the Go template in `GO_TEMPLATE_B64` would need a second variant; consider externalizing it to a real `.go` file with build tags before doing this — the base64-blob-in-Python approach does not scale past one target OS.
- New mount protocols beyond CIFS/NFS: extend `MountSpec`/`Config` in the Go template and `validate()` in `nas-enp-gen.py` together — they must stay in sync since there is no shared schema.
