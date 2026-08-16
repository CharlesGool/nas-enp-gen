# Status — updated 2026-08-16

**Version:** unreleased · **Branch:** main
**Notion:** not yet synced
**Repo:** https://github.com/CharlesGool/nas-enp-gen (private)
**Snapshots:** `/root/MyGithub_Project/nas-enp-gen/snapshots` (none yet — first snapshot is cut at v0.1.0)
**In progress:** normalized the project to full-tier structure per the project-management skill (doc skeleton, `.gitignore`, `requirements.txt`, sanitized `config.example.json`).
**Next:** fix the `--no-build` bug below (or decide to accept it), install a Go toolchain to verify the real `go build` path, then cut `v0.1.0` once the release checklist passes.
**Known issues:**
- no automated tests.
- `--no-build` is documented (README/DESIGN) as the no-Go-toolchain path, but `build()` in `nas-enp-gen.py` calls `subprocess.run(["go", "mod", "init", ...])` unconditionally at line 274, *before* the `if not do_build: return` branch — so `--no-build` still requires the `go` binary to exist and fails with `FileNotFoundError` if it doesn't. Verified on this host (no Go toolchain installed). Pre-existing bug, not introduced by this normalization pass — not fixed here since it's outside the scope of "restructure per project-management skill," but it blocks a real release-checklist pass (`--no-build` is a documented, load-bearing code path).
- Go toolchain not installed on this host, so the actual `go build` path (non-`--no-build`) is also unverified here.
**Blocked on:** deciding whether to fix the `--no-build` bug now or install Go to verify the primary build path — either way, do not cut `v0.1.0` until one of those two verifications actually passes.
