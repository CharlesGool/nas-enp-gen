# Status — updated 2026-08-16

**Version:** unreleased · **Branch:** main
**Notion:** not yet synced
**Repo:** https://github.com/CharlesGool/nas-enp-gen (public)
**Snapshots:** maintained privately (not published) — none yet, first snapshot is cut at v0.1.0
**In progress:** normalized the project to full-tier structure per the project-management skill (doc skeleton, `.gitignore`, `requirements.txt`, sanitized `config.example.json`); fixed the `--no-build` bug (see below).
**Next:** install a Go toolchain to verify the real `go build` path, then cut `v0.1.0` once the release checklist passes.
**Known issues:**
- no automated tests.
- Go toolchain not installed on this host, so the actual `go build` path (non-`--no-build`) remains unverified here.
**Blocked on:** installing Go (or verifying on a host that already has it) to exercise the primary `go build` path before cutting `v0.1.0`.
