# Decisions

Newest first. Append only — never delete or rewrite an entry. To reverse a past
decision, add a new entry that says so explicitly.

**Read this file before proposing any technical approach.** Without it, an
already-rejected option gets recommended again two weeks later.

---

## 2026-08-16 — Normalize project to full-tier structure

- **Context:** Project existed as a flat folder (`nas-enp-gen.py`, `README.md`, empty `Design.md`, `config.example.json`, a prebuilt `nas-enp-mount` binary) with no `repo/`/`snapshots/` split, no git repo, no `.gitignore`, no lockfile. It has real config/secrets and is meant to be deployed to other machines, so it qualifies for full-tier per the project-management skill.
- **Decision:** Restructure into the standard `<project>/{repo,snapshots}` layout, add the full bilingual doc set (README/DESIGN in EN+ZH, CHANGELOG, STATUS, DECISIONS), `.gitignore`, `requirements.txt`, `git init -b main` with the `CharlesGool` noreply identity, and a GitHub remote.
- **Rejected:** Leaving it as a light-tier flat folder — ruled out because it has an `.env`-equivalent config file with real secrets and is designed for cross-machine deployment, both of which are explicit upgrade triggers in the skill.
- **Consequences:** All future work happens under `repo/`; releases go through the tag + snapshot process instead of ad hoc copying.

## 2026-08-16 — Strip real NAS credentials out of `config.example.json`

- **Context:** The pre-existing `config.example.json` at the project root contained the *real* production NAS credentials (a real internal host IP, a real account name, and a real password) for the NAS that backs this maintainer's local project storage — despite being named "example" and about to become a git-tracked file.
- **Decision:** `repo/config.example.json` now contains only placeholder values (`192.0.2.10`, `your-nas-user`, `your-nas-password`, generic paths). The real values were moved to `nas.local.json` at the project root (outside `repo/`, outside git, never committed) so the working config isn't lost. `config.json` (the name a user is instructed to `cp` to) is gitignored so future local configs never accidentally get committed either.
- **Rejected:** Keeping the real values in `config.example.json` and just gitignoring the file going forward — rejected because "example" files are expected to be safe to commit and to read; a gitignored file named "example" is a trap for the next person (or session) who forgets to check.
- **Consequences:** The prebuilt `nas-enp-mount` binary at the project root also embeds these real (encrypted) credentials and is likewise kept outside `repo/`/git for the same reason.

## 2026-08-16 — Go public under Apache-2.0

- **Context:** User asked to make the repo public. Sole runtime dependency (`cryptography`) is dual BSD/Apache-2.0, not vendored — no copyleft, no NOTICE-triggering obligations. Full-history and commit-metadata review found no leaked credentials in git history (the real NAS credentials were caught before the first commit, see the entry above); a real internal host IP, account name, and local absolute paths that had leaked into `DECISIONS.md`/`STATUS.md` prose were redacted before the repo went public.
- **Decision:** License the project under Apache License 2.0 (`LICENSE`, `README.md`/`README.zh.md` updated); flip the GitHub repo to public.
- **Rejected:** "All rights reserved" (public but no reuse license) — user preferred a permissive open-source license over restricting reuse. MIT was also offered — user chose Apache-2.0 for its explicit patent grant.
- **Consequences:** Third parties may now use, modify, and redistribute this code under Apache-2.0 terms, including commercially. Any future vendored third-party content must be checked for Apache-2.0 compatibility before being added.
