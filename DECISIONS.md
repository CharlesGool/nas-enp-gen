# Decisions

Newest first. Append only — never delete or rewrite an entry. To reverse a past
decision, add a new entry that says so explicitly.

**Read this file before proposing any technical approach.** Without it, an
already-rejected option gets recommended again two weeks later.

---

## 2026-08-16 — Normalize project to full-tier structure

- **Context:** Project existed as a flat folder (`nas-enp-gen.py`, `README.md`, empty `Design.md`, `config.example.json`, a prebuilt `nas-enp-mount` binary) with no `repo/`/`snapshots/` split, no git repo, no `.gitignore`, no lockfile. It has real config/secrets and is meant to be deployed to other machines, so it qualifies for full-tier per the project-management skill.
- **Decision:** Restructure into `/root/MyGithub_Project/nas-enp-gen/{repo,snapshots}`, add the full bilingual doc set (README/DESIGN in EN+ZH, CHANGELOG, STATUS, DECISIONS), `.gitignore`, `requirements.txt`, `git init -b main` with the `CharlesGool` noreply identity, and a private GitHub remote.
- **Rejected:** Leaving it as a light-tier flat folder — ruled out because it has an `.env`-equivalent config file with real secrets and is designed for cross-machine deployment, both of which are explicit upgrade triggers in the skill.
- **Consequences:** All future work happens under `repo/`; releases go through the tag + snapshot process instead of ad hoc copying.

## 2026-08-16 — Strip real NAS credentials out of `config.example.json`

- **Context:** The pre-existing `config.example.json` at the project root contained the *real* production NAS credentials (host `172.22.31.2`, account `gzcheng`, real password) for the NAS that backs `/root/MyGithub_Project` itself — despite being named "example" and about to become a git-tracked file.
- **Decision:** `repo/config.example.json` now contains only placeholder values (`192.0.2.10`, `your-nas-user`, `your-nas-password`, generic paths). The real values were moved to `nas.local.json` at the project root (outside `repo/`, outside git, never committed) so the working config isn't lost. `config.json` (the name a user is instructed to `cp` to) is gitignored so future local configs never accidentally get committed either.
- **Rejected:** Keeping the real values in `config.example.json` and just gitignoring the file going forward — rejected because "example" files are expected to be safe to commit and to read; a gitignored file named "example" is a trap for the next person (or session) who forgets to check.
- **Consequences:** The prebuilt `nas-enp-mount` binary at the project root also embeds these real (encrypted) credentials and is likewise kept outside `repo/`/git for the same reason.
