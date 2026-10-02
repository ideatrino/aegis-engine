# Publishing AEGIS to GitHub

The package has no `.git` history, so you commit under your own identity.

## Option A - GitHub CLI (one command to create + push)

```bash
cd aegis-project
git init
git add .
git commit -m "AEGIS v6.4.0 - calibrated Bayesian-consensus antivirus (reference)"
gh repo create aegis-engine --public --source=. --push
```

CI (`.github/workflows/ci.yml`) runs `selftest` + `pytest` on Ubuntu and Windows
across Python 3.11-3.13 on the first push. The `ideatrino/aegis-engine` URLs in
`README.md` and `pyproject.toml` already match this repo name; change them only if
you rename the repo.

## Option B - web + git remote

1. Create an empty repo named `aegis-engine` at https://github.com/new (no README).
2. Then:

```bash
cd aegis-project
git init
git add .
git commit -m "AEGIS v6.4.0"
git branch -M main
git remote add origin https://github.com/<you>/aegis-engine.git
git push -u origin main
```

## Build the standalone app (optional)

```bash
pip install pyinstaller
python build_exe.py            # -> dist/AEGIS(.exe), icon from aegis.ico
```

## What ships

Source (`aegis/`), the bundled trained model (`aegis/data/model.json`), tests,
`pyproject.toml` (installs the `aegis` command), `LICENSE` (MIT), `SECURITY.md`,
`CONTRIBUTING.md`, `CHANGELOG.md`, the logo/icon in `assets/` + `aegis.ico`, and
this guide. `.gitignore` keeps per-user state (`~/.aegis`), build output and
caches out of the repo while keeping the bundled model.

## Not included (by design)

Real malware samples. To strengthen the learned layer, add real labeled samples
to a corpus's `malicious/` **in a VM** (see `SECURITY.md`) and run
`aegis train --corpus <dir>`. For signature coverage today, `aegis blocklist
import <feed>` ingests a public SHA-256/IOC feed.
