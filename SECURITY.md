# Security & secrets hygiene

## Automated scan (this repo)

From the project root (excluding `.venv`):

```powershell
.\.venv\Scripts\python .\scripts\scan_secrets.py
```

To exclude third-party vulnerable apps (e.g. PyGoat) if you vendor them locally:

```powershell
.\.venv\Scripts\python .\scripts\scan_secrets.py --exclude pygoat --exclude PyGoat
```

## What to exclude from GitHub publication

| Path / pattern | Reason |
|----------------|--------|
| `.venv/`, `venv/` | Local dependencies, large |
| `.env`, `.env.local` | Real secrets |
| `pygoat/`, `PyGoat/` | External OWASP training app; contains intentional vulnerabilities |
| `models/checkpoints/` | Large binary weights |
| `**/__pycache__/` | Build artifacts |

## Heimdall core scope (safe to publish)

These directories are the **first-party** analyzer:

- `src/heimdall/`
- `scripts/analyze.py`, `scripts/scan_secrets.py`
- `examples/` (synthetic vulnerability demos only; no real credentials)
- `pyproject.toml`, `requirements.txt`, `README.md`

## If you add real credentials later

1. Put values only in `.env` (see `.env.example`).
2. Load via `os.environ.get("VAR_NAME")` or `python-dotenv` in entry scripts.
3. Re-run `scripts/scan_secrets.py` before pushing.
