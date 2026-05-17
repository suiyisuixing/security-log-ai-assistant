# Contributing

This is a personal portfolio / learning project. External contributions are
not expected, but the development conventions below are documented for
transparency.

## Setup

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
cd frontend
npm install
```

## Validation

Before any commit:

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m compileall backend\app tests tools
cd frontend && npm run build
```

Or, equivalently:

```cmd
.venv\Scripts\python.exe tools\run_checks.py
```

## Style

- Python: standard library + FastAPI + Pydantic. Keep modules focused and
  pure where possible.
- Frontend: vanilla React + Vite, plain CSS, no extra UI frameworks.

## Sample data discipline

- Never add real customer logs.
- Use RFC 5737 test IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) for any external-looking addresses.
- Do not reference real production domains.

## Disclosure

This project was developed as an AI-assisted learning and engineering
project. AI tools were used for planning, code review, documentation
support, and debugging guidance, while all repository commits and project
decisions were managed by the author.
