# Frontend — Security Log AI Assistant

React + Vite single-page UI for the local Security Log AI Assistant backend.

## Run

```cmd
cd /d C:\Users\27827\Desktop\security-log-ai-assistant\frontend
npm install --registry=https://registry.npmmirror.com
npm run dev
```

The dev server listens on http://localhost:5173 and proxies `/api-backend/*`
to the FastAPI backend on http://127.0.0.1:8000.

## Build

```cmd
npm run build
```

## Notes

- No charting library is used; cards, tables, and badges only.
- No real LLM is contacted; all summarization happens in the local backend.
- All sample IPs are RFC 5737 test addresses (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24).

## AI-assisted disclosure

This project was developed as an AI-assisted learning and engineering
project. AI tools were used for planning, code review, documentation
support, and debugging guidance. All repository commits and project
decisions were managed by the author.
