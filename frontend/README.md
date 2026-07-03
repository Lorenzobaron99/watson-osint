# Watson Frontend

React UI (Vite + Tailwind) for the Watson OSINT investigation engine.

## Develop

```bash
cd frontend
npm install
npm run dev         # Dev server with HMR
```

## Build

Build output goes directly to `watson/web/static/` (served by the FastAPI backend).

```bash
npm run build
```

The built frontend is committed to the repo — users don't need Node.js to run Watson.
