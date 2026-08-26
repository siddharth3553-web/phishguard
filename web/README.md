# PhishGuard web UI

React 19 + Vite + TypeScript. Dev server proxies `/api`, `/health`, `/ready`, `/metrics` to the FastAPI app on `:8000`.

```bash
npm install
npm run dev    # http://127.0.0.1:5173
npm run build  # output → dist/ (served by nginx in Compose)
```
