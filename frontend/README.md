# SentinelSwitch dashboard

React 19 + TypeScript + Vite front end for the SentinelSwitch API.

```bash
npm install
npm run dev      # http://localhost:5173, proxies /api and /diagrams to http://127.0.0.1:8000
npm run build    # frontend/dist, served by the FastAPI app
npm run lint     # oxlint
npx tsc -b       # type-check
```

Structure: `src/pages` (one file per view plus `Media.tsx` for the fixed-size LinkedIn / hero cards),
`src/components` (shell, tables, correlation chain, timeline, switch front panel), `src/charts`
(Recharts wrappers), `src/lib` (typed API client, SSE-aware `useApi` hook, formatting helpers),
`src/styles` (design tokens and component CSS). No UI library; the design system is plain CSS.
