# AgentShield — Admin Portal

Real-time threat monitoring dashboard for the Adaptive LLM Firewall. Displays live security events, semantic drift visualization, and a filterable threat log archive.

## Quick Start

```bash
cd frontend-admin
npm install
npm run dev          # → http://localhost:5174
```

Set backend URL in `.env`:
```
VITE_BACKEND_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

## Pages

### Live Dashboard (`/`)
- **Stats bar** — Active sessions, blocked today, honeypot count, total events. Auto-refreshes every 10 seconds from `GET /admin/stats`.
- **Semantic Drift Map** — Plotly.js scatter plot showing session trajectories categorized as Safe (green), Drift (yellow), or Injection (red). Points come from live WebSocket events with x/y coordinates from the drift engine.
- **Live Event Feed** — Real-time stream of security events from all layers. Each event card shows layer badge, action badge, session ID, reason, and OWASP tag. Fed via WebSocket at `/ws/admin`.

### Threat Log (`/threat-log`)
- **Filters** — Action (BLOCKED/REDACTED/FLAGGED/ALLOWED/QUARANTINED), Security Layer, OWASP Tag. Filters send query params to `GET /admin/threat-log` — no client-side filtering.
- **Results Table** — Paginated (20/page), expandable rows with full conversation history. Click any row to see the user/guard turns, risk badges, and detected keywords.
- **Export CSV** — Downloads the current view as a CSV file.

### Settings (`/settings`)
- Display-only page showing role policy thresholds (Guest 0.5 / User 0.65 / Admin 0.85), layer toggles, and system connection info.

## WebSocket
- Connects to `/ws/admin` on mount.
- Auto-reconnects after 3 seconds on disconnect.
- Restores last 20 events from `GET /admin/recent-events` on reconnect.
- Yellow "Reconnecting" state shown in sidebar status indicator.

## Tech Stack
- React 18, Vite, Tailwind CSS v4
- Axios for REST API calls
- Plotly.js (react-plotly.js) for drift map visualization
- DM Sans + JetBrains Mono fonts
