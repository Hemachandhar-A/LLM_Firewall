# AgentShield — End User Site

Interactive chat interface for the Adaptive LLM Firewall. Every message is sent through 9 security layers before the LLM processes it.

## Quick Start

```bash
cd frontend-user
npm install
npm run dev          # → http://localhost:5173
```

Set backend URL in `.env`:
```
VITE_BACKEND_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_ADMIN_URL=http://localhost:5174
```

## Pages

### Landing Page (`/`)
Product marketing page with hero section, feature cards, and demo terminal animation.

### Chat Interface (`/chat`)
Interactive security demo. Type any message and watch the firewall pipeline process it in real time.

## Attack Scenario Buttons

| Button | What It Does |
|--------|-------------|
| **Hinglish Injection** | Sends a bilingual (Hindi + English) prompt injection asking the system to reveal its system prompt. Tests Layer 1 (Indic classifier). |
| **Tool Poisoning** | Sends a request to read `/etc/passwd` via a tool. Tests Layer 2 (Tool/RAG scanner). |
| **Memory Bomb** | Attempts to inject a persistent instruction into agent memory. Tests Layer 3 (Memory auditor). |
| **Crescendo Attack** | Cycles through 5 increasingly manipulative messages (social engineering). Tests Layer 4 (Drift engine). Click 5 times to see the full escalation. |
| **Cross-Agent Hijack** | Tells the agent to relay commands to other agents. Tests Layer 7 (Cross-agent interceptor). |

## Reading Responses

- **Normal response** — Dark bubble with AgentShield AI avatar. The message passed all security layers.
- **BLOCKED response** — Red-tinted bubble with "FIREWALL BLOCKED" header, reason code, and severity. The firewall intercepted the message.
- **Error message** — Gray bubble. The backend is unreachable.

## Tech Stack
- React 18, Vite, Tailwind CSS v4
- Axios for API calls
- DM Sans + JetBrains Mono fonts
