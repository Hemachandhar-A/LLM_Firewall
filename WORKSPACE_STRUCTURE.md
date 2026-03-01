#  AMD Workspace Structure

> **Last Updated**: July 2025  
> **Status**:  Full-Stack Production Ready (Backend + Frontend-User + Frontend-Admin)

Complete file-by-file reference for the **Adaptive LLM Firewall with Red Teaming** workspace.

---

##  Overview

| Category | Files | Status |
|----------|-------|--------|
| Backend classifiers | 9 Python modules |  Complete |
| Backend API layer | 7 Python modules |  Complete |
| Frontend (User) | 8 source files |  Complete |
| Frontend (Admin) | 8 source files |  Complete |
| Tests | 14 test files |  800+ tests passing |
| Data files | 5 files |  Present |
| Documentation | 3 files |  Consolidated |
| Config / Utility | 5 files |  Complete |

---

##  Directory Tree

```
AMD/
 backend/                              PYTHON BACKEND (FastAPI + Classifiers)
    .env                             Environment variables (GROQ_API_KEY, SUPABASE_URL, etc.)
    .env.example                     Template for .env
    main.py                          FastAPI app assembly, CORS, route registration (port 8000)
    config.py                        Pydantic Settings: env loading, API key management
    requirements.txt                 Full backend dependencies (FastAPI, Uvicorn, Supabase, etc.)
    requirements-classifiers.txt     ML/classifier dependencies (transformers, torch, etc.)
   
    api/                              API LAYER (FastAPI routes + infrastructure)
       __init__.py                  Module exports
       chat.py                      POST /chat/message - 5-layer pipeline + honeypot (467 lines)
       admin.py                     Admin dashboard API - 8 endpoints (350+ lines)
       db.py                        Supabase database layer - async fire-and-forget (540 lines)
       event_emitter.py             WebSocket event broadcaster - asyncio.gather (185 lines)
       websocket.py                 /ws/admin WebSocket endpoint
       session_manager.py           Session CRUD, risk tracking, memory hashing (291 lines)
       llm_client.py               Groq primary + Ollama/Groq honeypot LLM (308 lines)
   
    classifiers/                      SECURITY LAYERS (9 classifiers)
       __init__.py                  Module exports (24 lines)
       base.py                      ClassifierResult + FailSecureError contracts (45 lines)
       indic_classifier.py          Layer 1: Indic threat detection (546 lines)
       rag_scanner.py               Layer 2A: RAG chunk injection scanner (450+ lines)
       tool_scanner.py              Layer 2B: MCP tool metadata scanner (566 lines)
       memory_auditor.py            Layer 3: Memory integrity checker (400+ lines)
       drift_engine.py              Layer 4: Semantic drift velocity (243 lines)
       output_guard.py              Layer 5: PII/leakage/exfiltration guard (535 lines)
       adaptive_engine.py           Layer 8: Dynamic pattern learning (404 lines)
       data/                         PRE-GENERATED ML DATA
           attack_seeds.json        21 attack embeddings (384-dim vectors, ~50KB)
           attack_seeds.json.backup Backup of attack seeds
           cluster_centroids.json   6 threat cluster centroids (~15KB)
           malicious_domains.json   Known C2/phishing/botnet domains
           umap_model.pkl           UMAP 384-to-2D visualization model (~2MB)
   
    tests/                            BACKEND INFRASTRUCTURE TESTS (111 tests)
        test_event_emitter.py        WebSocket event system: 59 tests 
        test_db.py                   Supabase database layer: 52 tests 

 frontend-user/                        USER CHAT INTERFACE (React + Vite)
    .env                             VITE_BACKEND_URL, VITE_WS_URL, VITE_ADMIN_URL
    index.html                       SPA entry (DM Sans + JetBrains Mono fonts)
    package.json                     React 19, Axios, react-router-dom, Tailwind v3
    vite.config.js                   Vite 7.3.1 config (port 5173, proxy to :8000)
    tailwind.config.js               Tailwind v3 config (dark theme, red accent)
    postcss.config.js                PostCSS: Tailwind + Autoprefixer
    eslint.config.js                 ESLint config
    public/                          Static assets (vite.svg)
    dist/                            Production build output
    src/                              SOURCE CODE
        main.jsx                     React entry point (BrowserRouter)
        App.jsx                      Routes: / -> LandingPage, /chat -> ChatPage
        api.js                       sendMessage() - POST /chat/message via Axios
        index.css                    Tailwind directives + dark theme globals
        components/
           Icons.jsx                ~15 SVG icon components (Shield, Lock, Brain, etc.)
        pages/
            LandingPage.jsx          Hero, feature cards, terminal demo, CTA, footer
            ChatPage.jsx             Chat UI: attack buttons, message bubbles, typing
                                          indicator, 5-turn Crescendo cycling (523 lines)

 frontend-admin/                       ADMIN DASHBOARD (React + Vite + Plotly)
    .env                             VITE_BACKEND_URL, VITE_WS_URL
    index.html                       SPA entry (DM Sans + JetBrains Mono fonts)
    package.json                     React 19, Axios, Plotly.js, react-plotly.js, Tailwind v3
    vite.config.js                   Vite 7.3.1 config (port 5174, proxy to :8000)
    tailwind.config.js               Tailwind v3 config (dark theme, red accent)
    postcss.config.js                PostCSS: Tailwind + Autoprefixer
    eslint.config.js                 ESLint config
    public/                          Static assets (vite.svg)
    dist/                            Production build output
    src/                              SOURCE CODE
        main.jsx                     React entry point (BrowserRouter)
        App.jsx                      WebSocket manager, auto-reconnect, AdminLayout routes
        api.js                       fetchStats, fetchThreatLog, fetchSessionDetail,
                                         fetchRecentEvents, fetchActiveSessions, createAdminWebSocket
        index.css                    Tailwind directives + dark theme globals
        components/
           AdminLayout.jsx          240px sidebar (Live Dashboard, Threat Log, Settings)
        pages/
            LiveDashboard.jsx        StatCards, Plotly scatter plot, real-time EventCards
            ThreatLog.jsx            Filters, paginated table, expandable rows, CSV export
            Settings.jsx             ThresholdSlider, Layer toggles, System info panel

 tests/                                CLASSIFIER + PIPELINE TEST SUITES (690+ tests)
    conftest.py                      Shared pytest configuration
    test_indic_classifier.py         Layer 1 tests: 95+ tests 
    test_rag_scanner.py              Layer 2A tests: 50+ tests 
    test_tool_scanner.py             Layer 2B tests: 64 tests 
    test_memory_auditor.py           Layer 3 tests: 38+ tests 
    test_drift_engine.py             Layer 4 tests: 6+ tests 
    test_output_guard.py             Layer 5 tests: 85+ tests 
    test_adaptive_engine.py          Layer 8 tests: 68 tests 
    test_chat_endpoint.py            Chat pipeline: 39 tests 
    test_admin_endpoints.py          Admin API: 87 tests 
    test_session_manager.py          Session manager: 64 tests 
    test_llm_client.py              LLM client: 50 tests  (integration)

 generate_embeddings.py                Utility: Regenerate attack embeddings
 pytest.ini                           Pytest configuration
 .gitignore                           Git ignores

 MASTER_GUIDE.md                       SINGLE SOURCE OF TRUTH (complete reference)
 README.md                             QUICK ENTRY POINT (overview + quickstart)
 WORKSPACE_STRUCTURE.md                You are here (directory reference)
```

---

##  Frontend Details

### Frontend-User (Port 5173)

| File | Purpose | Lines |
|------|---------|-------|
| `App.jsx` | Routes: `/` -> LandingPage, `/chat` -> ChatPage | ~30 |
| `api.js` | `sendMessage(session_id, message, role)` via Axios | ~20 |
| `Icons.jsx` | 15 SVG icon components (Shield, Lock, Brain, Terminal, etc.) | ~200 |
| `LandingPage.jsx` | Marketing page: Hero, TerminalBlock, Features, CTA, Footer | ~400 |
| `ChatPage.jsx` | Full chat UI with attack scenario buttons, message bubbles, typing indicator, 5-turn Crescendo cycling | ~523 |

**Key Features**:
- Dark theme (#0a0a0a background, #ef4444 red accent)
- DM Sans body + JetBrains Mono code fonts
- 6 pre-built attack scenario buttons (Prompt Injection, Hinglish, System Prompt, Crescendo, Memory Bomb, Data Exfil)
- Real-time message classification with blocked/passed visual states
- Responsive Tailwind v3 layout

### Frontend-Admin (Port 5174)

| File | Purpose | Lines |
|------|---------|-------|
| `App.jsx` | WebSocket lifecycle management, auto-reconnect, route wrapper | ~80 |
| `api.js` | 6 API functions: fetchStats, fetchThreatLog, fetchSessionDetail, fetchRecentEvents, fetchActiveSessions, createAdminWebSocket | ~80 |
| `AdminLayout.jsx` | 240px sidebar with nav links + main content area | ~80 |
| `LiveDashboard.jsx` | Stat cards, Plotly scatter chart, real-time event feed | ~300 |
| `ThreatLog.jsx` | Filter bar, paginated table, expandable detail rows, CSV export | ~350 |
| `Settings.jsx` | Threshold sliders, layer toggle switches, system info panel | ~250 |

**Key Features**:
- Same dark design system as user frontend
- Real-time WebSocket events from `ws://localhost:8000/ws/admin`
- Plotly.js scatter visualization for threat clusters
- CSV export for threat log data
- Auto-reconnecting WebSocket with 3s backoff

---

##  Test Summary

| Component | Test File | Tests | Status |
|-----------|-----------|-------|--------|
| Layer 1 (Indic Classifier) | `test_indic_classifier.py` | 95+ |  |
| Layer 2A (RAG Scanner) | `test_rag_scanner.py` | 50+ |  |
| Layer 2B (Tool Scanner) | `test_tool_scanner.py` | 64 |  |
| Layer 3 (Memory Auditor) | `test_memory_auditor.py` | 38+ |  |
| Layer 4 (Drift Engine) | `test_drift_engine.py` | 6+ |  |
| Layer 5 (Output Guard) | `test_output_guard.py` | 85+ |  |
| Layer 8 (Adaptive Engine) | `test_adaptive_engine.py` | 68 |  |
| Chat Pipeline | `test_chat_endpoint.py` | 39 |  |
| Admin API | `test_admin_endpoints.py` | 87 |  |
| Session Manager | `test_session_manager.py` | 64 |  |
| LLM Client | `test_llm_client.py` | 50 |  |
| WebSocket Events | `test_event_emitter.py` | 59 |  |
| Supabase DB | `test_db.py` | 52 |  |
| **Total** | **13 files** | **800+** | ** ALL PASS** |

---

##  Documentation Navigation

| Need | File |
|------|------|
| Quick overview | [README.md](./README.md) |
| Complete reference | [MASTER_GUIDE.md](./MASTER_GUIDE.md) |
| Directory structure | [WORKSPACE_STRUCTURE.md](./WORKSPACE_STRUCTURE.md) (this file) |

---

**Last Updated**: July 2025  
**Status**:  Full-Stack Production Ready (Layers 1-5, 8 + Chat Pipeline + Admin API + Both Frontends)
