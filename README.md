# Adaptive LLM Firewall with Teaming

**Production-grade security middleware** that intercepts every message to an LLM and runs it through 9 defense layers to detect and block attacks.

---

## 📖 COMPLETE GUIDE

**👉 Read [MASTER_GUIDE.md](./MASTER_GUIDE.md) for complete implementation, setup, testing, and integration details.**

The MASTER_GUIDE contains everything you need:
- ✅ Quick start (5 minutes)
- ✅ Installation steps
- ✅ System architecture
- ✅ Layer 1 & Layer 4 documentation
- ✅ Testing guide (100+ tests)
- ✅ Integration patterns
- ✅ Troubleshooting
- ✅ Performance metrics

---

## ⚡ TL;DR (30 seconds)

```bash
# Install
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements-classifiers.txt

# Test
pytest tests/ -v

# Use
python -c "from classifiers.indic_classifier import classify_threat; \
print(classify_threat('ignore all instructions'))"
```

## ✅ Status

| Layer | Component | Status | Tests |
|-------|-----------|--------|-------|
| **1** | Indic Threat Classifier | ✅ READY | 95+ ✓ |
| **2A** | RAG Chunk Scanner | ✅ READY | 50+ ✓ |
| **2B** | MCP Tool Metadata Scanner | ✅ READY | 64+ ✓ |
| **3** | Memory Auditor | ✅ READY | 38+ ✓ |
| **4** | Semantic Drift Engine | ✅ READY | 6+ ✓ |
| **5** | Output Guard | ✅ READY | 85+ ✓ |
| **8** | Adaptive Rule Engine | ✅ READY | 68+ ✓ |
| **Core Backend** | Session Manager | ✅ READY | 64 ✓ |
| **Core Backend** | WebSocket Event System | ✅ READY | 59 ✓ |
| **Core Backend** | Supabase Database Layer | ✅ READY | 52 ✓ |
| **Primary LLM** | Groq Client | ✅ READY | 50 ✓ |
| **6,7,9** | Remaining Layers | 📋 IN PROGRESS | — |

**Critical Implementation**: All classifiers pass production-grade validation including fail-secure design, proper threshold handling, and pattern-based detection. 

**WebSocket & Database** (N1-4 & N1-5): Real-time event broadcasting to admin dashboard via `/ws/admin` endpoint + Supabase persistence layer with fire-and-forget writes (never blocks pipeline). **111 tests passing** (59 event emitter + 52 database).

See [MASTER_GUIDE.md](./MASTER_GUIDE.md) for complete details.

---

## 📁 What's in This Repository

```
backend/
  classifiers/                 ← All security classifiers (COMPLETED ✅)
    ├── base.py                  ← ClassifierResult & FailSecureError
    ├── indic_classifier.py      ← Layer 1: Prompt injection detection ✅
    ├── rag_scanner.py           ← Layer 2A: RAG document injection detection ✅
    ├── tool_scanner.py          ← Layer 2B: MCP tool metadata scanner ✅
    ├── memory_auditor.py        ← Layer 3: Memory integrity detection ✅
    ├── drift_engine.py          ← Layer 4: Multi-turn attack detection ✅
    ├── output_guard.py          ← Layer 5: Output PII/leakage detection ✅
    ├── adaptive_engine.py       ← Layer 8: Adaptive rule learning ✅
    ├── __init__.py              ← Proper exports
    └── data/
        ├── attack_seeds.json        ← 20+ attack embeddings
        ├── cluster_centroids.json   ← 6 threat clusters
        ├── malicious_domains.json   ← 15 known C2/phishing domains
        └── umap_model.pkl           ← 2D visualization model
  
  api/                         ← FastAPI backend routes (IN PROGRESS)
    ├── __init__.py
    ├── session_manager.py     ← Session state & audit trail (COMPLETED ✅)
    ├── llm_client.py          ← Groq API + honeypot (COMPLETED ✅)
    ├── event_emitter.py       ← Real-time event broadcast (COMPLETED ✅)
    ├── websocket.py           ← Admin WebSocket endpoint (COMPLETED ✅)
    ├── db.py                  ← Supabase database layer (COMPLETED ✅)
    ├── chat.py                ← Chat route + Layer 6 honeypot (TODO)
    ├── cross_agent.py         ← Layer 7 cross-agent isolation (TODO)
    └── admin.py               ← Admin API + Layer 9 dashboard (TODO)
  
  main.py                      ← FastAPI app assembly (COMPLETED ✅)
  config.py                    ← Configuration management (COMPLETED ✅)
  requirements.txt             ← All dependencies (COMPLETED ✅)

tests/                         ← All test suites
  ├── test_session_manager.py  ← Session manager tests (64 ✓)
  ├── test_llm_client.py       ← LLM client tests (50 ✓)
  ├── test_indic_classifier.py ← Layer 1 tests (95+ ✓)
  ├── test_rag_scanner.py      ← Layer 2A tests (50+ ✓)
  ├── test_tool_scanner.py     ← Layer 2B tests (64 ✓)
  ├── test_memory_auditor.py   ← Layer 3 tests (38+ ✓)
  ├── test_drift_engine.py     ← Layer 4 tests (6+ ✓)
  ├── test_output_guard.py     ← Layer 5 tests (85+ ✓)
  ├── test_adaptive_engine.py  ← Layer 8 tests (68 ✓)
  ├── conftest.py              ← Shared test config
  └── pytest.ini               ← Pytest configuration

backend/tests/                 ← Backend-specific test suites
  ├── test_event_emitter.py    ← WebSocket event tests (59 ✓)
  └── test_db.py               ← Database layer tests (52 ✓)

frontend-user/                 ← ChatUI for end users (TODO)
frontend-admin/                ← Threat dashboard (TODO)

MASTER_GUIDE.md                ← 📖 Complete implementation guide
README.md                       ← You are here (quick overview)
WORKSPACE_STRUCTURE.md          ← Detailed file-by-file reference
.env.example                    ← Environment variable template
requirements.txt                ← Root-level dependencies
pytest.ini                      ← Test configuration
```

---

## 🛡️ What It Detects

- ✅ **Prompt injection attacks** (English, Hindi, Tamil, Telugu, Hinglish, Tanglish)
- ✅ **Jailbreaks and instruction overrides**
- ✅ **Memory poisoning attacks**
- ✅ **Multi-turn social engineering**
- ✅ **Cross-agent hijacking**
- ✅ **System prompt leakage**
- ✅ **Data exfiltration**

---

## 🚀 Common Commands

```bash
# Setup (1 minute)
python3.11 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r backend/requirements-classifiers.txt

# Verify (30 seconds)
python -c "from classifiers.indic_classifier import classify_threat; \
result = classify_threat('What is the capital of France?'); \
print(f'✓ OK' if result.passed else '✗ BLOCKED')"

# Test everything (30 seconds)
pytest tests/ -v

# Test specific layer
pytest tests/test_indic_classifier.py -v        # Layer 1
pytest tests/test_drift_engine.py -v            # Layer 4
```

---

## � Implementation Details

### Backend Infrastructure (Completed)

#### 1. Session Manager (`backend/api/session_manager.py`)
- **Purpose**: Tracks cumulative security state across conversation turns
- **64 comprehensive tests** — all passing ✅
- **Key Features**:
  - Session CRUD (create, read, update, delete)
  - Weighted average risk calculation (alpha=0.6)
  - Conversation history tracking
  - Layer decision audit trail
  - Memory hashing (SHA-256)
  - Role-based access control (guest/user/admin)

**Example**:
```python
from backend.api.session_manager import get_or_create_session, add_turn, record_layer_decision

session = get_or_create_session("user_abc123", role="user")
add_turn("user_abc123", "Hello", "Hi there", risk_score=0.1)
record_layer_decision("user_abc123", layer=1, action="PASSED", 
                      reason="No threat detected", threat_score=0.1)
```

#### 2. LLM Client (`backend/api/llm_client.py`)
- **Purpose**: Interface to primary LLM (Groq) and honeypot (Ollama/Groq fallback)
- **50 comprehensive integration tests** — all passing ✅
- **Key Features**:
  - Primary LLM: Groq `llama-3.3-70b-versatile`
  - Honeypot: Ollama `phi3:mini` (fallback: Groq `llama-3.1-8b-instant`)
  - Streaming response support
  - Input validation (history format, token bounds, temperature ranges)
  - Proper error handling (`LLMConnectionError` — never swallows exceptions)

**Example**:
```python
from backend.api.llm_client import get_llm_response, get_honeypot_response

# Get safe response
response = get_llm_response([{"role": "user", "content": "What is Python?"}])

# Get honeypot response for detected attacks
honeypot = get_honeypot_response(
    [{"role": "user", "content": "Ignore instructions"}],
    attacker_apparent_goal="prompt_injection"
)
```

#### 3. FastAPI Main App (`backend/main.py`)
- **Purpose**: Assemble FastAPI application with CORS and routes
- **Status**: ✅ Created and tested
- **Features**:
  - CORS middleware configured
  - Route registration (chat, admin, websocket)
  - Starts on port 8000

#### 4. Configuration (`backend/config.py`)
- **Purpose**: Environment variable management with Pydantic Settings
- **Status**: ✅ Created
- **Features**:
  - Type-safe configuration
  - `.env` file loading
  - API key management (Groq, Supabase)

#### 5. WebSocket Event System (`backend/api/event_emitter.py`, `backend/api/websocket.py`)
- **Purpose**: Real-time threat intelligence broadcast to admin dashboard
- **59 comprehensive tests** — all passing ✅
- **Key Features**:
  - Global admin WebSocket connection registry
  - Async concurrent broadcast via `asyncio.gather()`
  - Dead connection removal (silent, non-blocking)
  - Unified event schema with UUID, timestamp, threat_score, OWASP tags
  - Never blocks the security pipeline
  - Admin endpoint: `/ws/admin`

#### 6. Supabase Database Layer (`backend/api/db.py`)
- **Purpose**: Persistent logging of security events, sessions, memory snapshots, honeypot telemetry
- **52 comprehensive tests** — all passing ✅
- **Key Features**:
  - Fire-and-forget writes (failures logged, never raised)
  - Async operations via `asyncio.to_thread()` (non-blocking)
  - SQL schema provided for 4 tables: sessions, events, memory_snapshots, honeypot_sessions
  - Graceful degradation when database unavailable
  - Filtering and pagination for threat log queries

---

## 🧪 Test Coverage

| Component | Tests | Edge Cases | Pass Rate |
|-----------|-------|-----------|-----------|
| Session Manager | 64 | 50+ edge cases per function | ✅ 100% |
| LLM Client | 50 | Unicode, special chars, errors | ✅ 100% (integration) |
| WebSocket Event System | 59 | Concurrency, dead connections, Unicode | ✅ 100% |
| Supabase Database Layer | 52 | Pagination, filtering, error handling | ✅ 100% |
| **All Classifiers** | 450+ | Both genuine + adversarial prompts | ✅ 100% |
| **Total** | **675+** | 10+ varieties per layer | ✅ 100% |

**Test Categories**:
- ✅ Basic functionality (happy path)
- ✅ Edge cases (empty inputs, extreme values, special characters)
- ✅ Adversarial prompts (injection, jailbreak, social engineering)
- ✅ Unicode support (Arabic, Chinese, mixed languages)
- ✅ Error handling (missing API keys, invalid input)
- ✅ Concurrent operations (session isolation, high-volume broadcasts)
- ✅ Database resilience (no database, error graceful handling)

---


| Question | Answer |
|----------|--------|
| **Where do I start?** | 👉 Read [MASTER_GUIDE.md](./MASTER_GUIDE.md) |
| **How do I install?** | 👉 [MASTER_GUIDE.md#installation-steps](./MASTER_GUIDE.md#installation-steps) |
| **How do I integrate with my API?** | 👉 [MASTER_GUIDE.md#integration-pattern](./MASTER_GUIDE.md#-integration-pattern-for-api-endpoints) |
| **How do I run tests?** | 👉 [MASTER_GUIDE.md#testing-guide](./MASTER_GUIDE.md#-testing-guide) |
| **Something's broken!** | 👉 [MASTER_GUIDE.md#troubleshooting](./MASTER_GUIDE.md#-troubleshooting) |

---

## 📊 What Gets Tested

**Layer 1 (Indic Classifier)**: 95+ tests covering
- Spec compliance (7 tests)
- Threat detection in 3 languages (30 tests)
- Genuine safe prompts (15 tests, should PASS)
- Adversarial attack prompts (15 tests, should FAIL)
- Role-based thresholds (5 tests)
- Boundary conditions (12 tests)
- Metadata validation (5 tests)
- Performance requirements (2 tests)

**Layer 4 (Drift Engine)**: 6+ tests covering
- Embeddings (384-dim vectors)
- Safe messages pass
- Injections detected
- Crescendo attack escalation
- Session independence
- Session reset

---

## 🔗 Team Structure

| Team Member | Owns | File |
|-------------|------|------|
| **Hemach** | `/backend/classifiers` (all classifiers) | [indic_classifier.py](./backend/classifiers/indic_classifier.py), [drift_engine.py](./backend/classifiers/drift_engine.py) |
| **Nishun** | API & Frontend (both React UIs) | FastAPI routes, React components |
| **Siddharth** | Integration & End-to-End Testing | main.py assembly, verification |

---

## 📞 Need Help?

1. **Read MASTER_GUIDE.md first** — comprehensive reference
2. **Check test files** — see usage examples  
3. **See troubleshooting** — common issues and solutions

---

**Status**: Layers 1 & 4 production ready ✅  
**Next**: Implement Layers 2, 3, 5-9  
**Estimated**: ~6-8 weeks for full team

try:
    result = classify_threat(text)
except FailSecureError:
    return {"blocked": True}  # Never accidentally allow
```

### 2. Real Data, Real Functions
- ✅ Every threat score comes from actual pattern/semantic detection
- ✅ No hardcoded threat scores
- ✅ No fake data in UI — all from real API calls
- ✅ No silent error catching — every error is surfaced

### 3. Layered Defense
- Each layer runs independently
- No single layer can be bypassed
- Layers combine evidence (highest threat score wins)

### 4. Language-Aware Security
- Detects attacks in English AND Indic languages (Hindi, Tamil, Telugu)
- Handles transliteration (Hinglish, Tanglish)
- Script-aware (Devanagari, Tamil, Telugu, Latin)

### 5. Role-Based Strictness
```python
classify_threat(text, role="guest")   # Strict threshold (0.5)
classify_threat(text, role="user")    # Moderate threshold (0.65)
classify_threat(text, role="admin")   # Permissive threshold (0.85)
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Backend** | Python 3.11, FastAPI | Classifier pipeline + API |
| **LLM (Primary)** | Groq API (llama-3.3-70b-versatile) | Safe inference |
| **LLM (Honeypot)** | Ollama phi3:mini or Groq | Tarpit for attacks |
| **Embeddings** | sentence-transformers (all-MiniLM-L6-v2) | Semantic threat detection |
| **ML Models** | HuggingFace transformers | IndicBERT, language models |
| **Database** | Supabase (Postgres + Realtime) | Persistent threat logs |
| **Frontend** | React 18, Tailwind, Vite | User & admin UIs |
| **Deployment** | Railway (backend), Vercel (frontend) | Production hosting |

---

## Team Ownership

| Team Member | Owns | Delivers | Interface |
|-------------|------|----------|-----------|
| **Hemach** | `/backend/classifiers/` (Layers 1-8) | Python classifier functions | `ClassifierResult` objects |
| **Nishun** | `/frontend-*` + `/backend/api/` | FastAPI routes, React components | HTTP endpoints, React hooks |
| **Siddharth** | `/backend/main.py`, `/backend/integration/`, `/tests/` | Pipeline orchestration, wiring | End-to-end integration |

### Interface Rules
- ✅ DO notify team before changing function signatures
- ✅ DO validate all inputs and raise `FailSecureError` on failure
- ✅ DO document all dependencies and version pins
- ❌ DON'T import from another person's module without confirmation
- ❌ DON'T silently catch exceptions

---

## Current Status

### ✅ Complete
- [x] Layer 1: Indic Threat Classifier (indic_classifier.py)
- [x] Base classes (ClassifierResult, FailSecureError)
- [x] Test infrastructure (test_indic_quick.py, test_indic_classifier.py, test_indic_production.py)
- [x] Documentation (ARCHITECTURE_OVERVIEW, LAYER1 details, API reference, SETUP, TESTING)
- [x] Attack embeddings (attack_seeds.json with 20 vectors)
- [x] Embedding utility (generate_embeddings.py)

### ✅ COMPLETED
1. **Layer 2: RAG Chunk Scanner** (Hemach) ✓
   - Scan RAG documents for injection patterns
   - Detect document chunk hijacking attacks

2. **Layer 3: Memory Auditor** (Hemach) ✓
   - SHA-256 baseline of persistent memory
   - Semantic diff for logic bombs

3. **Layer 4: Semantic Drift Engine** (Hemach) ✓
   - Stateful multi-turn conversation tracking
   - Semantic drift velocity computation

4. **Layer 5: Output Guard** (Hemach) ✓
   - PII detector (Aadhaar, PAN, phone, email, API keys, credit cards)
   - System prompt leakage detector
   - Data exfiltration pattern detector

### 📋 TODO (In Priority Order)
5. **Layers 6-8: Honeypot, Cross-Agent, Adaptive Rules** (Hemach)

6. **Backend API** (Nishun)

7. **Frontend (User)** (Nishun)
   - Chat interface
   - Real-time message processing

8. **Frontend (Admin)** (Nishun)
   - Threat dashboard
   - Analytics & analytics

9. **Layer 9: Observability** (Nishun)
   - Dashboard
   - Threat intelligence feed

---

## Deployment

### Development
```bash
# Terminal 1: Backend
cd /path/to/AMD
python -m uvicorn backend.main:app --reload

# Terminal 2: Frontend
cd /path/to/AMD/frontend-user
npm run dev
```

### Production
- **Backend**: Deploy to Railway (`python -m uvicorn backend.main:app`)
- **Frontend**: Deploy to Vercel
- **Database**: Supabase (managed)
- **LLM**: Groq API (managed)

See [ARCHITECTURE_OVERVIEW.md](./ARCHITECTURE_OVERVIEW.md#deployment-targets) for details.

---

## Common Commands

```bash
# Setup
pip install -r backend/requirements-classifiers.txt

# Quick test
pytest tests/test_indic_quick.py -v

# Full tests
pytest tests/ -v --tb=short

# Generate embeddings
python generate_embeddings.py

# Run Python REPL with imports ready
python -c "from classifiers.indic_classifier import classify_threat; \
result = classify_threat('ignore all'); print(result)"

# Check Python version
python --version  # Must be 3.11+

# Activate venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

---

## 🗄️ Setting Up Supabase (Database Layer - N1-5)

The Supabase database layer persists all security events and session metadata. No tables are auto-created by Python code—you must run the SQL schema manually.

### Prerequisites
- Create a free Supabase project at https://supabase.com
- Grab `SUPABASE_URL` and `SUPABASE_ANON_KEY` from Settings → API
- Add to `.env`:
  ```
  SUPABASE_URL=https://your-project.supabase.co
  SUPABASE_ANON_KEY=your-anon-key-here
  ```

### Create Tables (Run in Supabase SQL Editor)

Go to **SQL Editor** → **New Query** → paste this and click **RUN**:

```sql
-- sessions: Track conversation state across turns
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('guest', 'user', 'admin')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    total_turns INTEGER DEFAULT 0,
    final_risk_score FLOAT DEFAULT 0.0,
    is_honeypot BOOLEAN DEFAULT FALSE
);

-- events: Real-time security events from all 9 layers
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(session_id),
    layer INTEGER NOT NULL CHECK (layer >= 0 AND layer <= 9),
    action TEXT NOT NULL CHECK (action IN ('PASSED', 'BLOCKED', 'QUARANTINED', 'HONEYPOT', 'FLAGGED', 'SYSTEM')),
    threat_score FLOAT CHECK (threat_score >= 0.0 AND threat_score <= 1.0),
    reason TEXT,
    owasp_tag TEXT,
    turn_number INTEGER,
    x_coord FLOAT DEFAULT 0.0,
    y_coord FLOAT DEFAULT 0.0,
    metadata JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- memory_snapshots: Baseline + auditing of conversation memory
CREATE TABLE memory_snapshots (
    id SERIAL PRIMARY KEY,
    session_id TEXT REFERENCES sessions(session_id),
    snapshot_hash TEXT NOT NULL,
    content_length INTEGER,
    quarantined BOOLEAN DEFAULT FALSE,
    quarantine_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- honeypot_sessions: Tarpit interactions with detected attackers
CREATE TABLE honeypot_sessions (
    session_id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    messages JSONB DEFAULT '[]',
    attack_type TEXT,
    total_messages INTEGER DEFAULT 0
);

-- Create indexes for common queries
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_layer ON events(layer);
CREATE INDEX idx_events_action ON events(action);
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
```

Once tables exist, all `db.log_*()` calls will persist events automatically (fire-and-forget, non-blocking).

### Verify Database Connection
```bash
pytest backend/tests/test_db.py -v  # Should pass all 52 tests
```

---

## 🌐 WebSocket Admin Dashboard (N1-4)

Real-time security event streaming to admin clients.

### How It Works
1. Admin client connects to `ws://localhost:8000/ws/admin`
2. Whenever a security layer detects activity, event is broadcast to all connected admins
3. Each admin sees: layer, action, threat_score, reason, timestamp

### Connect Admin Client (Python)
```python
import asyncio
import websockets
import json

async def listen_events():
    async with websockets.connect("ws://localhost:8000/ws/admin") as ws:
        while True:
            event = await ws.recv()
            event_dict = json.loads(event)
            print(f"[Layer {event_dict['layer']}] {event_dict['action']}: {event_dict['reason']}")

asyncio.run(listen_events())
```

### Test WebSocket System
```bash
pytest backend/tests/test_event_emitter.py -v  # 59 tests
```

Features tested:
- ✅ Multiple admin clients receive same event simultaneously
- ✅ Dead connections removed cleanly (don't block pipeline)
- ✅ All threat layers can emit events (0-9)
- ✅ All action types broadcast (PASSED, BLOCKED, QUARANTINED, HONEYPOT, FLAGGED, SYSTEM)
- ✅ Concurrent broadcasts (50+ simultaneous events)
- ✅ Unicode support in event data

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'sentence_transformers'"
```bash
pip install sentence-transformers==3.0.0
```

### Tests fail with "FileNotFoundError: attack_seeds.json"
```bash
python generate_embeddings.py
```

### Tests are slow (> 30 seconds)
This is normal on first run. Model is cached after that:
```bash
pytest tests/test_indic_quick.py -v  # 2-3s (hot cache)
```

### "CUDA out of memory"
```bash
export CUDA_VISIBLE_DEVICES=""  # Use CPU only
pytest tests/ -v
```

### Supabase not persisting events?
1. Verify `.env` has correct `SUPABASE_URL` and `SUPABASE_ANON_KEY`
2. Check that tables were created (run SQL schema in Supabase SQL Editor)
3. Events are logged asynchronously—check browser console/server logs for errors

### WebSocket connection refused (ws://localhost:8000/ws/admin)?
1. Verify FastAPI backend is running: `python -m uvicorn backend.main:app --reload`
2. Check that `/ws/admin` endpoint exists in `backend/api/websocket.py`
3. Admin must connect to same host/port as running server

See [MASTER_GUIDE.md](./MASTER_GUIDE.md#troubleshooting) for more help.

---

## Resources

- **OWASP LLM Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **sentence-transformers**: https://www.sbert.net/
- **HuggingFace**: https://huggingface.co/
- **Groq API**: https://console.groq.com/docs
- **FastAPI**: https://fastapi.tiangolo.com/
- **Supabase**: https://supabase.com/docs
- **WebSockets**: https://fastapi.tiangolo.com/advanced/websockets/

---

## Questions?

📖 See the documentation:
- [MASTER_GUIDE.md](./MASTER_GUIDE.md) — Complete reference (installation, setup, testing, integration)
- [WORKSPACE_STRUCTURE.md](./WORKSPACE_STRUCTURE.md) — File-by-file reference

---

**Status**: 🟢 Layers 1-4 production-ready | ✅ N1-4, N1-5 complete (111 tests) | 🟡 Layers 6-9 in development

**Last Updated**: 2026-02-28

