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
| **5-9** | Remaining Layers | 📋 TODO | — |

**Critical Implementation**: All classifiers pass production-grade validation. Tool metadata scanner includes 10 critical bug fixes (fail-secure design, correct threshold handling, shell injection detection on all endpoints). See [MASTER_GUIDE.md#critical-bug-fixes--implementation-details](./MASTER_GUIDE.md#critical-bug-fixes--implementation-details) for details.

---

## 📁 What's in This Repository

```
backend/classifiers/           ← All security classifiers
  ├── base.py                  ← ClassifierResult & FailSecureError
  ├── indic_classifier.py      ← Layer 1: Prompt injection detection ✅
  ├── rag_scanner.py           ← Layer 2A: RAG document injection detection ✅
  ├── tool_scanner.py          ← Layer 2B: MCP tool metadata scanner ✅
  ├── memory_auditor.py        ← Layer 3: Memory integrity detection ✅
  ├── drift_engine.py          ← Layer 4: Multi-turn attack detection ✅
  ├── __init__.py              ← Proper exports
  └── data/
      ├── attack_seeds.json        ← 20+ attack embeddings
      ├── cluster_centroids.json   ← 6 threat clusters
      ├── malicious_domains.json   ← 15 known C2/phishing domains
      └── umap_model.pkl           ← 2D visualization model

tests/                          ← All test suites
  ├── test_indic_classifier.py ← 95+ tests ✓
  ├── test_rag_scanner.py      ← 50+ tests ✓
  ├── test_tool_scanner.py     ← 64 tests ✓ (all pass, failures validated)
  ├── test_memory_auditor.py   ← 38+ tests ✓
  └── test_drift_engine.py     ← 6+ tests ✓

backend/requirements-classifiers.txt  ← Dependencies (pinned versions)
generate_embeddings.py                ← Utility to regenerate embeddings
MASTER_GUIDE.md                       ← 📖 Complete reference (READ THIS)
README.md                             ← You are here (quick overview)
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

## 💡 Common Questions

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

### 📋 TODO (In Priority Order)
1. **Layer 2: MCP Tool Scanner** (Hemach)
   - Scan tool metadata for injection patterns
   - Detect RAG chunk injection attacks

2. **Layer 3: Memory Auditor** (Hemach)
   - SHA-256 baseline of persistent memory
   - Semantic diff for logic bombs

3. **Layer 4: Multi-Turn Risk Graph** (Hemach)
   - Stateful conversation tracking
   - Semantic drift velocity engine

4. **Layer 5: Output Guard** (Hemach)
   - PII detector
   - System prompt leakage detector
   - Exfiltration pattern detector

5. **Layers 6-8: Honeypot, Cross-Agent, Adaptive Rules** (Hemach)

6. **Backend API** (Nishun)
   - FastAPI endpoints
   - WebSocket handlers for real-time monitoring

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

See [SETUP_GUIDE.md](./SETUP_GUIDE.md#troubleshooting) for more troubleshooting.

---

## Resources

- **OWASP LLM Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **sentence-transformers**: https://www.sbert.net/
- **HuggingFace**: https://huggingface.co/
- **Groq API**: https://console.groq.com/docs
- **FastAPI**: https://fastapi.tiangolo.com/

---

## Questions?

📖 See the documentation:
- [ARCHITECTURE_OVERVIEW.md](./ARCHITECTURE_OVERVIEW.md) — System design
- [LAYER1_INDIC_CLASSIFIER.md](./LAYER1_INDIC_CLASSIFIER.md) — Layer 1 details & examples
- [API_REFERENCE.md](./API_REFERENCE.md) — Function signatures
- [SETUP_GUIDE.md](./SETUP_GUIDE.md) — Installation & configuration
- [TESTING.md](./TESTING.md) — How to test

---

**Status**: 🟢 Layer 1 production-ready | 🟡 Layers 2-9 in development

**Last Updated**: 2026-02-28
