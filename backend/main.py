from dotenv import load_dotenv
load_dotenv()  # Load .env before any other imports that use env vars

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.chat import router as chat_router
from api.admin import router as admin_router
from api.websocket import router as ws_router
from api.policy import router as policy_router
from api.integrations import router as integrations_router
from api.users import router as users_router

app = FastAPI(title="Adaptive LLM Firewall", version="1.0.0")

import os
import json

# CORS origins from env (JSON array or comma-separated)
_raw_origins = os.getenv("ALLOWED_ORIGINS", '["*"]')
try:
    allowed_origins = json.loads(_raw_origins)
except (json.JSONDecodeError, TypeError):
    allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_router, prefix="/chat")
app.include_router(admin_router, prefix="/admin")
app.include_router(ws_router, prefix="/ws")
app.include_router(policy_router, prefix="/api/policy")
app.include_router(integrations_router, prefix="/api/integrations")
app.include_router(users_router, prefix="/api/users")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    uvicorn.run("main:app", host=host, port=port, reload=debug)
