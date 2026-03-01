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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Will be restricted in production
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
