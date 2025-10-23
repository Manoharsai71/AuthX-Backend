from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager

from core.config import settings
from db.database import init_db
from auth.auth_routes import router as auth_router
from auth.oauth import router as oauth_router
from auth.magic_link import router as magic_link_router
from auth.two_fa import router as two_fa_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="AuthX API",
    description="Full-stack authentication system with JWT, OAuth2, and 2FA",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.FRONTEND_URL,
        settings.FRONTEND_URL_IP,
        "http://localhost:3000", 
        "http://127.0.0.1:3000",
        "http://192.168.0.11:3000",
        "http://0.0.0.0:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Include routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(oauth_router, prefix="/api/oauth", tags=["OAuth"])
app.include_router(magic_link_router, prefix="/api/magic", tags=["Magic Link"])
app.include_router(two_fa_router, prefix="/api/2fa", tags=["Two Factor Auth"])


@app.get("/")
async def root():
    return {"message": "AuthX API is running!"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "AuthX API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )