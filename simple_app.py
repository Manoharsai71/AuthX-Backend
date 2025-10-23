from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class UserLogin(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_2fa: bool = False

# Routes
@app.post("/api/auth/login", response_model=LoginResponse)
async def login(user_credentials: UserLogin):
    """Test login endpoint."""
    print(f"Login attempt for email: {user_credentials.email}")
    
    # Simulate successful login
    if user_credentials.email == "test@example.com" and user_credentials.password == "password123":
        return {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "token_type": "bearer",
            "requires_2fa": False
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

@app.get("/")
async def root():
    return {"message": "Test API is running!"}

if __name__ == "__main__":
    uvicorn.run("simple_app:app", host="127.0.0.1", port=8000, reload=True)