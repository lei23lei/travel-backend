from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from app.auth import auth
from app.chat import chat
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
app = FastAPI(
    title="Travel Backend API",
    description="Backend API for the travel application",
    version="0.1.0"
)

app.include_router(auth.router, prefix="/auth")
app.include_router(chat.router, prefix="/chat")
# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Development environment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Welcome to Travel Backend API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
