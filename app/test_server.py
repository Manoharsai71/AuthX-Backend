#!/usr/bin/env python3
"""
Test script to verify the server can start and routes are working
"""
import uvicorn
from main import app

if __name__ == "__main__":
    print("🚀 Starting AuthX Backend Server...")
    print("📍 Server will be available at: http://localhost:8000")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔄 Auto-reload enabled for development")
    print("-" * 50)
    
    # Print available routes
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = getattr(route, 'methods', set())
            if methods:
                print(f"  {', '.join(methods)} {route.path}")
    
    print("-" * 50)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )