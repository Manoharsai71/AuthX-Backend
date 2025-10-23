#!/usr/bin/env python3
"""
Quick test to verify server functionality
"""
import asyncio
import httpx
from main import app
import uvicorn
import threading
import time

async def test_endpoints():
    """Test if endpoints are responding"""
    await asyncio.sleep(2)  # Wait for server to start
    
    async with httpx.AsyncClient() as client:
        try:
            # Test root endpoint
            response = await client.get("http://localhost:8000/")
            print(f"Root endpoint: {response.status_code} - {response.json()}")
            
            # Test health endpoint
            response = await client.get("http://localhost:8000/api/health")
            print(f"Health endpoint: {response.status_code} - {response.json()}")
            
            # Test register endpoint with OPTIONS (CORS preflight)
            response = await client.options("http://localhost:8000/api/auth/register")
            print(f"Register OPTIONS: {response.status_code}")
            
        except Exception as e:
            print(f"Error testing endpoints: {e}")

def run_server():
    """Run the server in a separate thread"""
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        log_level="error"  # Reduce log noise
    )

if __name__ == "__main__":
    print("🧪 Quick test of AuthX server...")
    
    # Start server in background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Test endpoints
    asyncio.run(test_endpoints())
    
    print("✅ Test completed!")