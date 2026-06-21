#!/usr/bin/env python3
"""
Hugging Face Spaces deployment wrapper for Luffy Panel
"""
import sys
import os

# Import main FastAPI application
from main import app, CONFIG

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment or use default
    port = int(os.environ.get("PORT", 7860))  # HF Spaces default port
    
    # Run the application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
