"""
Development runner for SecureFileGuard backend.
Run from the backend/ directory:
    python run.py
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_excludes=["*.db", "*.log"],
        log_level="info",
    )
