"""
Launcher for Butler ML Security Service
"""

import uvicorn
from app.config import settings

def main():
    print(f"🚀 Starting {settings.SERVICE_NAME} on http://{settings.HOST}:{settings.PORT}")
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=False)

if __name__ == "__main__":
    main()
