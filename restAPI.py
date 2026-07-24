import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from src.core.__init__ import VaultBaseException

load_dotenv()

app = FastAPI(
    title="Mini Vault API",
    description="Secure Storage (KV Engine) & Encryption / Signing as a Service (Transit Engine)",
    version="1.0.0"
)

# Exception Handler using the custom VaultBaseException class
@app.exception_handler(VaultBaseException)
async def vault_exception_handler(request: Request, exc: VaultBaseException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "message": exc.message
        }
    )

@app.get("/health", tags=["Health Check"])
async def health_check():
    """Endpoint to check the health status of the service"""
    return {
        "status": "healthy",
        "service": "Mini Vault Engine"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)