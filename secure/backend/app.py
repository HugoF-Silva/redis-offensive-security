import os
import time
import json
import redis
import hashlib
import logging
import uvicorn
import secrets

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, EmailStr, validator, Field
from fastapi import FastAPI, HTTPException, Request, Depends, Security, status
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import contextmanager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Iinitialize with security metadata
app = FastAPI(
    title="Savio Seguranças",
    description="A secured API for Redis data access",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://secureapp.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"]
)

# Redis connection settings from environment variables
redis_host = os.environ.get("REDIS_HOST", "localhost")
redis_port = int(os.environ.get("REDIS_PORT"))
redis_password = os.environ.get("REDIS_PASSWORD")
redis_tls_enabled = os.environ.get("REDIS_TLS_ENABLED", "true").lower() == "true"
redis_tls_cert_path = os.environ.get("REDIS_TLS_CERT_PATH")
redis_tls_key_path = os.environ.get("REDIS_TLS_KEY_PATH")
redis_tls_ca_cert_path = os.environ.get("REDIS_TLS_CA_CERT_PATH")

# Encryption settings
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

def encrypt_field(value: str) -> str:
    """SHA-256 field encryption"""
    if not value:
        return ""
    return f"encrypted_{hashlib.sha256((value + ENCRYPTION_KEY).encode()).hexdigest()}"

def decrypt_field(value: str) -> str:
    """ÏMPLEMENT, lacking"""
    if not value or not value.startswith("encrypted_"):
        return value
    return "[ENCRYPTED]"

@contextmanager
def get_redis_connection():
    """Get a Redis connection with proper error handling and TLS support"""
    connection_params = {
        "host": redis_host,
        "port": redis_port,
        "password": redis_password,
        "decode_responses": True,
        "socket_timeout": 5.0,
        "retry_on_timeout": True
    }

    if redis_tls_enabled:
        connection_params.update({
            "ssl": True,
            "ssl_certfile": redis_tls_cert_path,
            "ssl_keyfile": redis_tls_key_path,
            "ssl_ca_certs": redis_tls_ca_cert_path,
            "ssl_cert_reqs": "required"
        })

    try:
        client = redis.Redis(**connection_params)
        yield client

    except redis.RedisError as e:
        logger.error(f"Redis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection error: {str(e)}"
        )
    
    finally:
        if 'client' in locals():
            client.close()

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting middleware"""
    client_ip = request.client.host
    rate_key = f"rate:limit:{encrypt_field(client_ip)}"

    with get_redis_connection() as redis_client:
        # Get current count
        current = redis_client.get(rate_key)
        current = int(current) if current else 0

        if current > 100:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please try again later."}
            )
        
        # Increment count and set expiry
        redis_client.incr(rate_key)
        redis_client.expire(rate_key, 60) # 1 minute window
    
    # Process the request
    response = await call_next(request)
    return response

# Models with validation
class User(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    role: str = Field(..., regex="^(user|admin|readonly)$")

    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['user', 'admin', 'readonly']
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v
    
class ApiKey(BaseModel):
    permissions: List[str] = Field(..., min_items=1)

    @validator('permissions')
    def validate_permissions(cls, v):
        allowed_permissions = ['read', 'write', 'delete']
        for perm in v:
            if perm not in allowed_permissions:
                raise ValueError(f"Pemission must be one of: {', '.join(allowed_permissions)}")
        return v
    
class SessionData(BaseModel):
    user_id: str = Field(..., regex="^[0-9]+$")
    token: str
    ip: str
    device: str
    
    @validator('ip')
    def validate_ip(cls, v):
        parts = v.split('.')
        if len(parts) != 4:
            raise ValueError("Invalid IP format")
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    raise ValueError("IP parts must be between 0 and 255")
            except ValueError:
                raise ValueError("IP parts must be numbers")
        return v

# Security - API key validation
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
api_key_test = os.environ.get("SECURE_API_KEY")

async def get_api_key(api_key:str = Security(api_key_header)):
    """Validate API key from header"""
    # For demo, use a simple hardcoded key
    # In production, this would validate against secure storage
    if api_key != "secure_api_key_for_testing":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return api_key

# Routes
@app.get("/")
async def root():
    return {"message": "Savio Seguranças"}

@app.get("/health")
async def health_check():
    """Health check with proper error handling"""
    try:
        with get_redis_connection() as redis_client:
            if redis_client.ping():
                return {"status": "healthy"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable"
        )

@app.get("/users/{user_id}", dependencies=[Depends(get_api_key)])
async def get_user(user_id: str):
    """Get user with proper input validation and error handling"""

    # Validate user ID format
    if not user_id.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a number"
        )

    try:
        with get_redis_connection() as redis_client:
            user_data = redis_client.hgetall(f"user_profile:{user_id}")

            if not user_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Decrypt sensitive fields
            if "last_login_ip" in user_data:
                user_data["last_login_ip"] = decrypt_field(user_data["last_login_ip"])
            
            # Log access for auditing
            logger.info(f"User data accessed for ID: {user_id}")

            return user_data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
    
@app.post("/users", dependencies=[Depends(get_api_key)])
async def create_user(user: User):
    try:
        with get_redis_connection() as redis_client:
            # Generate user od
            user_id = redis_client.incr("next_user_id")

            # Store user with encrypted fields
            redis_client.hset(f"user_profile:{user_id}", mapping={
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "last_login_ip": encrypt_field("0.0.0.0"), # Encrypted default value
                "last_login_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })

            # Log for auditing
            logger.info(f"Created new user with ID: {user_id}, role: {user.role}")

            # Return safe response (no internal data)
            return {
                "user_id": user_id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )

@app.get("/api-keys/{user_id}", dependencies=[Depends(get_api_key)])
async def get_api_key_for_user(user_id: str):
    """Get API key with security measures"""
    if not user_id.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a number"
        )
    
    try:
        with get_redis_connection() as redis_client:
            # Check if user exists first
            user_exists = redis_client.exists(f"user_profile:{user_id}")
            if not user_exists:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Get API key data
            api_key_data = redis_client.hgetall(f"api_key:{user_id}")
            if not api_key_data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="API key not found"
                )
            
            if "key" in api_key_data:
                api_key_data["key"] = decrypt_field(api_key_data["key"])

            if "permissions" in api_key_data:
                api_key_data["permissions"] = api_key_data["permissions"].split(",")

            logger.info(f"API key accessed for user ID: {user_id}")
            return api_key_data
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving API key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
    
@app.post("/api-keys/{user_id}", dependencies=[Depends(get_api_key)])
async def create_api_key_for_user(user_id: str, api_key: ApiKey):
    """Create API key with validation and secure storage"""
    if not user_id.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID must be a number"
        )

    try:
        with get_redis_connection() as redis_client:
            # Check if user exists
            user_exists = redis_client.exists(f"user_profile:{user_id}")
            if not user_exists:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Generate secure API key
            key = secrets.token_hex(16)

            # Store with encryption
            redis_client.hset(f"api_key:{user_id}", mapping={
                "key": encrypt_field(key),
                "permissions": ",".join(api_key.permissions)
            })

            logger.info(f"Generated new API key for user ID: {user_id}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating API key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )
    
@app.get("/sessions/{session_id}", dependencies=[Depends(get_api_key)])
async def get_session(session_id: str):
    """Get session with security measures"""
    # Basic validation
    if not session_id or len(session_id) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format"
        )
    
    try:
        with get_redis_connection() as redis_client:
            session = redis_client.hgetall(f"session:{session_id}")
            if not session:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Session not found"
                )
            
            if "ip" in session:
                session["ip"] = decrypt_field(session["ip"])
            
            logger.info(f"Session data accessed: {session_id}")
            return session
    except HTTPException:
        raise
    except Exception as e:
        logger.erro(f"Error retrieving session: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/sessions", dependencies=[Depends(get_api_key)])
async def create_session(session: SessionData):
    """Create session with validation and secure storage"""
    try:
        with get_redis_connection() as redis_client:
            # Check if user exists
            user_exists = redis_client.exists(f"user_profile:{session.user_id}")
            if not user_exists:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Generate session ID with randomness for security
            session_id = f"{session.user_id[:4]}{secrets.token_hex(4)}"

            # Store session with encrypted fields
            redis_client.hset(f"session:{session_id}", mapping={
                "user_id": session.user_id,
                "token": session.token,
                "ip": encrypt_field(session.ip),
                "device": session.device
            })

            # Update last login
            redis_client.hset(f"user_profile:{session.user_id}", mapping={
                "last_login_ip": encrypt_field(session.ip),
                "last_login_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })

            logger.info(f"New session created for user: {session.user_id}")

            return {
                "session_id": session_id,
                "user_id": session.user_id,
                "device": session.device
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session"
        )
    
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)