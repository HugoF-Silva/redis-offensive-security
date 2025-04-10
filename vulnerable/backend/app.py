from fastapi import FastAPI, HTTPException, Request
import redis
import json
import os
import uvicorn
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

app = FastAPI(title="Sávio Inseguranças")

redis_host = os.environ.get("REDIS_HOST", "localhost")
redis_port = int(os.environ.get("REDIS_PORT", 6379))
redis_password = os.environ.get("REDIS_PASSWORD", "123")

redis_client = redis.Redis(
    host=redis_host,
    port=redis_port,
    password=redis_password,
    decode_responses=True
)

class User(BaseModel):
    name: str
    email: str
    role: str

class ApiKey(BaseModel):
    key: str
    permissions: List[str]

class SessionData(BaseModel):
    user_id: str
    token: str
    ip: str
    device: str

@app.get("/")
async def root():
    return {"message", "Sávio Inseguranças"}

@app.get("/health")
async def health_check():
    # No proper error handling
    redis_client.ping()
    return {"status": "healthy"}

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # Vulnerable: No input validation or sanitization
    user_data = redis_client.hgetall(f"user_profile:{user_id}")
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    return user_data

@app.post("/users")
async def create_user(user: User):
    # Vulnerable: no pint validation
    user_id = redis_client.incr("next_user_id")
    redis_client.hset(f"user_profile:{user_id}", mapping={
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "last_login_ip": "not set",
        "last_login_time": "not set"
    })
    return {"user_id": user_id, **user.dict()}

@app.get("/api-keys/{user-id}")
async def get_api_key(user_id: str):
    # Vulnerable: Insecure direct access
    api_key = redis_client.hgetall(f"api_key:{user_id}")
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    return api_key

@app.post("/api-keys/{user_id}")
async def create_api_key(user_id: str, api_key: ApiKey):
    # Vulnerable: No validation
    redis_client.hset(f"api_key:{user_id}", mapping={
        "key": api_key.key,
        "permissions": ",".join(api_key.permissions)
    })
    return {"user_id": user_id, **api_key.dict()}

@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    # Vulnerable: Insecure direct access
    session = redis_client.hgetall(f"session:{session_id}")
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@app.post("/sessions")
async def create_session(session: SessionData):
    # Vulnerable: No validation or security checks
    session_id = "".join(session.user_id[:4]) + "123"
    redis_client.hset(f"session:{session_id}", mapping=session.dict())
    return {"session_id": session_id, **session.dict()}

@app.get("/dump")
async def dump_data():
    # Vulnerable: allows data dumping
    keys = redis_client.keys("*")
    data = {}
    for key in keys:
        key_type = redis_client.type(key)
        if key_type == "string":
            data[key] = redis_client.get(key)
        elif key_type == "hash":
            data[key] = redis_client.hgetall(key)
        elif key_type == "list":
            data[key] = redis_client.lrange(key, 0, -1)
        elif key_type == "set":
            data[key] = list(redis_client.smembers(key))
        elif key_type == "zset":
            data[key] = redis_client.zrange(key, 0, -1, withscores=True)
    return data

@app.post("/exec")
async def exec_command(request: Request):
    # Vulnerable: Allows arbitrary Redis commands
    data = await request.json()
    command = data.get("command", "")
    args = data.get("args", [])

    # Vulnerable: Allows any command execution
    result = redis_client.execute_command(command, *args)

    # Try to convert bytes to string if needed
    if isinstance(result, bytes):
        try:
            result = result.decode("utf-8")
        except:
            result = str(result)
    
    return {"result": result}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)