import os
import json
import hashlib
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("secure-redis.encrypt.py")

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "k-change-me-in-prod")
ENCRYPTION_SALT = os.environ.get("ENCRYPTION_SALT", "s-change-me-in-prod").encode()

SENSITIVE_FIELDS = [
    "ip", "token", "api_key", "code", "transaction-id",
    "last_login_ip", "last_attempt_ip"
]

def setup_encryption(key):
    """Set up encryption with a key derivation function."""
    salt = ENCRYPTION_SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
    return Fernet(derived_key)

cipher_suite = setup_encryption(ENCRYPTION_KEY)

def encrypt_field(field_value):
    if not field_value:
        return field_value
    
    try:
        return f"<encrypted>{cipher_suite.encrypt(str(field_value).encode()).decode()}"
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return field_value
    
def hash_field(field_value):
    if not field_value:
        return field_value
    
    try:
        hashed = hashlib.sha256(str(field_value).encode()).hexdigest()
        return f"<hashed_{hashed}>"
    except Exception as e:
        logger.error(f"Hashing error: {e}")
        return field_value

def process_data(data):
    processed_data = {}
    for key, value in data.items():
        if key.startswith("rate_limit:ip:"):
            ip = key.split(":")[2]
            hashed_ip = hash_field(ip)
            new_key = f"rate_limit:ip:{hashed_ip}"
            processed_data[new_key] = value
        else:
            processed_data[key] = {}
            for field, field_value in value.items():
                if field in SENSITIVE_FIELDS:
                    if field.endswith("_ip") or field == "ip":
                        processed_data[key][field] = hash_field(field_value)
                    else:
                        processed_data[key][field] = encrypt_field(field_value)
                else:
                    processed_data[key][field] = field_value

    return processed_data

if __name__ == "__main__":
    test_data = {"test": {"token": "secret", "ip": "127.0.0.1"}}
    logger.info(f"Sample encryption result: {process_data(test_data)}")