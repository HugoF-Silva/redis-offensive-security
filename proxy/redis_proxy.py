import socket
import ssl
import threading
import os
import re
import logging
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
log_directory = "/app/logs"
os.makedirs(log_directory, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{log_directory}/proxy.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("proxy.redis-proxy.py")

# Environment variables
REDIS_HOST = os.environ.get("REDIS_HOST", "secure-redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
PROXY_PORT = int(os.environ.get("PROXY_PORT", 6381))
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "k-change-me-in-prod")
ENCRYPTION_SALT = os.environ.get("ENCRYPTION_SALT", "s-change-me-in-prod").encode()
REDIS_TLS_ENABLED = os.environ.get("REDIS_TLS_ENABLED", "true").lower() == "true"
REDIS_TLS_CA_CERT = os.environ.get("REDIS_TLS_CA_CERT", "/app/tls/ca.crt")
REDIS_TLS_CLIENT_CERT = os.environ.get("REDIS_TLS_CLIENT_CERT", "/app/tls/client.crt")
REDIS_TLS_CLIENT_KEY = os.environ.get("REDIS_TLS_CLIENT_KEY", "/app/tls/client.key")

# Encryption setup
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

# Fields that need encryption or hashing
SENSITIVE_FIELDS = [
    "ip", "token", "api_key", "code", "transaction_id",
    "last_login_ip", "last_attempt_ip"
]

# Patterns for keys that need special handling
IP_RATE_LIMIT_PATTERN = re.compile(r'rate_limit:ip:([^:]+)')

# Commands to block entirely
BLOCKED_COMMANDS = [
    "CONFIG", "DEBUG", "MONITOR", "SHUTDOWN", "SLAVEOF", "REPLICAOF", "MIGRATE",
    "RESTORE", "BGREWRITEAOF", "BGSAVE", "SAVE", "SCRIPT", "MODULE", "ACL",
    "APPEND", "APPENDONLY"
]

class EncryptionHandler:
    """Handles field-level encryption for Redis data."""

    @staticmethod
    def encrypt_field(field_value):
        """Encrypt a field value."""
        if not field_value:
            return field_value

        try:
            return f"<encrypted>{cipher_suite.encrypt(str(field_value).encode()).decode()}"
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return field_value
    
    @staticmethod
    def decrypt_field(field_value):
        """Decrypt a field value."""
        if not field_value or not str(field_value).startswith("<encrypted>"):
            return field_value
        
        try:
            encrypted_part = str(field_value)[11:]
            return cipher_suite.decrypt(encrypted_part.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return field_value

    @staticmethod
    def hash_field(field_value):
        """Create a one-way hash for sensitive fields."""
        if not field_value:
            return field_value

        try:
            hashed = hashlib.sha256(str(field_value).encode()).hexdigest()
            return f"<hashed_{hashed}>"
        except Exception as e:
            logger.error(f"Hashing error: {e}")
            return field_value

class RedisCommand:
    """Parser for Redis protocol commands."""

    @staticmethod
    def parse(data):
        """Parse a Redis command from the raw data."""
        try:
            if data.startswith(b'*'):
                # RESP Array
                parts = data.split(b'\r\n')
                num_parts = int(parts[0][1:])
                command_parts = []
                
                i = 1
                for _ in range(num_parts):
                    if parts[i].startswith(b'$'):
                        length = int(parts[i][1:])
                        command_parts.append(parts[i+1][:length])
                        i += 2
                
                return command_parts
            else:
                # Simple inline command
                return data.strip().split()
        except Exception as e:
            logger.error(f"Command parsing error: {e}")
            return None
    
    @staticmethod
    def is_blocked_command(command_parts):
        """Check if the command is in the blocked list."""
        if not command_parts:
            return False

        cmd = command_parts[0].upper().decode('utf-8', errors='ignore')
        return cmd in BLOCKED_COMMANDS

class SecurityProxy:
    """Main proxy class for handling Redis connections."""

    def __init__(self, listen_port, redis_host, redis_port, use_tls=False,
                 ca_cert=None, client_cert=None, client_key=None):
        self.listen_port = listen_port
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.use_tls = use_tls
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Start the proxy server."""
        try:
            self.sock.bind(('0.0.0.0'), self.listen_port)
            self.sock.listen(5)
            logger.info(f"Proxy listening on port {self.listen_port}")

            while True:
                client_sock, client_address = self.sock.accept()
                logger.info(f"New connection from {client_address}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        
        except KeyboardInterrupt:
            logger.info("Shutting down proxy server...")
        except Exception as e:
            logger.error(f"Error in proxy server: {e}")
        finally:
            self.sock.close()

    def handle_client(self, client_sock, client_address):
        """Handle a client connection."""
        redis_sock = None

        try:
            # Connect to Redis
            if self.use_tls:
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.load_verify_locations(self.ca_cert)
                context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
                context.check_hostname = False

                redis_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                redis_sock = context.wrap_socket(redis_sock, server_hostname=self.redis_host)
            else:
                redis_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            redis_sock.connect((self.redis_host, self.redis_port))
            logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")

            # Set up bidirectional communication
            client_to_redis = threading.Thread(
                target=self.forward_data,
                args=(client_sock, redis_sock, True)
            )
            redis_to_client = threading.Thread(
                target=self.forward_data,
                args=(redis_sock, client_sock, False)
            )

            client_to_redis.daemon = True
            redis_to_client.daemon = True

            client_to_redis.start()
            redis_to_client.start()

            client_to_redis.join()
            redis_to_client.join()

        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if redis_sock:
                redis_sock.close()
            client_sock.close()
            logger.info(f"Connection with {client_address} closed")
    
    def forward_data(self, src_sock, dst_sock, is_request):
        """Forward data between sockets with security handling."""
        try:
            while True:
                data = src_sock.recv(4096)
                if not data:
                    break
                    
                # Process the data
                if is_request:
                    processed_data = self.process_request(data)
                    if processed_data:
                        dst_sock.sendall(processed_data)
                else:
                    dst_sock.sendall(data) # response as-is
        
        except Exception as e:
            logger.error(f"Error forwarding data: {e}")

    def process_request(self, data):
        """Process requests from the client to Redis."""
        command_parts = RedisCommand.parse(data)

        if not command_parts:
            return data

        if RedisCommand.is_blocked_command(command_parts):
            logger.warning(f"Blocked command: {command_parts[0]}")
            return b"-ERR blocked command\r\n"
        
        # Handle SET commands with potential sensitive data
        if len(command_parts) >= 3 and command_parts[0].upper() == b'SET':
            key = command_parts[1].decode('utf-8', errors='ignore')
            value = command_parts[2].decode('utf-8', errors='ignore')

            # Check if key matches rate limit pattern (for IP hashing)
            ip_match = IP_RATE_LIMIT_PATTERN.match(key)
            if ip_match:
                # Hash the IP in the key
                ip = ip_match.group(1)
                hashed_ip = EncryptionHandler.hash_field(ip)
                new_key = f"rate_limit:ip:{hashed_ip}"
                command_parts[1] = new_key.encode()

            # Try to parse as JSON for field-level encryption
            try:
                json_data = json.loads(value)
                modified = False

                if isinstance(json_data, dict):
                    for field  in json_data:
                        if field in SENSITIVE_FIELDS:
                            modified = True
                            # Hash IPs, encrypt other sensitive fields
                            if field.endswith('_ip') or field == 'ip':
                                json_data[field] = EncryptionHandler.hash_field(json_data[field])
                            else:
                                json_data[field] = EncryptionHandler.encrypt_field(json_data[field])

                    if modified:
                        # Replace the value with the encrypted version
                        new_value = json.dumps(json_data)
                        command_parts[2] = new_value.encode()
                        
                        # Rebuild the command
                        result = [f"*{len(command_parts)}".encode()]
                        for part in command_parts:
                            if isinstance(part, str):
                                part = part.encode()
                            result.append(f"${len(part)}".encode())
                            result.append(part)

                        logger.info(f"Encrypted sensistive fields in SET command for key: {key}")
                        return b"\r\n".join(result) + b"\r\n"
            except json.JSONDecodeError:
                # Not JSON, proceed normally
                pass
                
        return data
    
def main():
    proxy = SecurityProxy(
        listen_port=PROXY_PORT,
        redis_host=REDIS_HOST,
        redis_port=REDIS_PORT,
        use_tls=REDIS_TLS_ENABLED,
        ca_cert=REDIS_TLS_CA_CERT,
        client_cert=REDIS_TLS_CLIENT_CERT,
        client_key=REDIS_TLS_CLIENT_KEY
    )
    logger.info("Starting Redis Security Proxy...")
    proxy.start()

if __name__ == "__main__":
    main()