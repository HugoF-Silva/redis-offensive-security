import json
import os
import redis
import ssl
import time
import logging
from encrypt import process_data

log_directory = "/var/log/redis"
os.makedirs(log_directory, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{log_directory}/populate.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("secure-redis.populate.py")

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_USER = os.environ.get("ADMIN_USER")
REDIS_PASSWORD = os.environ.get("REDIS_ADMIN_PASSWORD")

SAMPLE_DATA_FILE = "/usr/local/bin/sample-data.json"

def connect_to_redis():
    try:
        logger.info(f"Connecting to secure Redis at {REDIS_HOST}:{REDIS_PORT}")

        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                username=REDIS_USER,
                password=REDIS_PASSWORD,
                ssl=True,
                ssl_cert_reqs="required",
                ssl_keyfile="/usr/local/etc/redis/tls/client.key",
                ssl_certfile="/usr/local/etc/redis/tls/client.crt",
                ssl_ca_certs="/usr/local/etc/redis/tls/ca.crt",
                socket_timeout=5
            )
            client.ping()
            logger.info("Connected to secure Redis with TLS")
            return client
        except Exception as e:
            logger.warning(f"TLS connection failed, trying non-TLS: {e}")

            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                username=REDIS_USER,
                password=REDIS_PASSWORD,
                socket_timeout=5
            )
            client.ping()
            logger.info("Connected to secure Redis without TLS")
            return client
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to secure Redis: {e}")
        return None
    
def load_sample_data():
    try:
        with open(SAMPLE_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading sample data: {e}")
        return {}
    
def load_data_to_redis(client, data):
    if not client:
        logger.error("Redis client is not available")
        return False
    try:
        processed_data = process_data(data)

        for key, value in processed_data.items():
            json_data = json.dumps(value)
            client.set(key, json_data)
            logger.info(f"Loaded key: {key} into secure Redis")
        return True
    
    except Exception as e:
        logger.error(f"Error loading data to Redis: {e}")
        return False

def main():
    logger.info("Starting secure Redis initialization")
    sample_data = load_sample_data()
    if not sample_data:
        logger.error("No sample data to load")
        return
    
    client = None
    max_retries = 5
    retry_delay = 2 # sec

    for attempt in range(max_retries):
        client = connect_to_redis()
        if client:
            break
        logger.warning(f"Retry attempt {attempt+1}/{max_retries} in {retry_delay} seconds...")
        time.sleep(retry_delay)
    
    if client:
        if load_data_to_redis(client, sample_data):
            logger.info("Secure Redis initialization completed successfully")
        else:
            logger.error("Failed to load data to secure Redis")
    else:
        logger.error("Failed to connect to secure Redis after retries")

if __name__ == "__main__":
    main()