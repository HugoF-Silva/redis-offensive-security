FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY redis_proxy.py .

# Set execute permissions
RUN chmod +x /app/redis_proxy.py

# Expose port
EXPOSE 6381

# Run the proxy
CMD ["python", "redis_proxy.py"]