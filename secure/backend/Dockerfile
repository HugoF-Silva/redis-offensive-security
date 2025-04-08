FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Create non-root-user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy aaplication code
COPY app.py .

# Create necessary directories with proper permissions
RUN mkdir -p /var/log/app && \
    chown -R appuser:appuser /var/log/app /app

# Sitch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]