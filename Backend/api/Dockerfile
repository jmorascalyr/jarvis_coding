# Multi-stage build for Jarvis Coding API
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY app/ ./app/
COPY start_api.py .

# Copy event generators and parsers from parent directory
COPY ../event_generators ./event_generators
COPY ../parsers ./parsers
COPY ../scenarios ./scenarios

# Make sure scripts are in PATH
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN useradd -m -u 1000 jarvis && \
    chown -R jarvis:jarvis /app

# Switch to non-root user
USER jarvis

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/api/v1/health')" || exit 1

# Run the application
CMD ["python", "start_api.py"]