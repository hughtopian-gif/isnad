# Isnad - Trust Infrastructure for Agents
# Multi-stage build for production deployment

FROM python:3.11-slim as builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY scanner/ scanner/
COPY api/ api/
COPY web/ web/

# Create non-root user
RUN useradd -m isnad && chown -R isnad:isnad /app
USER isnad

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
