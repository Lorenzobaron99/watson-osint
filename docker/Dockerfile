# Watson OSINT — Dockerfile
# Multi-stage build: builder → runtime
# Target: FastAPI on port 8777 with uvicorn

FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ curl dnsutils whois exiftool tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Runtime ──────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl dnsutils whois exiftool tesseract-ocr \
    tesseract-ocr-eng tesseract-ocr-ita tesseract-ocr-fra tesseract-ocr-spa tesseract-ocr-deu \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy app
COPY . .

# Create non-root user
RUN useradd --create-home watson && chown -R watson:watson /app
USER watson

# Data volume
RUN mkdir -p /data/cases

EXPOSE 8777

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8777/health || exit 1

CMD ["uvicorn", "watson.web.app:app", "--host", "0.0.0.0", "--port", "8777", "--workers", "4"]
