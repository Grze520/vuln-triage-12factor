# --- ETAP 1: BUILDER ---
FROM python:3.11-alpine AS builder

WORKDIR /build
COPY requirements.txt .

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/pip uninstall -y pip setuptools wheel && \
    rm -rf /opt/venv/lib/python3.11/ensurepip

# --- ETAP 2: HARDENED RUNTIME ---
FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8080

# Łatanie warstwy OS Alpine + usunięcie systemowego ensurepip/setuptools z obrazu bazowego
RUN apk update && apk upgrade --no-cache && \
    rm -rf /usr/local/lib/python3.11/ensurepip /usr/local/lib/python3.11/site-packages/setuptools* /usr/local/lib/python3.11/site-packages/wheel* && \
    find / -name "*setuptools*" -exec rm -rf {} + 2>/dev/null || true && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY app.py admin_seed.py ./
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --graceful-timeout 10 app:app"]
