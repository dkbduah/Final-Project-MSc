FROM python:3.11-slim

WORKDIR /app

# Install build dependencies for phe (C extension)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directory for SQLite
RUN mkdir -p /data

ENV DATABASE_URL=sqlite+aiosqlite:////data/seas.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
