# ---- frontend build -----------------------------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- runtime -------------------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SENTINEL_HOST=0.0.0.0 SENTINEL_PORT=8000 SENTINEL_AUTO_SEED=1 SENTINEL_AUTO_DEMO=1
WORKDIR /app
COPY pyproject.toml requirements.txt README.md ./
COPY backend/ backend/
COPY simulator/ simulator/
COPY detections/ detections/
COPY automation/ automation/
COPY cisco/ cisco/
COPY diagrams/ diagrams/
COPY data/ data/
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic PyYAML rich && pip install --no-cache-dir -e .
COPY --from=frontend /app/frontend/dist frontend/dist
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/meta').status==200 else 1)"
CMD ["python", "-m", "sentinelswitch", "serve", "--host", "0.0.0.0", "--port", "8000"]
