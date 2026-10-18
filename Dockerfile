# One image: builds the React UI, then serves it and the API from a single FastAPI process.
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
RUN pip install --no-cache-dir uv==0.5.11
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ backend/
COPY demo/ demo/
COPY docs/ docs/
COPY --from=ui /ui/dist frontend/dist
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app PORT=8010
EXPOSE 8010
# FALKORDB_HOST / FALKORDB_PORT / FALKORDB_PASSWORD come from the environment.
CMD ["sh", "-c", "uvicorn backend.api.main:app --host 0.0.0.0 --port ${PORT}"]
