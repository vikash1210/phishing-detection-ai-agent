
FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy project dependency and metadata files
COPY pyproject.toml uv.lock README.md ./

# Copy application source code
COPY src/ ./src/

# Copy RAG knowledge base
COPY data/knowledge_base/ ./data/knowledge_base/

# Install project dependencies
RUN uv sync --frozen --no-dev

# Make application package importable
ENV PYTHONPATH=/app/src

# Application port
EXPOSE 8000

# Start FastAPI
CMD ["uv", "run", "--no-sync", "uvicorn", "phishing_detection.api:app", "--host", "0.0.0.0", "--port", "8000"]
