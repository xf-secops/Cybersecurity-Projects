# ©AngelaMos | 2026
# Dockerfile

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/
RUN uv pip install --system fastapi uvicorn

WORKDIR /app
COPY app.py .

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
