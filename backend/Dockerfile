FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build deps are not needed: every dependency ships wheels (psycopg[binary], nh3).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

# Run as a non-root user (least privilege).
RUN useradd --create-home --uid 10001 asber && chown -R asber:asber /app
USER asber

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
