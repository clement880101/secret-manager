FROM python:3.12-slim

ARG OAUTH_ID_GITHUB
ARG OAUTH_SECRET_GITHUB
ARG BACKEND_URL

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    OAUTH_ID_GITHUB=${OAUTH_ID_GITHUB} \
    OAUTH_SECRET_GITHUB=${OAUTH_SECRET_GITHUB} \
    BACKEND_URL=${BACKEND_URL}

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        sqlite3 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements-prod.txt /tmp/requirements-prod.txt
RUN pip install --no-cache-dir -r /tmp/requirements-prod.txt

COPY . /app

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]

# uvicorn app:app --host 0.0.0.0 --port 8000
# uvicorn app:app --host 0.0.0.0 --port 8000 --reload --log-level debug