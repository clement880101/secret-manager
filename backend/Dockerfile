FROM python:3.12-slim

# Configuration is supplied at runtime, never baked in. A build arg copied into
# an ENV is written into the image layers, so anyone who can pull the image can
# read it -- which previously exposed the GitHub OAuth client secret. The ECS
# task definition already injects OAUTH_SECRET_GITHUB from Secrets Manager.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# No build toolchain: every dependency publishes a manylinux wheel, and
# psycopg[binary] bundles its own libpq. Installing build-essential, libffi-dev,
# libssl-dev and sqlite3 added roughly 400MB to an image that never compiled
# anything, which is a long pull on every platform this gets deployed to.

COPY requirements-prod.txt /tmp/requirements-prod.txt
RUN pip install --no-cache-dir -r /tmp/requirements-prod.txt

COPY . /app

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]

# uvicorn app:app --host 0.0.0.0 --port 8000
# uvicorn app:app --host 0.0.0.0 --port 8000 --reload --log-level debug