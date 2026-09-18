FROM python:3.12-slim

# Configuration is supplied at runtime, never baked in. A build arg copied into
# an ENV is written into the image layers, so anyone who can pull the image can
# read it -- which previously exposed the GitHub OAuth client secret. The ECS
# task definition already injects OAUTH_SECRET_GITHUB from Secrets Manager.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_URL=sqlite:////data/secrets.db

# The database ships with the image: SQLite is part of the Python standard
# library, so `docker run` needs nothing else to work. It lives under /data
# rather than in /app so it can be kept on a volume -- otherwise it is written
# into the container's writable layer and thrown away with the container.
#
# Postgres is NOT bundled into this image on purpose. A database inside the
# application container would give every replica its own copy, so scaling to
# two would silently produce two divergent datasets. Point DB_URL at a shared
# Postgres when you want more than one instance; see deploy/docker-compose.yml.
RUN mkdir -p /data
VOLUME ["/data"]

WORKDIR /app

# No build toolchain: every dependency publishes a manylinux wheel, and
# psycopg[binary] bundles its own libpq. Installing build-essential, libffi-dev,
# libssl-dev and sqlite3 added roughly 400MB to an image that never compiled
# anything, which is a long pull on every platform this gets deployed to.

COPY requirements-prod.txt /tmp/requirements-prod.txt
RUN pip install --no-cache-dir -r /tmp/requirements-prod.txt

COPY . /app

EXPOSE 8000

# --proxy-headers matters once this sits behind a load balancer or ingress,
# which is the normal way to run it: without it the app sees the proxy's
# address rather than the client's.
CMD ["./entrypoint.sh"]

# uvicorn app:app --host 0.0.0.0 --port 8000
# uvicorn app:app --host 0.0.0.0 --port 8000 --reload --log-level debug