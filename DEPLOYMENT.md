# Deploying

The backend is a single stateless container that speaks plain HTTP on port
8000 and keeps its state in a SQL database. That is all it assumes, so it runs
on anything that can run a container — your laptop, a VPS, a PaaS, Kubernetes,
or a cloud container service.

It deliberately does **not** terminate TLS. Almost every platform already does
that for you, and owning certificates inside the app would tie it to one way of
being deployed. Put it behind whatever your platform provides.

## Configuration

Everything is environment variables. Nothing is baked into the image.

Nothing here is required to start. The service brings its own database and
issues its own tokens, so `docker run` with no environment at all works.

| Variable | Required | Notes |
| --- | --- | --- |
| `ALLOW_REGISTRATION` | no | Whether anyone reaching the service may sign up. Default `true`. |
| `BOOTSTRAP_TOKEN` | no | Local mode: the first token, instead of one generated at startup. |
| `BACKEND_URL` | no | The public address clients reach. |
| `SECRET_ENCRYPTION_KEY` | strongly recommended | Fernet key. **Without it, secret values are stored unencrypted.** |
| `DB_URL` | no | SQLAlchemy URL. Defaults to local SQLite. Use Postgres for anything real. |
| `ENABLE_API_DOCS` | no | Serve `/docs` and `/openapi.json`. Default `false`. |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: none. |
| `TOKEN_CACHE_TTL_SECONDS` | no | Default `300`. |

Generate an encryption key:

```bash
docker run --rm ghcr.io/clement880101/secret-manager:latest \
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Accounts

The service manages its own. People sign themselves up:

```bash
secretmgr register alice          # prompts for a password
secretmgr login alice             # from any other machine
```

Passwords are hashed with scrypt from the standard library — no extra
dependency — and are never stored in any recoverable form. Failed logins are
rate limited per username and per address. Set `ALLOW_REGISTRATION=false` to
close sign-ups on a deployment reachable from the open internet; an
administrator can then provision access with `secretmgr token <name>`.

There is also always a way in without a password. On first start the service
creates a token and writes it to the log:

```
No API tokens existed, so one was created for user 'admin'.
This is shown once and cannot be recovered:

    smt_sGQr0f3dFBP39sUNBm2jpwZ6tnZyFms-dLPcIUp6SwE
```

Set `BOOTSTRAP_TOKEN` to choose it yourself, which is easier on immutable
platforms or where logs are awkward to read. Only the SHA-256 of a token is
stored, and tokens do not expire — revoke deliberately with `secretmgr revoke`.


## Choosing a database

`DB_URL` accepts any SQLAlchemy URL. Both of these are exercised by the test
suite and by a real container on each release:

- **SQLite — bundled, and the default.** The image needs no external database
  to start. It writes to `/data/secrets.db`, which is declared as a volume:
  mount one (`-v secretmgr-data:/data`) or the file lands in the container's
  writable layer and is lost when the container is replaced. Fine for a single
  instance; it cannot back more than one.
- `postgresql+psycopg://user:password@host:5432/dbname` — use this on any
  platform that moves containers around, or if you run more than one replica.
  The driver ships in the image.

Tables are created on startup; there is no migration step to run.

## Running it

### Docker

```bash
docker run -d --name secret-manager -p 8000:8000 \
  -v secretmgr-data:/data \
  ghcr.io/clement880101/secret-manager:latest
```

That is enough to have a working deployment. For anything real, add:

```bash
  -e SECRET_ENCRYPTION_KEY=...   # encrypt values at rest
  -e BACKEND_URL=https://secrets.example.com
  -e DB_URL=postgresql+psycopg://user:pass@db:5432/secretmgr
```

The image is published for `linux/amd64` and `linux/arm64`.

### Docker Compose

[`deploy/docker-compose.yml`](deploy/docker-compose.yml) brings up the API and a
Postgres with a persistent volume:

```bash
cd deploy
cp .env.example .env    # fill it in
docker compose up -d
```

Note this is *not* the repository root's `docker-compose.yml`, which exists to
back the Dev Containers and runs `sleep infinity` rather than the app.

### Behind a reverse proxy

Terminate TLS at the proxy and forward to port 8000. With Caddy, that is the
whole config:

```
secrets.example.com {
    reverse_proxy localhost:8000
}
```

Set `BACKEND_URL=https://secrets.example.com` so the service knows the address
clients actually reach.

### Platforms that build from a Dockerfile

Fly.io, Render, Railway, Google Cloud Run, Azure Container Apps and similar all
work without special handling: point them at `backend/Dockerfile`, set the
environment variables above, and attach a Postgres. They terminate TLS for you,
so `BACKEND_URL` is the `https://` address they assign.

The container listens on 8000. Where a platform injects its own `PORT`, either
map it to 8000 or override the command:

```
uvicorn app:app --host 0.0.0.0 --port $PORT
```

### A distributed deployment, in one command

[`deploy/docker-compose.cluster.yml`](deploy/docker-compose.cluster.yml) runs
the API behind a load balancer, sharing one Postgres:

```bash
cd deploy
cp .env.example .env    # set BOOTSTRAP_TOKEN as well
docker compose -f docker-compose.cluster.yml up -d --scale api=3
```

Scale to any number. Replicas hold no state, so a request is served by whichever
one the balancer picks, and a login started on one is finished by another. The
balancer re-resolves the replicas every few seconds, so scaling up or losing one
needs no restart.

### Kubernetes

[`deploy/k8s/`](deploy/k8s/) has manifests for a three-replica Deployment, a
Postgres, a Service and an example Ingress, with a README. Scale with
`kubectl scale deployment/secretmgr --replicas=10`; nothing else changes, and no
session affinity is needed anywhere.

`GET /healthz` returns `{"ok": true, "version": ...}`, does no database work, and
suits both liveness and readiness probes.

### Platforms that inject a port

`PORT` is honoured when set, so Cloud Run, Heroku-style platforms and anything
else that chooses the port for you works without a custom command. `HOST`,
`LOG_LEVEL` and `FORWARDED_ALLOW_IPS` are configurable the same way, and the
server reads `X-Forwarded-*` so it sees the client's address rather than the
proxy's.

### AWS with Terraform

[`terraform/`](terraform/) holds the original AWS deployment (ECS Fargate, ECR,
a network load balancer, and CloudFront for TLS). It is one option among the
above, not the supported path — the container runs anywhere, and most platforms
need far less setup.

## Running more than one replica

Supported, on Postgres. Everything a request needs is in the database rather
than in process memory, so requests can land on any instance:

- Accounts, tokens and rate-limit counters all live in the database, so any
  replica can serve any request and no session affinity is needed.
- Creating a user and sharing a secret are both idempotent under concurrent
  writers.
- Failed-login counting is shared across replicas, so the limit is the limit
  rather than the limit multiplied by however many instances are running.

Two caveats worth knowing:

- **Use Postgres.** SQLite serialises writers and does not survive a container
  being replaced, so it cannot back more than one instance.

The concurrency behaviour is covered by tests that run against a real Postgres.
They skip unless `TEST_POSTGRES_URL` is set, because SQLite would report success
for code that is not actually safe.

## Upgrading

Pull the new image and restart. Tables are created on startup and existing rows
are left alone; values written before `SECRET_ENCRYPTION_KEY` was configured
stay readable, because ciphertext is tagged and untagged rows are treated as
plaintext.

Keep the encryption key. **Losing or changing it makes every encrypted value
unreadable, with no recovery path.**

## Pointing the CLI at your deployment

```bash
export BACKEND_URL=https://secrets.example.com
secretmgr login
```

The CLI warns if `BACKEND_URL` is plain HTTP to anything other than localhost,
because the access token and secret values would cross the network in the clear.
