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

| Variable | Required | Notes |
| --- | --- | --- |
| `BACKEND_URL` | yes | The public URL clients reach, including scheme. GitHub redirects the OAuth callback here, so it must match your real address. |
| `OAUTH_ID_GITHUB` | yes | GitHub OAuth app client ID. |
| `OAUTH_SECRET_GITHUB` | yes | GitHub OAuth app client secret. |
| `SECRET_ENCRYPTION_KEY` | strongly recommended | Fernet key. **Without it, secret values are stored unencrypted.** |
| `DB_URL` | no | SQLAlchemy URL. Defaults to local SQLite. Use Postgres for anything real. |
| `ENABLE_API_DOCS` | no | Serve `/docs` and `/openapi.json`. Default `false`. |
| `ENABLE_TEST_LOGIN` | no | Serve `POST /auth/login-test`. Default `false`. |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: none. |
| `TOKEN_CACHE_TTL_SECONDS` | no | Default `300`. |

Generate an encryption key:

```bash
docker run --rm ghcr.io/clement880101/secret-manager:latest \
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Create the GitHub OAuth app at <https://github.com/settings/developers> and set
its callback URL to `<BACKEND_URL>/auth/callback`.

## Choosing a database

`DB_URL` accepts any SQLAlchemy URL. Both of these are exercised by the test
suite and by a real container on each release:

- `sqlite:///./secrets.db` — the default. Fine for a single box with a
  persistent disk. **Not** fine anywhere containers get replaced, because the
  file goes with them.
- `postgresql+psycopg://user:password@host:5432/dbname` — use this on any
  platform that moves containers around, or if you run more than one replica.
  The driver ships in the image.

Tables are created on startup; there is no migration step to run.

## Running it

### Docker

```bash
docker run -d --name secret-manager -p 8000:8000 \
  -e BACKEND_URL=https://secrets.example.com \
  -e OAUTH_ID_GITHUB=... \
  -e OAUTH_SECRET_GITHUB=... \
  -e SECRET_ENCRYPTION_KEY=... \
  -e DB_URL=postgresql+psycopg://user:pass@db:5432/secretmgr \
  ghcr.io/clement880101/secret-manager:latest
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

Set `BACKEND_URL=https://secrets.example.com` so the OAuth callback comes back
to the public address rather than the container's.

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

### Kubernetes

Nothing unusual is required: one Deployment, one Service, secrets from a
`Secret`, and an Ingress that terminates TLS. Use Postgres and the pods can
scale past one replica — login state lives in the database, not in process
memory, so a request can land on any pod.

`GET /healthz` returns `{"ok": true}` and is suitable for both liveness and
readiness probes.

### AWS with Terraform

[`terraform/`](terraform/) holds the original AWS deployment (ECS Fargate, ECR,
a network load balancer, and CloudFront for TLS). It is one option among the
above, not the supported path — the container runs anywhere, and most platforms
need far less setup.

## Running more than one replica

Supported, on Postgres. Everything a request needs is in the database rather
than in process memory, so requests can land on any instance:

- Login state (the OAuth `state`, the pending session, the issued token) lives
  in `login_sessions`, so a login can start on one replica and finish on
  another.
- An OAuth `state` is claimed with a conditional `UPDATE` and is redeemed
  exactly once, so a replayed callback loses even if it arrives concurrently.
- Creating a user and sharing a secret are both idempotent under concurrent
  writers.

Two caveats worth knowing:

- **Use Postgres.** SQLite serialises writers and does not survive a container
  being replaced, so it cannot back more than one instance.
- **Token verification is cached per process** (`TOKEN_CACHE_TTL_SECONDS`,
  default 300s). Each replica keeps its own cache, so a token revoked on GitHub
  can stay accepted for up to that long on each. Set it to `0` if you need
  revocation to take effect immediately.

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
