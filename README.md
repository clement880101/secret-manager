# Secret Manager

A lightweight, distributed secret manager. Store a secret, share it with
another GitHub user, read it back from any machine.

- **One binary.** Under 10 MB, no Python, no runtime to install.
- **One container.** Configured entirely through environment variables.
- **Actually distributed.** No state in process memory, so it runs behind a load
  balancer across as many replicas as you like.
- **Your GitHub account is your identity.** No new passwords, no user table to
  administer.

```bash
secretmgr login
secretmgr create db-pw hunter2
secretmgr share db-pw 5842167
secretmgr list
```

[Website](https://clement880101.github.io/secret-manager/) ·
[Download](https://github.com/clement880101/secret-manager/releases/latest) ·
[Deployment](DEPLOYMENT.md) · [Security](SECURITY.md)

---

## Install the CLI

Download the build for your platform, make it executable, put it on your `PATH`:

```bash
curl -fsSL -o secretmgr \
  https://github.com/clement880101/secret-manager/releases/latest/download/secretmgr-macos-arm64
chmod +x secretmgr && sudo mv secretmgr /usr/local/bin/
```

Swap the filename for `secretmgr-macos-x86_64`, `secretmgr-linux-x86_64` or
`secretmgr-linux-arm64`. On macOS the binaries are unsigned, so clear the
quarantine flag once: `xattr -d com.apple.quarantine /usr/local/bin/secretmgr`.

Point it at your deployment and log in:

```bash
export BACKEND_URL=https://secrets.example.com
secretmgr login
```

### Commands

| Command | Does |
| --- | --- |
| `secretmgr login` | Authenticate with GitHub; stores a token in `~/.token` (mode `0600`). |
| `secretmgr logout` | Remove the stored token. |
| `secretmgr create KEY VALUE` | Store a secret you own. |
| `secretmgr list` | Everything visible to you: yours, plus what others shared. |
| `secretmgr share KEY GITHUB_ID` | Grant another GitHub user read access. |
| `secretmgr delete KEY` | Delete a secret you own. |
| `secretmgr ping` | Check the backend is reachable. |
| `secretmgr version` | Print the CLI version. |

`share` takes a numeric GitHub user ID, not a username. Find one with
`curl -s https://api.github.com/users/<login> | jq .id`.

## Run the server

The backend is a single stateless container listening on port 8000. It keeps
everything in a SQL database and does **not** terminate TLS — whatever you put
in front of it already does.

**The database ships with it.** SQLite is part of the Python standard library,
so this needs nothing else running:

```bash
docker run -d -p 8000:8000 -v secretmgr-data:/data \
  -e BACKEND_URL=https://secrets.example.com \
  -e OAUTH_ID_GITHUB=... \
  -e OAUTH_SECRET_GITHUB=... \
  -e SECRET_ENCRYPTION_KEY=... \
  ghcr.io/clement880101/secret-manager:latest
```

The volume matters: `/data` is where the database lives, and without it the
file goes into the container's writable layer and disappears with the
container. Published for `linux/amd64` and `linux/arm64`.

Point `DB_URL` at Postgres when you want more than one replica:

```bash
  -e DB_URL=postgresql+psycopg://user:pass@host:5432/secretmgr
```

Postgres is deliberately *not* bundled inside this image. A database in the
application container would give each replica its own copy, so scaling to two
would quietly produce two divergent datasets.

Or bring up the API and a Postgres together:

```bash
cd deploy && cp .env.example .env   # fill it in
docker compose up -d
```

**[DEPLOYMENT.md](DEPLOYMENT.md) has the detail**: every configuration
variable, choosing a database, reverse proxies, PaaS platforms, Kubernetes,
running multiple replicas, and upgrading.

### Configuration at a glance

| Variable | Required | Notes |
| --- | --- | --- |
| `BACKEND_URL` | yes | Public URL clients reach. GitHub redirects the OAuth callback here. |
| `OAUTH_ID_GITHUB` | yes | GitHub OAuth app client ID. |
| `OAUTH_SECRET_GITHUB` | yes | GitHub OAuth app client secret. |
| `SECRET_ENCRYPTION_KEY` | recommended | Fernet key. **Unset means values are stored in plaintext.** |
| `DB_URL` | no | Defaults to local SQLite. Use Postgres for anything real. |
| `ENABLE_API_DOCS` | no | Serve `/docs`. Default `false`. |
| `ENABLE_TEST_LOGIN` | no | Serve `POST /auth/login-test`. Default `false`. |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: none. |
| `TOKEN_CACHE_TTL_SECONDS` | no | Default `300`. `0` disables caching. |

Create the GitHub OAuth app at <https://github.com/settings/developers> with
callback URL `<BACKEND_URL>/auth/callback`.

## How it works

1. `secretmgr login` opens GitHub's authorization page and polls the backend.
2. The backend trades the code for a GitHub token and hands it to the CLI once.
3. Every later request carries that token; the backend verifies it against
   GitHub and caches the result briefly.
4. Secrets are encrypted before they reach the database, decrypted on read.

Login state — the OAuth `state`, the pending session, the issued token — lives
in the `login_sessions` table, not in process memory. A login can start on one
replica and finish on another, and a redeploy mid-login doesn't break it. The
`state` is claimed with a conditional `UPDATE`, so a replayed callback loses
even when it arrives concurrently.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI service, SQLAlchemy models, tests. |
| `cli/` | The CLI, packaged with PyInstaller. |
| `deploy/` | Docker Compose stack: API plus Postgres. |
| `integration-tests/` | Drives the built binary against a real backend. |
| `terraform/` | One AWS deployment. Optional — see `DEPLOYMENT.md`. |

## Development

Each component has a dev container; open the directory and reopen in container.
Or work locally:

```bash
cd backend && pip install -r requirements-dev.txt && pytest
cd cli     && pip install -r requirements-dev.txt && pytest
```

The backend's concurrency tests need a real database and skip without one:

```bash
docker run -d -p 5432:5432 -e POSTGRES_USER=sm -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=sm postgres:16-alpine
TEST_POSTGRES_URL=postgresql+psycopg://sm:secret@localhost:5432/sm pytest
```

SQLite serialises writers, so it would report success for code that is not
actually safe to run on more than one replica.

### CI/CD

| Workflow | Runs |
| --- | --- |
| `backend-ci.yml` | Tests against a real Postgres service, then builds and deploys on `main`. |
| `cli-ci.yml` | Tests, then builds Linux `x86_64`/`arm64` binaries. |
| `integration-tests.yml` | Starts a backend and Postgres, builds the CLI, drives it end to end. |
| `release.yml` | On a `v*` tag: builds every platform binary, publishes a GitHub Release with `SHA256SUMS`, and pushes a multi-arch image to GHCR. |

## Status

Early, and honest about it. Read the **Known limitations** in
[SECURITY.md](SECURITY.md) before trusting it with anything that matters —
notably that `GET /secrets` returns values in plaintext and there is no rate
limiting.

## License

[Apache License 2.0](LICENSE).
