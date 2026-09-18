# Secret Manager

A lightweight, distributed secret manager. Store a secret, share it with a
teammate, read it back from any machine.

- **One binary.** Under 10 MB, no Python, no runtime to install.
- **One container.** Configured entirely through environment variables.
- **Actually distributed.** No state in process memory, so it runs behind a load
  balancer across as many replicas as you like.
- **Nothing external required.** Its own accounts, its own tokens, its own
  database. `docker run` is the whole setup, and GitHub login is opt-in.

```bash
docker run -d -p 8000:8000 -v secretmgr-data:/data \
  ghcr.io/clement880101/secret-manager:latest

secretmgr register alice     # your teammates do the same
secretmgr create db-pw hunter2
secretmgr share db-pw bob
```

No OAuth app to register, no accounts on anyone else's platform, no outbound
network access. Users sign themselves up.

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

Swap the filename for `secretmgr-macos-x86_64`, `secretmgr-linux-x86_64`,
`secretmgr-linux-arm64` or `secretmgr-windows-x86_64.exe`. On macOS the binaries are unsigned, so clear the
quarantine flag once: `xattr -d com.apple.quarantine /usr/local/bin/secretmgr`.

Point it at your deployment and log in:

```bash
export BACKEND_URL=https://secrets.example.com
secretmgr login
```

### Commands

| Command | Does |
| --- | --- |
| `secretmgr register NAME` | Create an account on this deployment and log in. |
| `secretmgr login NAME` | Log in with your password. |
| `secretmgr login --token T` | Log in with a token the server issued. |
| `secretmgr login` | Log in through GitHub, when the deployment is configured for it. |
| `secretmgr token USER` | Issue a token for someone, without giving them a password. |
| `secretmgr whoami` | Show who you are and how this deployment authenticates. |
| `secretmgr logout` | Remove the stored token. |
| `secretmgr create KEY VALUE` | Store a secret you own. |
| `secretmgr list` | Everything visible to you: yours, plus what others shared. |
| `secretmgr share KEY GITHUB_ID` | Grant another GitHub user read access. |
| `secretmgr delete KEY` | Delete a secret you own. |
| `secretmgr ping` | Check the backend is reachable. |
| `secretmgr version` | Print the CLI version. |

`share` takes whatever identifies the recipient on that deployment: the name
you issued their token under in local mode, or their numeric GitHub user ID in
GitHub mode (`curl -s https://api.github.com/users/<login> | jq .id`).

## Run the server

The backend is a single stateless container listening on port 8000. It keeps
everything in a SQL database and does **not** terminate TLS — whatever you put
in front of it already does.

**Nothing else is required.** The database ships with it (SQLite is part of the
Python standard library) and it issues its own tokens:

```bash
docker run -d -p 8000:8000 -v secretmgr-data:/data \
  ghcr.io/clement880101/secret-manager:latest
```

People sign themselves up with `secretmgr register <name>` — no invitation and
no GitHub account. Close that with `ALLOW_REGISTRATION=false` on anything
reachable from the open internet; an administrator can then hand out access
with `secretmgr token <name>` instead.

The server also prints one token on first start, so there is always a way in:

```
No API tokens existed, so one was created for user 'admin'.
This is shown once and cannot be recovered:

    smt_sGQr0f3dFBP39sUNBm2jpwZ6tnZyFms-dLPcIUp6SwE
```

Set `BOOTSTRAP_TOKEN` to choose it yourself instead. Passwords are hashed with
scrypt and tokens are stored only as a SHA-256, so a copy of the database is
not a set of working credentials.

For anything real, also set `SECRET_ENCRYPTION_KEY` (encrypts values at rest)
and `BACKEND_URL` (the address clients actually reach).

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

Or run it distributed, behind a load balancer, in one command:

```bash
docker compose -f docker-compose.cluster.yml up -d --scale api=3
```

Kubernetes manifests are in [`deploy/k8s/`](deploy/k8s/). Replicas hold no
state, so scaling needs no session affinity and no further configuration.

**[DEPLOYMENT.md](DEPLOYMENT.md) has the detail**: every configuration
variable, choosing a database, reverse proxies, PaaS platforms, Kubernetes,
running multiple replicas, and upgrading.

### Configuration at a glance

| Variable | Required | Notes |
| --- | --- | --- |
| `AUTH_MODE` | no | `local` or `github`. Defaults to `github` when an OAuth app is configured, `local` otherwise. |
| `ALLOW_REGISTRATION` | no | Whether anyone reaching the service may sign up. Default `true`. |
| `BOOTSTRAP_TOKEN` | no | Local mode: the first token, instead of a generated one. |
| `BACKEND_URL` | github mode | Public URL clients reach. GitHub redirects the OAuth callback here. |
| `OAUTH_ID_GITHUB` | github mode | GitHub OAuth app client ID. |
| `OAUTH_SECRET_GITHUB` | github mode | GitHub OAuth app client secret. |
| `SECRET_ENCRYPTION_KEY` | recommended | Fernet key. **Unset means values are stored in plaintext.** |
| `DB_URL` | no | Defaults to local SQLite. Use Postgres for anything real. |
| `ENABLE_API_DOCS` | no | Serve `/docs`. Default `false`. |
| `ENABLE_TEST_LOGIN` | no | Serve `POST /auth/login-test`. Default `false`. |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: none. |
| `TOKEN_CACHE_TTL_SECONDS` | no | Default `300`. `0` disables caching. |

### Using GitHub instead

Set `OAUTH_ID_GITHUB` and `OAUTH_SECRET_GITHUB` and the service switches to
GitHub logins: `secretmgr login` opens a browser, identities are GitHub user
IDs, and the token routes disappear. Create the OAuth app at
<https://github.com/settings/developers> with callback URL
`<BACKEND_URL>/auth/callback`.

The trade: no tokens to hand out and no accounts to administer, in exchange for
every user needing a GitHub account and the server needing outbound access to
`api.github.com`.

## How it works

1. You register, or log in with a password, a token, or GitHub.
2. Every request carries that token as a bearer credential.
3. The backend resolves it to a user: against its own table in local mode, or
   against GitHub (cached briefly) in GitHub mode.
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
| `deploy/` | Compose stacks (single node and clustered) plus Kubernetes manifests. |
| `integration-tests/` | Drives the built binary against a real backend on a real database. |
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
| `integration-tests.yml` | Starts a backend and Postgres, builds the CLI, drives it end to end. No secrets needed. |
| `release.yml` | On a `v*` tag: builds every platform binary, publishes a GitHub Release with `SHA256SUMS`, and pushes a multi-arch image to GHCR. |

## Status

Early, and honest about it. Read the **Known limitations** in
[SECURITY.md](SECURITY.md) before trusting it with anything that matters —
notably that `GET /secrets` returns values in plaintext and there is no rate
limiting.

## License

[Apache License 2.0](LICENSE).
