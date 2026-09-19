# Secret Manager

A lightweight, distributed secret manager you run in your own cloud. Store a
secret, share it with a teammate, read it back from any machine.

```bash
docker pull ghcr.io/clement880101/secret-manager
```

- **One binary.** Under 10 MB, no Python, no runtime to install.
- **One container.** Configured entirely through environment variables.
- **Actually distributed.** No state in process memory, so it runs behind a load
  balancer across as many replicas as you like.
- **Nothing external required.** Its own accounts, its own tokens, its own
  database. `docker run` is the whole setup. No identity provider, no outbound
  network access, no third party involved at all.

```bash
docker run -d -p 8000:8000 -v secretmgr-data:/data \
  ghcr.io/clement880101/secret-manager:latest

secretmgr register alice     # your teammates do the same
secretmgr create db-pw hunter2
secretmgr share db-pw bob
secretmgr get db-pw          # values are fetched one at a time
```

[Website](https://clement880101.github.io/secret-manager/) ·
[Download](https://github.com/clement880101/secret-manager/releases/latest) ·
[Deployment](DEPLOYMENT.md) · [Security](SECURITY.md) ·
[About the author](https://clement880101.github.io/personal-web/)

---

## What you need to run it

**A container runtime. That is the whole list.** AWS, GCP, Azure, a VPS,
Kubernetes, or a laptop — anywhere that runs a container.

```bash
docker run -d -p 8000:8000 -v secretmgr-data:/data \
  ghcr.io/clement880101/secret-manager:latest
```

No database to provision, no identity provider, no TLS certificate, no
config file, no accounts to create in advance. The volume is the one thing not
to skip: without it the database lives in the container's writable layer and
goes away with the container.

Then, depending on what you are doing:

| If you want | Add |
| --- | --- |
| Anything you would miss | `SECRET_ENCRYPTION_KEY`, or values are stored unencrypted |
| Clients on other machines | `BACKEND_URL`, and TLS in front of it |
| To not be publicly signup-able | `ALLOW_REGISTRATION=false` |
| More than one replica | `DB_URL` pointing at Postgres, and a fixed `BOOTSTRAP_TOKEN` |
| A specific listen port | `PORT` — honoured automatically on Cloud Run and similar |

For the CLI: one binary, no runtime. Set `BACKEND_URL` to your own server —
without it the CLI talks to the project's demo deployment, which is not where
you want your secrets.

## Production checklist

Working through this is the difference between a demo and a deployment:

- [ ] **`SECRET_ENCRYPTION_KEY` set**, and backed up somewhere you can get it
      from. Losing it makes every stored value unreadable, permanently.
- [ ] **TLS in front.** The service speaks plain HTTP by design; terminate at
      your proxy, ingress or platform. The CLI warns when it is talking
      cleartext to a remote host.
- [ ] **`DB_URL` pointing at Postgres**, not the bundled SQLite, if you run more
      than one replica or your platform replaces containers.
- [ ] **Database backed up.** Nothing here backs itself up.
- [ ] **`ALLOW_REGISTRATION=false`** if the deployment is reachable from the
      open internet and you know who should have accounts.
- [ ] **`BOOTSTRAP_TOKEN` set and then rotated**, or the first token sits in
      your logs.
- [ ] **`ENABLE_API_DOCS` left off**, so the schema is not published.
- [ ] Checksums verified on any binary you distribute internally.
- [ ] You have read the **Known limitations** in [SECURITY.md](SECURITY.md) —
      particularly that there is no key rotation, no schema migration path, and
      nothing here backs itself up.

Read [SECURITY.md](SECURITY.md) for what this does *not* do. There are real
limitations and they are listed plainly.

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
no external account. Close that with `ALLOW_REGISTRATION=false` on anything
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
| `ALLOW_REGISTRATION` | no | Whether anyone reaching the service may sign up. Default `true`. |
| `ENABLE_AUDIT_LOG` | no | Record who did what. Default `true`. |
| `AUDIT_RETENTION_DAYS` | no | How long events are kept. Default `90`, `0` keeps forever. |
| `MAX_REQUEST_BYTES` | no | Largest accepted request body. Default `262144`. |
| `AUTH_RATE_LIMIT` | no | Failed logins allowed per username and per address. Default `10`, `0` disables. |
| `BOOTSTRAP_TOKEN` | no | Local mode: the first token, instead of a generated one. |
| `BACKEND_URL` | no | The public address clients reach. Only used for display and warnings. |
| `SECRET_ENCRYPTION_KEY` | recommended | Fernet key. **Unset means values are stored in plaintext.** |
| `DB_URL` | no | Defaults to local SQLite. Use Postgres for anything real. |
| `ENABLE_API_DOCS` | no | Serve `/docs`. Default `false`. |
| `ENABLE_TEST_LOGIN` | no | Serve `POST /auth/login-test`. Default `false`. |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: none. |
| `TOKEN_CACHE_TTL_SECONDS` | no | Default `300`. `0` disables caching. |


## Then install the CLI

Once your server is up, this is how people talk to it. Download the build
for your platform, make it executable, put it on your `PATH`:

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
| `secretmgr passwd` | Change your password. |
| `secretmgr revoke TOKEN` | Revoke a token, after losing a machine. |
| `secretmgr token USER` | Issue a token for someone, without giving them a password. |
| `secretmgr whoami` | Show who you are and how this deployment authenticates. |
| `secretmgr logout` | Remove the stored token. |
| `secretmgr create KEY VALUE` | Store a secret you own. |
| `secretmgr list` | The keys you can see. Values are not included. |
| `secretmgr get KEY` | Print one secret's value. |
| `secretmgr audit` | Recent activity on your account. |
| `secretmgr share KEY USER` | Grant a teammate read access. |
| `secretmgr delete KEY` | Delete a secret you own. |
| `secretmgr ping` | Check the backend is reachable. |
| `secretmgr version` | Print the CLI version. |

`share` takes the username the recipient registered with.

## How it works

1. You register, or log in with a password or a token the server issued.
2. Every request carries that token as a bearer credential.
3. The backend resolves it against its own table. Only the SHA-256 of a token
   is stored, and passwords are hashed with scrypt.
4. Secrets are encrypted before they reach the database, decrypted on read.

Nothing lives in process memory: accounts, tokens and rate-limit counters are
all in the database. Any replica can serve any request, so scaling needs no
session affinity and a redeploy interrupts nothing.

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

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)
for how to get set up and what makes a change easy to accept, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release notes are in
[CHANGELOG.md](CHANGELOG.md).

## Status

Early, and honest about it. Read the **Known limitations** in
[SECURITY.md](SECURITY.md) before trusting it with anything that matters.

Two things that were on that list are now fixed: `list` returns keys without
values, so one stolen token no longer hands over everything in a single
request, and every read, write, share and deletion is recorded — `secretmgr
audit` shows what was done as you.

## License

[Apache License 2.0](LICENSE).
