# Contributing

Thanks for looking. Issues and pull requests are welcome.

## Getting set up

Each component is independent:

```bash
cd backend && pip install -r requirements-dev.txt && pytest
cd cli     && pip install -r requirements-dev.txt && pytest
```

Some backend tests need a real database and skip without one, deliberately:
SQLite serialises writers, so it would report success for code that is not
actually safe to run on more than one replica.

```bash
docker run -d -p 5432:5432 -e POSTGRES_USER=sm -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=sm postgres:16-alpine
TEST_POSTGRES_URL=postgresql+psycopg://sm:secret@localhost:5432/sm pytest
```

To run the whole thing end to end, `deploy/docker-compose.yml` brings up the API
and a Postgres together.

## What makes a change easy to accept

- **A test that fails without the change.** Most of the bugs found in this
  repository were found by writing the test first and watching it fail.
- **Say why in the commit message, not just what.** The diff already shows what
  changed; what it cannot show is the reasoning, or the option you rejected.
- **Keep the image small and the dependencies few.** This is meant to be pulled
  and run. A new runtime dependency needs to earn its place — password hashing
  uses `hashlib.scrypt` rather than bcrypt for exactly this reason.
- **Do not add a test-only switch to production code.** The integration suite
  stubs GitHub from its own harness (`integration-tests/stub_backend.py`)
  precisely so the application has no such flag to turn on by accident.

## Things to know before changing the database

There is no migration framework. `create_all()` adds missing tables but will not
add a column to a table that already exists, so a change that needs new storage
should be a new table rather than a new column. That is why credentials, tokens
and login sessions each live in their own table.

## Security

Please report vulnerabilities through
[a security advisory](https://github.com/clement880101/secret-manager/security/advisories/new)
rather than a public issue. See [SECURITY.md](SECURITY.md).
