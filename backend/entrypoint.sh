#!/bin/sh
# Start the API, honouring whatever the platform asks for.
#
# Several hosts (Cloud Run, Heroku-style platforms, some PaaS) inject the port
# they expect the process to listen on rather than letting the image choose, so
# a hardcoded port makes the image unusable there. PORT wins when it is set.
#
# The log level was previously pinned to debug, which is noisy in production and
# logs more than an operator asked for.
set -e

exec uvicorn app:app \
  --host "${HOST:-0.0.0.0}" \
  --port "${PORT:-8000}" \
  --log-level "${LOG_LEVEL:-info}" \
  --proxy-headers \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}"
