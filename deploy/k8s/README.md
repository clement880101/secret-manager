# Kubernetes

Three API replicas, a Postgres, and a Service. Replicas hold no state — login
state, sessions and issued tokens all live in the database — so this scales
with `kubectl scale` and needs no session affinity anywhere.

```bash
kubectl create secret generic secretmgr \
  --from-literal=SECRET_ENCRYPTION_KEY="$(docker run --rm \
      ghcr.io/clement880101/secret-manager:latest \
      python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=BOOTSTRAP_TOKEN="smt_$(openssl rand -hex 24)"

kubectl apply -f 10-postgres.yaml
kubectl apply -f 20-api.yaml
kubectl rollout status deployment/secretmgr
```

Then edit `BACKEND_URL` in `20-api.yaml` to the address clients actually reach,
and apply `30-ingress.example.yaml` (or your own) to terminate TLS.

## Notes

- **`BOOTSTRAP_TOKEN` is not optional here.** Without a fixed value each replica
  would mint its own first token on the way up, and only one of them would be
  the one you hold.
- **`POSTGRES_PASSWORD` is declared before `DB_URL`.** Kubernetes expands
  `$(VAR)` only from variables earlier in the same list, so the other order
  passes the placeholder through literally and the connection fails with a
  confusing name-resolution error.
- **`/healthz` touches no database**, so it keeps answering while the database
  is briefly unavailable rather than triggering a restart loop.
- The bundled Postgres exists so this directory works on its own. Point `DB_URL`
  at a managed database instead if you have one.

## Scaling

```bash
kubectl scale deployment/secretmgr --replicas=10
```

Nothing else to change.
