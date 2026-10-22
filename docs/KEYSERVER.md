# ARAP keyserver

The current service is an immutable public object store with proof-prefix lookup and a public-key directory. It does not verify signatures, decide callsign trust, or assert that a key belongs to a callsign. Clients must perform those checks locally.

## Run

Set an upload credential and start the Compose service for containers on its Docker network:

```sh
export ARAP_UPLOAD_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
```

The base Compose file does not publish an HTTP port on the Docker host. If HAProxy runs on the same host, add the optional loopback-only port mapping:

```sh
docker compose -f compose.yaml -f compose.haproxy.yaml up --build -d
```

HAProxy can then use `127.0.0.1:8080` as its backend. If the proxy runs on another machine, set `ARAP_PUBLISH_ADDRESS` to a private IPv4 address on the Docker host and `ARAP_PUBLISH_PORT` to the selected port before starting Compose. Restrict that port in the host firewall to the proxy address. Keep TLS termination at HAProxy; the keyserver itself serves HTTP.

Every server construction path rejects upload tokens with fewer than 32 non-padding characters or characters invalid in a Bearer credential. This is a syntax and minimum-length check, not an entropy measurement; supply a cryptographically random token. The command above creates a 256-bit random hexadecimal token. Keep it in a protected environment or secrets manager; do not commit it. Put the service behind the existing HTTPS proxy before remote use. Keep the data volume backed up. Reads are public; writes require `Authorization: Bearer <token>` (raw tokens and other schemes are rejected). SQLite-backed accounting applies per-kind object caps and one shared byte cap across proofs and keys. The default limits are 100,000 proofs, 10,000 keys, 10 GiB total object bytes, and 600 authenticated PUT requests per minute. The rate limit is service-wide and uses a persistent fixed minute window. A quota rejection returns HTTP 507; rate limiting returns HTTP 429 with `Retry-After: 60`.

Configure limits through Compose environment variables: `ARAP_MAX_PROOF_OBJECTS`, `ARAP_MAX_KEY_OBJECTS`, `ARAP_MAX_TOTAL_BYTES`, and `ARAP_MAX_UPLOADS_PER_MINUTE` must be positive integers. `ARAP_RETENTION_DAYS` defaults to `0`, which keeps objects indefinitely; a positive value expires objects after that many days. Expired objects are pruned on startup and during reads, lookup, and writes. Accounting is rebuilt from regular files in the data directories on startup, so keep the SQLite index and object directories on the same persistent volume and avoid editing the volume while the service runs.

The object server is still a single-node service. It does not provide replicated storage, per-client quotas, distributed rate limits, certificate-chain validation, or production deployment validation. Upload requests must contain exactly one `Authorization` header; duplicate values are rejected to avoid disagreement between proxies and the application.

## Endpoints

| Method and path | Behavior |
| --- | --- |
| `GET /healthz` | Readiness check for the SQLite index and writable proof/key object directories. Returns HTTP 503 when storage is unavailable. |
| `PUT /v1/proofs/{sha256-hex}` | Authenticated upload, at most 64 KiB. The path digest must match the exact uploaded COSE bytes. Objects are immutable. |
| `GET /v1/proofs/{sha256-hex}` | Read only indexed objects, enforce the 64 KiB proof bound, and return an object only after rechecking its SHA-256. |
| `GET /v1/lookup/{base32-prefix}` | Return candidate full hashes for a 16-symbol uppercase, unpadded Base32 prefix; `truncated` reports the 100-candidate bound. |
| `PUT /v1/keys/{spki-sha256-hex}` | Authenticated upload of a PEM public key or certificate, at most 1 MiB. The SPKI fingerprint must match the path. |
| `GET /v1/keys/{spki-sha256-hex}` | Read only indexed objects, enforce the 1 MiB key bound, and return a stored public key/certificate after checking its fingerprint. |

The 80-bit AR1 lookup token is the Base32 representation of the first ten bytes of the proof hash. The client must verify the returned full hash, signature, signed purpose, content and local trust. Multiple candidates are ambiguous. No callsign directory or certificate-status responder exists yet.

The CLI can fingerprint and publish either a public-key SPKI PEM or an X.509 certificate PEM using the certificate's subject public key. Fetching checks that same SPKI fingerprint. A published certificate is only an untrusted candidate: ARAP does not validate its chain, usage, callsign binding or revocation status. The current proof profile still verifies Ed25519 signatures only.

The Go resolver and CLI reject redirects, require HTTPS for remote base URLs, verify returned content hashes and reject ambiguous or truncated AR1 lookups. `resolve`, `verify-ref`, and `fetch-key` accept repeated `--server` flags (up to eight URLs). AR1 resolution merges candidates from every configured resolver and fails closed if any lookup is unavailable, malformed or truncated; full-hash and key fetches retry other resolvers and accept only matching content hashes/fingerprints. This detects collisions present in the configured set but cannot prove that a malicious server returned every candidate. Publishing targets the first configured URL. The desktop accepts comma- or semicolon-separated resolver URLs for fetches and publishes to the first.

The Compose file uses a non-root static container, a named persistent volume, a read-only root filesystem, a required upload token and a Docker health check against `/healthz`. The optional `compose.haproxy.yaml` overlay publishes HTTP on loopback by default and supports an explicit private host address for a remote proxy. The readiness handler confirms the SQLite index responds and can create/remove probe files in both object directories. TLS termination and authorization policy beyond the bearer token remain deployment responsibilities.
