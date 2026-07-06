# Agrello Signing

A small file-signing service: upload a file, get back a detached **CMS/CAdES-BES**
signature produced with an EC P-256 key, view the signer certificate, and verify
signature + file together — either in the app or independently with `openssl`.

Monorepo: `backend/` (Kotlin 2.1 + Ktor 3.1.1, JDK 21) and `frontend/` (React 19 +
Vite 6 + TypeScript).

## Quick start (Docker)

Requires Docker 29+ and `docker compose` v2+.

```bash
docker compose up --build
```

Open `http://localhost:3000`. The frontend is served by nginx and proxies `/api`
to the backend container. The backend image build runs the full test suite as a
quality gate — the build fails if any test fails.

## Quick start (native)

Backend (serves on `:8080`):

```bash
cd backend
./gradlew run
```

Frontend (Vite dev server, proxies `/api` to `:8080`):

```bash
cd frontend
npm install
npm run dev
```

Backend configuration is via environment variables (see [Key & certificate
handling](#key--certificate-handling) below); copy `.env.example` to `.env` to
override locally.

## What gets signed

The service signs the **raw bytes of the uploaded file** — not a derived hash
alone, though SHA-256 of the file is computed and shown as a fingerprint. The
signature returned is a **detached** CMS/CAdES-BES signature (`.p7s`, DER-encoded):
the signature file contains no copy of the original content, so both the file and
the `.p7s` are needed to verify.

### Endpoints

- `GET /health` — liveness check.
- `POST /api/sign` — multipart field `file` → JSON: `fileName`, `sha256Hex`,
  `signerSubject`, `signingTime`, `signatureAlgorithm`, `signatureFormat`,
  `signatureBase64`.
- `POST /api/verify` — multipart fields `file` + `signature` → JSON: `valid`,
  `signerSubject`, `signingTime`, `signatureAlgorithm`, `reason`.
- `GET /api/certificate` — the signer's certificate as PEM.

## Verify it yourself

You don't have to trust the app's own verify button — the signature is a
standard CMS structure and can be checked with `openssl`. After signing a file
in the app, download its `.p7s` next to the original, then:

```bash
curl -s http://localhost:3000/api/certificate > cert.pem
openssl cms -verify -binary -content <original-file> -in <original-file>.p7s \
  -inform DER -CAfile cert.pem -noverify
```

Expected output: `CMS Verification successful`.

Notes:
- Use port `3000` through the Docker/nginx setup, or `8080` if you're running
  the backend natively.
- `-noverify` (OpenSSL 3.x) skips certificate-chain building, which is expected
  here since the demo certificate is self-signed. The older `-no_signer_cert_verify`
  flag does not exist in OpenSSL 3.x.

## Standard used

**CMS/CAdES-BES**, detached — [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)
(Cryptographic Message Syntax) profiled by
[ETSI EN 319 122](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/) (CAdES),
built with BouncyCastle 1.79.

Signed attributes included in every signature:

- `content-type`
- `message-digest`
- `signing-time`
- `signing-certificate-v2` (ESSCertIDv2) — this is what elevates a plain CMS
  signature to CAdES-BES, binding the signature to the specific signing
  certificate and preventing certificate-substitution attacks.

## Key & certificate handling

Signing key: **EC P-256** (secp256r1), signature algorithm **SHA256withECDSA**.

The key is accessed through a `SigningKeyProvider` interface, with a single
implementation today backed by a PKCS12 keystore
(`KeystoreSigningKeyProvider`). That seam is what would let a production
deployment swap in an HSM- or KMS-backed provider without touching the signing
or verification code.

Configuration (environment variables, all optional — defaults shown):

| Variable                    | Default                      | Purpose                          |
|------------------------------|-------------------------------|-----------------------------------|
| `SIGNING_KEYSTORE_PATH`      | `keys/demo-keystore.p12`      | Path to the PKCS12 keystore       |
| `SIGNING_KEYSTORE_PASSWORD`  | `changeit`                    | Keystore / key password           |
| `SIGNING_KEY_ALIAS`          | `signing`                     | Key alias inside the keystore     |
| `MAX_UPLOAD_BYTES`           | `26214400` (25 MiB)           | Upload size cap                   |
| `SERVER_PORT`                | `8080`                        | Backend listen port               |

The committed `backend/keys/demo-keystore.p12` is a **throwaway, self-signed**
key, checked in deliberately (see `backend/keys/README.md`) so the service runs
out of the box with no setup. It protects nothing. In production the keystore
(or its credentials) would be injected from a secret manager, or the key would
live in an HSM/KMS accessed through the same `SigningKeyProvider` interface —
never committed to source control.

## Architecture

```
backend/    Kotlin + Ktor API — signing, verification, key management, routes
frontend/   React + TypeScript SPA — upload, sign, view, verify
docker-compose.yml   builds and wires both services (nginx serves the frontend
                      and proxies /api to the backend)
```

Backend layout (`backend/src/main/kotlin/com/agrello/signing/`):

- `Application.kt` — Ktor server setup and plugin wiring.
- `config/AppConfig.kt` — environment-variable configuration.
- `routes/HealthRoutes.kt`, `routes/SigningRoutes.kt` — HTTP endpoints.
- `signing/SigningKeyProvider.kt` + `KeystoreSigningKeyProvider.kt` — key access seam.
- `signing/CmsSigner.kt`, `signing/CmsVerifier.kt` — CMS/CAdES-BES construction and verification.
- `model/Dtos.kt` — request/response shapes.

Request flow for `POST /api/sign`: multipart upload → bytes read into memory
(bounded by `MAX_UPLOAD_BYTES`) → SHA-256 computed → CMS signed-data built over
the bytes with the signing certificate and signed attributes → DER-encoded
detached signature returned as base64 alongside metadata. `POST /api/verify`
re-derives the digest from the uploaded file and checks it, and the signature's
internal consistency, against the uploaded `.p7s`.

The backend is **stateless**: no database, no session, no server-side file
retention beyond the current request.

## Performance & concurrency

- **Stateless backend** — no shared mutable state between requests, so it
  scales horizontally: run N replicas behind a load balancer with no
  coordination required.
- **CPU-bound signing is offloaded** to `Dispatchers.Default` so it doesn't
  block Ktor's request-handling threads under load.
- **Uploads are size-bounded** by `MAX_UPLOAD_BYTES` to cap per-request memory
  use.
- **Crypto objects are per-request**: BouncyCastle's signature/CMS generators
  are not thread-safe, so a fresh one is built per request, while the
  (immutable) key material is loaded once and shared.
- For very large files, the current implementation buffers the file in memory;
  a production version would use `CMSSignedDataStreamGenerator` to stream the
  content through signing rather than holding it all in memory.
- The main scaling dimension is **signing throughput**. If the key moves to an
  HSM or KMS, every signing operation gains network latency to that service —
  at that point, connection pooling and/or key-handle caching against the HSM/KMS
  becomes the relevant optimization, not raw CPU.

## Testing

Native (requires a local JDK/Gradle toolchain):

```bash
cd backend
./gradlew test
```

No local toolchain required, via Docker:

```bash
docker run --rm -v "$PWD/backend:/app" -w /app gradle:8.11-jdk21 gradle test --no-daemon
```

Tests also run automatically as part of the Docker image build — `docker
compose up --build` fails if any test fails, so the test suite doubles as a
build gate.

Coverage includes:

- Sign → verify round-trip (a validly signed file verifies successfully).
- Tamper detection (an altered file fails verification against its original
  signature).
- Malformed-input handling (bad/missing multipart fields, corrupt signatures).
- Route-level responses for `/health`, `/api/sign`, `/api/verify`, `/api/certificate`.
- Keystore loading (`KeystoreSigningKeyProviderTest`).

## Known simplifications (what production would add)

This project is scoped as a demonstration of the signing/verification core, not
a production-ready service. Known gaps, stated plainly:

- **CORS** uses `anyHost()` for convenience. Production would restrict this to
  a known set of allowed origins.
- **Error handling** currently maps all uncaught exceptions to HTTP 400 via a
  single StatusPages handler. Production would use a tiered handler that
  distinguishes client errors (4xx) from server faults (5xx).
- **Docker base images** are pinned to major versions only. Production builds
  would pin exact patch versions or digests for reproducibility.
- **Signing key** is a committed, self-signed throwaway (see above). Production
  never commits key material — it's injected via a secret manager or held in
  an HSM/KMS.
- **No trusted timestamp (TSA).** The signature includes a local `signing-time`
  attribute but no RFC 3161 timestamp from a trusted authority. A CAdES-T
  upgrade would add TSA timestamping, which is what gives a signature long-term
  validity independent of the signer's certificate lifetime.

## Deliberate scope cuts

Out of scope for this task, and not implemented:

- **Authentication / user accounts** — anyone who can reach the API can sign or verify.
- **Persistence / history** — nothing is stored; each request is independent and
  nothing is retained after the response is returned.
- **Multi-file / batch signing** — one file per request.
- **Trusted timestamping (TSA / CAdES-T)** — see above.
- **Real CA-issued certificates** — the demo certificate is self-signed, not
  chained to a trusted root.

Natural next steps, roughly in order of production impact: real certificate
(CA-issued or private PKI), TSA timestamping (CAdES-T), then auth and
persistence if the service needs to track who signed what over time.
