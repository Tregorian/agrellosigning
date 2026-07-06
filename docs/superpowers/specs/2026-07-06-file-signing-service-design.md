# Agrello File-Signing Service — Design Spec

**Date:** 2026-07-06
**Status:** Approved, ready for implementation planning

## Context

Interview homework: a file-signing service. A user uploads a file via a React
frontend; a Kotlin backend signs it using a recognized standard and returns
enough information for someone to understand what happened and verify it
themselves. Code should be close to production quality, runnable by the
reviewer, and address performance/concurrency for a production deployment.

## Decisions (locked)

| Area              | Choice                                                        |
|-------------------|---------------------------------------------------------------|
| Backend           | Kotlin + Ktor                                                 |
| Signature standard| CMS / CAdES (PKCS#7), **detached** `.p7s`, DER-encoded        |
| Crypto library    | BouncyCastle                                                  |
| Key type          | **EC P-256 + SHA-256** (ECDSA)                                |
| Key handling      | `SigningKeyProvider` interface + PKCS12 keystore impl         |
| Key config        | keystore path / password / alias via **env vars** (12-factor)|
| Demo key          | bundled throwaway keystore + demo defaults in compose         |
| Verification      | in-app `/api/verify` **and** documented `openssl cms -verify` |
| Repo layout       | monorepo (`backend/`, `frontend/`)                            |
| Frontend          | React + Vite + TypeScript, focused single-page flow           |
| Deployment        | Docker + `docker-compose.yml` (one-command run)               |

## Architecture

```
agrellosigning/
├── backend/            Kotlin + Ktor signing & verification service
│   ├── keys/           bundled throwaway demo keystore (labeled, not for prod)
│   └── Dockerfile      multi-stage: Gradle build -> slim JRE runtime
├── frontend/           React + Vite + TS upload UI
│   └── Dockerfile      multi-stage: Node build -> nginx (static + /api proxy)
├── docker-compose.yml  wires both; sets demo env defaults
├── .env.example        documents all config vars (real .env is gitignored)
└── README.md           what it is, how to run, how to verify yourself
```

The backend is **stateless** — no session or per-request state, only the
immutable signing key loaded once at startup. This is the basis of the
concurrency/scaling story: N replicas behind a load balancer, no coordination.

## Backend components

Each unit has one responsibility and a clear interface.

- **`SigningKeyProvider`** (interface) → **`KeystoreSigningKeyProvider`**
  Loads a PKCS12 keystore (private key + certificate) from a configurable
  path/env var, defaulting to the bundled demo keystore. Reads:
  - `SIGNING_KEYSTORE_PATH`
  - `SIGNING_KEYSTORE_PASSWORD`
  - `SIGNING_KEY_ALIAS`
  This is the single seam where production swaps in an HSM/KMS implementation.

- **`CmsSigner`**
  Wraps BouncyCastle. Takes file bytes (streamed), produces a **detached
  CMS/CAdES** `.p7s` (DER). Stateless; a fresh `CMSSignedDataGenerator` /
  `Signature` object per request (those objects are not thread-safe; key
  material is immutable and shared).

- **`CmsVerifier`**
  Takes original file + `.p7s`, recomputes the digest, validates the signature
  against the embedded certificate, returns a structured result: valid?, signer
  subject DN, signing time, algorithm.

- **HTTP routes (Ktor):**
  - `POST /api/sign` — multipart file upload → JSON: SHA-256 fingerprint (hex),
    signer subject, signing time, key/digest algorithm, base64 `.p7s`.
  - `POST /api/verify` — multipart original file + `.p7s` → JSON validity report.
  - `GET /api/certificate` — returns the public certificate (PEM) for openssl.
  - `GET /health` — liveness.

## Crypto choices

- **EC P-256 + SHA-256** (ECDSA). Modern, compact, widely respected. Verification
  is a verification-equation check (not hash-recovery as with RSA); same
  integrity + authenticity guarantees. `openssl cms -verify` supports EC.
- **Detached** signature: user keeps the original file untouched plus a small
  `.p7s` proof file.
- Key type is entirely determined by the keystore contents — swapping to RSA or
  another curve is a keystore change, no code change, thanks to the
  `SigningKeyProvider` abstraction.

## Data flow

1. Frontend uploads a file (multipart) to `POST /api/sign`.
2. Backend streams the bytes through a SHA-256 digest.
3. `CmsSigner` produces a detached CMS/CAdES signature with the private key.
4. Response: fingerprint (hex), signer metadata, signing time, algorithm,
   base64 `.p7s`.
5. Frontend renders a result panel and offers:
   - download the `.p7s`,
   - an in-app **Verify** action round-tripping file + signature to
     `/api/verify`,
   - the documented `openssl` command for independent verification.

## Frontend

Single-page flow (Vite + React + TS):

- Upload/drop a file.
- Result panel: SHA-256 fingerprint, signer subject, timestamp, algorithm,
  `.p7s` download button, and a **"Verify this signature"** button that calls
  `/api/verify` and shows a clear valid/invalid result.
- Clean and readable. No router, auth, or history.

## Performance & concurrency (production considerations)

- **Bounded memory:** enforce a max upload size; stream the upload through the
  digest rather than buffering whole files. The asymmetric signing operates on
  the 32-byte hash, so the crypto step is constant-time regardless of file size.
- **CPU-bound work off the event loop:** run hashing/signing on a dedicated
  dispatcher so Ktor's request-handling threads aren't blocked.
- **Thread-safety:** key material is immutable and shared; per-request creation
  of `Signature` / CMS generator objects (not thread-safe).
- **Horizontal scalability:** statelessness → N instances behind a load balancer,
  no coordination. Scale by adding replicas.
- **Production notes (README):** an HSM/KMS adds per-sign network latency →
  discuss connection pooling, key-handle caching, rate limiting, and
  signing throughput as the primary scaling dimension. A Timestamp Authority
  (TSA) would be integrated for trusted signing time.

## Secret management

- Demo keystore ships as a file (`backend/keys/…`), loudly labeled throwaway.
- `docker-compose.yml` sets keystore path/password/alias env vars to demo
  defaults → `docker compose up` runs with no setup.
- `.env.example` documents every config var; real `.env` is gitignored.
- README states: in production the keystore is never committed — env vars are
  injected from a secret manager, and ideally the key never touches disk
  (HSM/KMS via the same `SigningKeyProvider` seam).

## Testing

- **Backend unit tests:**
  - `CmsSigner`/`CmsVerifier` round-trip: sign → verify succeeds.
  - Tamper detection: altering the file after signing → verify fails.
  - Cross-check: generated `.p7s` verifies against the certificate.
- **Route test:** `POST /api/sign` returns the expected structured response.
- **Human acceptance check:** README-documented `openssl cms -verify` command.

## Deliberately out of scope (YAGNI)

Auth/users, persistence/history, multi-file batches, TSA integration, real
CA-issued certificates. HSM/KMS and TSA are noted as "next steps" in the README
to show awareness of where this goes in production.

## Deployment / running it

- **Docker (primary):** `docker compose up` → open the browser. Any device with
  Docker; no local JDK/Node required.
  - `backend/Dockerfile`: multi-stage Gradle build → slim JRE runtime.
  - `frontend/Dockerfile`: multi-stage Node build → nginx serving static bundle
    and reverse-proxying `/api` to the backend.
- **Native (documented alternative):** Gradle for backend, npm/Vite for frontend.
