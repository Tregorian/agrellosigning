# Demo keys — THROWAWAY, NOT FOR PRODUCTION

`demo-keystore.p12` holds a self-signed EC P-256 key used only so the service
runs out of the box. It protects nothing and must never be used for real
signing. In production the keystore is injected via env vars from a secret
manager, or the key lives in an HSM/KMS behind the same `SigningKeyProvider`.

- Store password / key password: `changeit`
- Alias: `signing`
- `demo-cert.pem` is the matching public certificate (for `openssl` verification).
