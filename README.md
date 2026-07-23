# algaguard-device-service

Durable device registry, claim, bootstrap-session, per-device X.509 credential lifecycle, tank-association, status, and health service.

PostgreSQL is the runtime source of truth; `MemoryDeviceRepository` is an explicit test adapter only. Human JWTs are verified locally and organization/device actions are authorized through Access Service using a cached OIDC client-credentials token. No arbitrary identity header is trusted.

Each device has an immutable canonical `deviceId` (`AG-######`) for firmware, QR, and MQTT plus a stable `deviceUuid` for REST, authorization, and WebSocket resources. Device Service is the authoritative mapping source. Authenticated backend services resolve an active mapping through `GET /v1/internal/devices/by-device-id/{deviceId}/context` or its UUID-keyed alias `GET /v1/internal/devices/{deviceUuid}/context`; the response adds backend-owned `organizationId` and monotonic `ownershipVersion` and contains no credentials.

Ownership transfer updates the organization and version atomically, records immutable history, and refreshes the Access Service resource hook. Historical consumers retain the organization accepted at ingest rather than rewriting past ownership.

## Commands

```sh
npm ci
npm run migrate
npm run check
npm run test:integration
npm run dev
```

Claim QR values conform to the additive onboarding contracts. High-entropy claim, fallback, and bootstrap values are stored only as SHA-256 digests, expire, are one-use, and are redacted from logs. Claim consumption and bootstrap creation are one PostgreSQL transaction; concurrent attempts yield one success. Persistent failure windows rate-limit guessing.

## Device certificates

`DeviceCredentialService` accepts CSR public material only. It binds the canonical `deviceId` to the certificate CN and the immutable `deviceUuid` to exactly one SAN URI, stores the SHA-256 fingerprint plus public certificate metadata, and retains issuance, rotation, revocation, and audit history. No device private key or CA private key is accepted by an API, stored in PostgreSQL, or returned in a response.

The provider-independent `CertificateAuthorityAdapter` has an explicit local OpenSSL implementation for development. Select it with `DEVICE_CA_PROVIDER=local-development`, absolute `DEVICE_CA_CERTIFICATE_PATH` and `DEVICE_CA_PRIVATE_KEY_PATH` values, and a minimum 32-character `BROKER_DEVICE_AUTH_TOKEN`. The local adapter refuses `NODE_ENV=production`; a production CA provider remains an interface decision.

The broker calls `POST /v1/internal/device-credentials/authenticate` with its static service bearer token, the certificate-derived client ID, and the verified public certificate. Device Service validates the recorded fingerprint, serial, CN, SAN UUID, certificate time, credential state, bounded rotation overlap, and active device lifecycle, then returns exact device-scoped ACL rules. Revocation state is authoritative in PostgreSQL; an optional broker management adapter disconnects the canonical client ID after rotation, revocation, or compromise.

Development limits are environment-configurable: HTTP body size, bootstrap lifetime and attempts, certificate validity, rotation overlap, broker keepalive/session expiry, authentication cache, and revocation enforcement interval. Defaults are bounded in `src/config.ts`.

The earlier username/password development credential provider remains isolated, disabled by default, and cannot activate when `NODE_ENV=production`; the authenticated credential E2E does not use it. This repository validates simulated certificate flows only and does not claim physical QR, BLE, Wi-Fi, production CA, or ESP32 success.
