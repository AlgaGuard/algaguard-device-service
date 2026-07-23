# algaguard-device-service

Durable device registry, claim, bootstrap-session, lifecycle, tank-association, status, and health service.

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

The development credential provider is isolated behind `DeviceCredentialProvider`, disabled by default, and cannot activate when `NODE_ENV=production`. This repository does not claim physical QR, BLE, Wi-Fi, MQTT credential-provider, or ESP32 success.
