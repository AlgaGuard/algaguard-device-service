# algaguard-device-service

Durable device registry, claim, bootstrap-session, lifecycle, tank-association, status, and health service.

PostgreSQL is the runtime source of truth; `MemoryDeviceRepository` is an explicit test adapter only. Human JWTs are verified locally and organization/device actions are authorized through Access Service using a cached OIDC client-credentials token. No arbitrary identity header is trusted.

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
