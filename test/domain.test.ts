import assert from "node:assert/strict";
import test from "node:test";
import {
  DevelopmentCredentialProvider,
  DomainError,
  MemoryDeviceRepository,
  secretDigest,
} from "../src/domain.js";

async function fixture() {
  const repository = new MemoryDeviceRepository();
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const device = await repository.createDevice({
    organizationId,
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  return { repository, organizationId, device };
}

test("claim QR is contract-shaped and contains no Wi-Fi or permanent credential", async () => {
  const { repository, device } = await fixture();
  const qr = await repository.createClaim(device.deviceId, 60_000, "owner");
  assert.match(qr.d, /^AG-[0-9]{6}$/);
  assert.match(qr.c, /^[A-Za-z0-9_-]{32,64}$/);
  assert.match(qr.f, /^[A-HJ-NP-Z2-9]{8,12}$/);
  assert.doesNotMatch(
    JSON.stringify(qr),
    /wifi|password|privateKey|mqttPassword/i,
  );
  assert.notEqual(secretDigest(qr.c), qr.c);
});

test("claim consumption is one-use under concurrent attempts and survives cross-org checks", async () => {
  const { repository, organizationId, device } = await fixture();
  const qr = await repository.createClaim(device.deviceId, 60_000, "owner");
  await assert.rejects(
    repository.consumeClaim({
      deviceId: device.deviceId,
      secret: qr.c,
      organizationId: "20000000-0000-4000-8000-000000000002",
      subjectId: "owner",
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "CROSS_ORGANIZATION_DENIED",
  );
  const outcomes = await Promise.allSettled([
    repository.consumeClaim({
      deviceId: device.deviceId,
      secret: qr.c,
      organizationId,
      subjectId: "owner",
    }),
    repository.consumeClaim({
      deviceId: device.deviceId,
      secret: qr.c,
      organizationId,
      subjectId: "owner",
    }),
  ]);
  assert.equal(
    outcomes.filter((value) => value.status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter((value) => value.status === "rejected").length,
    1,
  );
});

test("claim and bootstrap expiry are enforced", async () => {
  const { repository, organizationId, device } = await fixture();
  const expired = await repository.createClaim(device.deviceId, 1, "owner");
  await assert.rejects(
    repository.consumeClaim({
      deviceId: device.deviceId,
      secret: expired.c,
      organizationId,
      subjectId: "owner",
      now: new Date(Date.now() + 2),
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "CLAIM_UNAVAILABLE",
  );
  const active = await repository.createClaim(device.deviceId, 60_000, "owner");
  const consumed = await repository.consumeClaim({
    deviceId: device.deviceId,
    secret: active.c,
    organizationId,
    subjectId: "owner",
    now: new Date("2026-07-23T00:00:00Z"),
  });
  await assert.rejects(
    repository.consumeBootstrap(
      device.deviceId,
      consumed.bootstrap.sessionToken,
      new Date("2026-07-23T00:06:00Z"),
    ),
    (error: unknown) =>
      error instanceof DomainError && error.code === "BOOTSTRAP_UNAVAILABLE",
  );
});

test("failed claim attempts are rate limited", async () => {
  const { repository, organizationId, device } = await fixture();
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await assert.rejects(
      repository.consumeClaim({
        deviceId: device.deviceId,
        secret: "INVALID-CODE",
        organizationId,
        subjectId: "owner",
      }),
      (error: unknown) =>
        error instanceof DomainError && error.code === "CLAIM_UNAVAILABLE",
    );
  }
  await assert.rejects(
    repository.consumeClaim({
      deviceId: device.deviceId,
      secret: "INVALID-CODE",
      organizationId,
      subjectId: "owner",
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "CLAIM_RATE_LIMITED",
  );
});

test("development credentials are isolated and disabled unless explicitly enabled", async () => {
  await assert.rejects(
    new DevelopmentCredentialProvider(false).issue("AG-000001"),
  );
  const issued = await new DevelopmentCredentialProvider(true).issue(
    "AG-000001",
  );
  assert.equal(issued.username, "AG-000001");
  assert.ok(issued.password.length >= 32);
});
