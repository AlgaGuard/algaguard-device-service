import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import {
  AuthenticationError,
  type AccessAuthorizer,
  type Authenticator,
} from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import { MemoryDeviceRepository } from "../src/domain.js";
import {
  MemoryPhysicalSessionHandoffStore,
  PhysicalSessionCipher,
  PhysicalSessionHandoffService,
} from "../src/physical-session-handoff.js";

const organizationId = "10000000-0000-4000-8000-000000000001";
const wrappingKey = Buffer.alloc(32, 7).toString("base64url");

function fixture() {
  let current = new Date();
  const repository = new MemoryDeviceRepository();
  const store = new MemoryPhysicalSessionHandoffStore();
  const service = new PhysicalSessionHandoffService(
    repository,
    store,
    PhysicalSessionCipher.fromBase64Url(wrappingKey),
    () => current,
  );
  return {
    repository,
    store,
    service,
    now: () => current,
    advance: (milliseconds: number) => {
      current = new Date(current.getTime() + milliseconds);
    },
  };
}

async function activeSession(
  repository: MemoryDeviceRepository,
  now = new Date(),
) {
  const device = await repository.createDevice({
    organizationId,
    hardwareModel: "test-device",
  });
  const claim = await repository.createClaim(
    device.deviceId,
    600_000,
    "test-user",
  );
  const consumed = await repository.consumeClaim({
    deviceId: device.deviceId,
    secret: claim.c,
    organizationId,
    subjectId: "test-user",
    now,
  });
  return { device, bootstrap: consumed.bootstrap };
}

async function approveActive(
  value: ReturnType<typeof fixture>,
  handoff: Awaited<ReturnType<PhysicalSessionHandoffService["start"]>>,
) {
  const active = await activeSession(value.repository, value.now());
  await value.service.approve({
    userCode: handoff.userCode,
    sessionId: active.bootstrap.sessionId,
    deviceId: active.device.deviceId,
    sessionToken: active.bootstrap.sessionToken,
    authorizedOrganizationId: organizationId,
    authorizedOwnershipVersion: active.device.ownershipVersion,
  });
  return active;
}

test("feature defaults disabled and rejects production or a missing wrapping key", () => {
  assert.equal(
    loadConfig({
      DATABASE_URL: "postgres://localhost/test",
      REDIS_URL: "redis://localhost",
    }).ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF,
    "0",
  );
  assert.throws(() =>
    loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://localhost/test",
      REDIS_URL: "redis://localhost",
      ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF: "1",
      PHYSICAL_SESSION_HANDOFF_WRAPPING_KEY: wrappingKey,
    }),
  );
  assert.throws(() =>
    loadConfig({
      DATABASE_URL: "postgres://localhost/test",
      REDIS_URL: "redis://localhost",
      ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF: "1",
    }),
  );
});

test("start returns high-entropy codes and persists only digests", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const stored = await value.store.byDeviceCodeHash(
    (await import("../src/domain.js")).secretDigest(handoff.deviceCode),
  );

  assert.equal(handoff.deviceCode.length >= 43, true);
  assert.match(handoff.userCode, /^[A-HJ-NP-Z2-9]{8}$/);
  assert.ok(stored);
  assert.equal(JSON.stringify(stored).includes(handoff.deviceCode), false);
  assert.equal(JSON.stringify(stored).includes(handoff.userCode), false);
});

test("approval requires authentication and matching organization and device ownership", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const active = await activeSession(value.repository, value.now());
  const authenticate: Authenticator = async (authorization) => {
    if (!authorization) throw new AuthenticationError("Bearer token required");
    return { subjectId: "test-user", service: false };
  };
  let requestedAuthorization:
    Parameters<AccessAuthorizer["authorize"]>[0] | undefined;
  const authorize: AccessAuthorizer = {
    async authorize(input) {
      requestedAuthorization = input;
      return true;
    },
    async registerDevice() {},
  };
  const instance = buildApp({
    repository: value.repository,
    authenticate,
    authorize,
    physicalSessionHandoff: value.service,
  });
  const unauthenticated = await request(instance)
    .post("/v1/development/physical-session-handoffs/approve")
    .send({
      protocolVersion: 1,
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: active.bootstrap.sessionToken,
    });
  assert.equal(unauthenticated.status, 401);
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: active.bootstrap.sessionToken,
      authorizedOrganizationId: "20000000-0000-4000-8000-000000000002",
      authorizedOwnershipVersion: active.device.ownershipVersion,
    }),
  );
  const approved = await request(instance)
    .post("/v1/development/physical-session-handoffs/approve")
    .set("authorization", "Bearer user")
    .send({
      protocolVersion: 1,
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: active.bootstrap.sessionToken,
    });
  assert.equal(approved.status, 204);
  assert.equal(
    requestedAuthorization?.action,
    "device.physical-session-handoff.approve",
  );
  assert.equal(requestedAuthorization?.resourceId, active.device.deviceUuid);
  assert.equal(requestedAuthorization?.organizationId, organizationId);
});

test("wrong device, organization, and ownership-version changes are rejected", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const active = await activeSession(value.repository, value.now());
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: "AG-999999",
      sessionToken: active.bootstrap.sessionToken,
      authorizedOrganizationId: organizationId,
      authorizedOwnershipVersion: active.device.ownershipVersion,
    }),
  );
  await value.repository.transferOwnership(
    active.device.deviceUuid,
    "20000000-0000-4000-8000-000000000002",
    "test-user",
  );
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: active.bootstrap.sessionToken,
      authorizedOrganizationId: organizationId,
      authorizedOwnershipVersion: active.device.ownershipVersion,
    }),
  );
});

test("wrong, expired, consumed, or mismatched sessions fail closed", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const active = await activeSession(value.repository, value.now());
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: "x".repeat(32),
      authorizedOrganizationId: organizationId,
      authorizedOwnershipVersion: active.device.ownershipVersion,
    }),
  );
  await value.repository.consumeBootstrap(
    active.device.deviceId,
    active.bootstrap.sessionToken,
  );
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: active.bootstrap.sessionId,
      deviceId: active.device.deviceId,
      sessionToken: active.bootstrap.sessionToken,
      authorizedOrganizationId: organizationId,
      authorizedOwnershipVersion: active.device.ownershipVersion,
    }),
  );
});

test("approved bundles are AES-GCM ciphertext with a bounded TTL", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const active = await approveActive(value, handoff);
  const stored = await value.store.byDeviceCodeHash(
    (await import("../src/domain.js")).secretDigest(handoff.deviceCode),
  );

  assert.equal(stored?.state, "APPROVED");
  assert.ok(stored?.encryptedBundle?.ciphertext);
  assert.equal(
    JSON.stringify(stored).includes(active.bootstrap.sessionToken),
    false,
  );
  assert.equal(
    new Date(stored!.expiresAt) <= new Date(active.bootstrap.expiresAt),
    true,
  );
});

test("invalid AES-GCM wrapping keys fail closed", () => {
  assert.throws(() => PhysicalSessionCipher.fromBase64Url("not-a-32-byte-key"));
});

test("redeem reports pending before approval and returns the bundle once", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  assert.equal(
    (await value.service.redeem(handoff.deviceCode)).status,
    "PENDING",
  );
  const active = await approveActive(value, handoff);
  const redeemed = await value.service.redeem(handoff.deviceCode);

  assert.equal(redeemed.status, "REDEEMED");
  if (redeemed.status === "REDEEMED") {
    assert.equal(redeemed.sessionId, active.bootstrap.sessionId);
    assert.equal(redeemed.deviceId, active.device.deviceId);
  }
});

test("replay, expiry, duplicate approval, and polling abuse fail closed", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  assert.equal(
    (await value.service.redeem(handoff.deviceCode)).status,
    "PENDING",
  );
  assert.equal(
    (await value.service.redeem(handoff.deviceCode)).status,
    "SLOW_DOWN",
  );
  await approveActive(value, handoff);
  await assert.rejects(
    value.service.approve({
      userCode: handoff.userCode,
      sessionId: "50000000-0000-4000-8000-000000000001",
      deviceId: "AG-000001",
      sessionToken: "x".repeat(32),
      authorizedOrganizationId: organizationId,
      authorizedOwnershipVersion: "1",
    }),
  );
  await value.service.redeem(handoff.deviceCode);
  await assert.rejects(value.service.redeem(handoff.deviceCode));
  const expired = await value.service.start("AG-000002");
  value.advance(6 * 60_000);
  assert.equal(
    (await value.service.redeem(expired.deviceCode)).status,
    "EXPIRED",
  );
});

test("records and safe errors do not expose plaintext handoff or session secrets", async () => {
  const value = fixture();
  const handoff = await value.service.start("AG-000001");
  const stored = await value.store.byDeviceCodeHash(
    (await import("../src/domain.js")).secretDigest(handoff.deviceCode),
  );
  await assert.rejects(value.service.redeem("z".repeat(43)), (error: Error) => {
    assert.equal(error.message.includes(handoff.deviceCode), false);
    assert.equal(error.message.includes(handoff.userCode), false);
    return true;
  });
  assert.equal(JSON.stringify(stored).includes(handoff.deviceCode), false);
  assert.equal(JSON.stringify(stored).includes(handoff.userCode), false);
});
