import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import { buildApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import {
  DEFAULT_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS,
  DEVELOPMENT_ONBOARDING_CLOCK_SKEW_SECONDS,
  developmentOnboardingWindowMs,
} from "../src/development-onboarding-policy.js";
import { MemoryDeviceRepository } from "../src/domain.js";
import {
  MemoryPhysicalSessionHandoffStore,
  PhysicalSessionCipher,
  PhysicalSessionHandoffService,
} from "../src/physical-session-handoff.js";

const database = "postgres://safe.invalid/db";
const redis = "redis://safe.invalid:6379";
const organizationId = "10000000-0000-4000-8000-000000000001";
const authenticate: Authenticator = async () => ({
  subjectId: "owner",
  service: false,
});
const authorize: AccessAuthorizer = {
  async authorize() {
    return true;
  },
  async registerDevice() {},
};

test("development timing is bounded and production rejects the override", () => {
  assert.equal(DEFAULT_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS, 900);
  assert.equal(DEVELOPMENT_ONBOARDING_CLOCK_SKEW_SECONDS, 15);
  assert.equal(developmentOnboardingWindowMs(), 900_000);
  assert.throws(() =>
    loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: database,
      REDIS_URL: redis,
      ALGAGUARD_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS: "900",
    }),
  );
  assert.equal(
    loadConfig({
      NODE_ENV: "development",
      DATABASE_URL: database,
      REDIS_URL: redis,
      ALGAGUARD_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS: "900",
    }).ALGAGUARD_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS,
    900,
  );
});

test("v2 reissue returns server expiry without changing lifecycle or ownership", async () => {
  const repository = new MemoryDeviceRepository();
  const created = await repository.createDevice({
    organizationId,
    hardwareModel: "test-device",
  });
  const claim = await repository.createClaim(created.deviceId, 60_000, "owner");
  const claimed = await repository.consumeClaim({
    deviceId: created.deviceId,
    secret: claim.c,
    organizationId,
    subjectId: "owner",
  });
  const internal = repository as unknown as {
    bootstrap: Map<string, { invalidatedAt?: number }>;
  };
  internal.bootstrap.get(claimed.bootstrap.sessionId)!.invalidatedAt =
    Date.now();
  const before = await repository.getDevice(created.deviceUuid);
  const response = await request(
    buildApp({
      repository,
      authenticate,
      authorize,
      ownedDeviceBootstrapReissueEnabled: true,
      developmentOnboardingWindowMs: 900_000,
    }),
  )
    .post(`/v1/devices/${created.deviceUuid}/bootstrap-sessions/reissue`)
    .set("authorization", "Bearer synthetic")
    .send({
      schema:
        "urn:algaguard:schema:onboarding:owned-device-bootstrap-reissue-request:v2",
      schemaVersion: "2.0.0",
      ownershipVersion: created.ownershipVersion,
    });
  assert.equal(response.status, 201);
  assert.equal(
    Date.parse(response.body.expiresAt) - Date.parse(response.body.createdAt),
    900_000,
  );
  const after = await repository.getDevice(created.deviceUuid);
  assert.equal(after?.lifecycle, before?.lifecycle);
  assert.equal(after?.organizationId, before?.organizationId);
  assert.equal(after?.ownershipVersion, before?.ownershipVersion);
});

test("handoff uses the same window and expiry plus replay fail closed", async () => {
  let now = new Date("2030-01-01T00:00:00Z");
  const service = new PhysicalSessionHandoffService(
    new MemoryDeviceRepository(),
    new MemoryPhysicalSessionHandoffStore(),
    new PhysicalSessionCipher(Buffer.alloc(32, 3)),
    () => now,
    900_000,
  );
  const handoff = await service.start("AG-000001");
  assert.equal(Date.parse(handoff.expiresAt) - now.getTime(), 900_000);
  now = new Date(now.getTime() + 900_001);
  assert.equal((await service.redeem(handoff.deviceCode)).status, "EXPIRED");
  await assert.rejects(service.redeem(handoff.deviceCode));
});
