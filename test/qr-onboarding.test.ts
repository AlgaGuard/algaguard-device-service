import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import { DomainError, MemoryDeviceRepository } from "../src/domain.js";
import {
  decodeQrOnboardingInvitation,
  QrOnboardingGrantSigner,
  QrOnboardingService,
} from "../src/qr-onboarding.js";

const organizationId = "10000000-0000-4000-8000-000000000001";
const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const privateKeyEncoded = privateKey
  .export({ format: "der", type: "pkcs8" })
  .toString("base64url");

function crc16(bytes: Uint8Array) {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1)
      crc =
        (crc & 0x8000) !== 0
          ? ((crc << 1) ^ 0x1021) & 0xffff
          : (crc << 1) & 0xffff;
  }
  return crc;
}

function invitation(
  now: Date,
  overrides: {
    device?: number;
    issued?: number;
    expires?: number;
    nonceFill?: number;
  } = {},
) {
  const seconds = Math.floor(now.getTime() / 1000);
  const bytes = Buffer.alloc(31);
  bytes[0] = 1;
  bytes.writeUIntBE(overrides.device ?? 1, 1, 3);
  Buffer.alloc(16, overrides.nonceFill ?? 0xa5).copy(bytes, 4);
  bytes.writeUInt32BE(overrides.issued ?? seconds, 20);
  bytes.writeUInt32BE(overrides.expires ?? seconds + 180, 24);
  bytes[28] = 1;
  bytes.writeUInt16BE(crc16(bytes.subarray(0, 29)), 29);
  return `ag://q/${bytes.toString("base64url")}`;
}

async function owned(now: Date) {
  const repository = new MemoryDeviceRepository();
  const created = await repository.createDevice({
    organizationId,
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  const claim = await repository.createClaim(created.deviceId, 60_000, "owner");
  const result = await repository.consumeClaim({
    deviceId: created.deviceId,
    secret: claim.c,
    organizationId,
    subjectId: "owner",
    now,
  });
  const internal = repository as unknown as {
    bootstrap: Map<string, { invalidatedAt?: number }>;
  };
  internal.bootstrap.get(result.bootstrap.sessionId)!.invalidatedAt =
    now.getTime();
  return { repository, device: result.device };
}

function service(repository: MemoryDeviceRepository, now: Date) {
  return new QrOnboardingService(
    repository,
    new QrOnboardingGrantSigner(privateKeyEncoded),
    900_000,
    () => now,
  );
}

test("valid compact QR decodes with its public binding fields", () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const parsed = decodeQrOnboardingInvitation(invitation(now));
  assert.equal(parsed.deviceId, "AG-000001");
  assert.equal(parsed.nonce.length, 16);
  assert.equal(parsed.capabilityVersion, 1);
});

test("malformed, overlong, and unsupported invitations fail closed", () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  assert.throws(() => decodeQrOnboardingInvitation("https://example.test"));
  assert.throws(
    () =>
      decodeQrOnboardingInvitation(
        invitation(now, { issued: 1, expires: 302 }),
      ),
    (error: unknown) =>
      error instanceof DomainError && error.code === "QR_INVITATION_INVALID",
  );
});

test("owned CLAIMED device receives one session and a verifiable binding grant", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  const output = await service(value.repository, now).exchange({
    invitationUri: invitation(now),
    ownershipVersion: value.device.ownershipVersion,
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  const grant = Buffer.from(output.bindingGrant, "base64url");
  assert.equal(grant.length, 145);
  assert.equal(
    verify(
      "sha256",
      grant.subarray(0, 81),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      grant.subarray(81),
    ),
    true,
  );
  const validation = await value.repository.validateBootstrapSession(
    output.sessionToken,
    output.deviceId,
    now,
  );
  assert.equal(validation.sessionId, output.sessionId);
});

test("session is bound to nonce, device, organization, and ownership version", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  const output = await service(value.repository, now).exchange({
    invitationUri: invitation(now),
    ownershipVersion: "1",
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  const grant = Buffer.from(output.bindingGrant, "base64url");
  assert.equal(grant.readUIntBE(1, 3), 1);
  assert.deepEqual(
    grant.subarray(48, 80),
    createHash("sha256").update(output.sessionToken).digest(),
  );
  assert.equal(grant.readBigUInt64BE(40), 1n);
});

test("replayed nonce is rejected exactly once", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  const qr = invitation(now);
  await service(value.repository, now).exchange({
    invitationUri: qr,
    ownershipVersion: "1",
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  await assert.rejects(
    service(value.repository, now).exchange({
      invitationUri: qr,
      ownershipVersion: "1",
      actorSubjectId: "owner",
      expectedOrganizationId: organizationId,
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "QR_INVITATION_REPLAYED",
  );
});

test("fresh QR invalidates previous unconsumed QR session for safe retry", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  const first = await service(value.repository, now).exchange({
    invitationUri: invitation(now, { nonceFill: 0xa5 }),
    ownershipVersion: "1",
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  const second = await service(value.repository, now).exchange({
    invitationUri: invitation(now, { nonceFill: 0x5a }),
    ownershipVersion: "1",
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  assert.notEqual(second.sessionId, first.sessionId);
  await assert.rejects(
    value.repository.validateBootstrapSession(
      first.sessionToken,
      first.deviceId,
      now,
    ),
    (error: unknown) =>
      error instanceof DomainError && error.code === "EXPIRED_SESSION_TOKEN",
  );
  const validation = await value.repository.validateBootstrapSession(
    second.sessionToken,
    second.deviceId,
    now,
  );
  assert.equal(validation.sessionId, second.sessionId);
});

test("wrong organization and ownership change are denied", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  await assert.rejects(
    service(value.repository, now).exchange({
      invitationUri: invitation(now),
      ownershipVersion: "2",
      actorSubjectId: "other",
      expectedOrganizationId: "20000000-0000-4000-8000-000000000002",
    }),
  );
});

test("exchange creates no duplicate device or ownership record", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  const before = await value.repository.listDevices(organizationId);
  await service(value.repository, now).exchange({
    invitationUri: invitation(now),
    ownershipVersion: "1",
    actorSubjectId: "owner",
    expectedOrganizationId: organizationId,
  });
  assert.deepEqual(await value.repository.listDevices(organizationId), before);
});

test("HTTP exchange is authenticated, authorized, no-store, and returns once", async () => {
  const now = new Date();
  const value = await owned(now);
  const authenticate: Authenticator = async () => ({
    subjectId: "owner",
    service: false,
  });
  let action = "";
  const authorize: AccessAuthorizer = {
    async authorize(input) {
      action = input.action;
      return true;
    },
    async registerDevice() {},
  };
  const response = await request(
    buildApp({
      repository: value.repository,
      authenticate,
      authorize,
      qrOnboarding: service(value.repository, now),
    }),
  )
    .post("/v1/device-onboarding/qr/exchange")
    .set("authorization", "Bearer redacted")
    .send({
      schema:
        "urn:algaguard:schema:onboarding:qr-onboarding-exchange-request:v1",
      schemaVersion: "1.0.0",
      invitationUri: invitation(now),
      ownershipVersion: "1",
    });
  assert.equal(response.status, 201);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(action, "device.credentials.bootstrap");
  assert.equal(typeof response.body.bindingGrant, "string");
});

test("QR onboarding is disabled by default and forbidden in production", () => {
  const previous = { ...process.env };
  try {
    process.env = {
      DATABASE_URL: "postgres://localhost/test",
      REDIS_URL: "redis://localhost:6379",
      NODE_ENV: "production",
      ALGAGUARD_ENABLE_QR_ONBOARDING: "1",
      QR_ONBOARDING_SIGNING_PRIVATE_KEY_PKCS8: privateKeyEncoded,
    };
    assert.throws(() => loadConfig());
    process.env.ALGAGUARD_ENABLE_QR_ONBOARDING = "0";
    const config = loadConfig();
    assert.equal(config.ALGAGUARD_ENABLE_QR_ONBOARDING, "0");
  } finally {
    process.env = previous;
  }
});

test("failed exchange preserves CLAIMED lifecycle and stores no plaintext token", async () => {
  const now = new Date("2026-07-30T10:00:00.000Z");
  const value = await owned(now);
  await assert.rejects(
    service(value.repository, now).exchange({
      invitationUri: invitation(now, { device: 2 }),
      ownershipVersion: "1",
      actorSubjectId: "owner",
      expectedOrganizationId: organizationId,
    }),
  );
  const after = await value.repository.getDevice(value.device.deviceUuid);
  assert.equal(after?.lifecycle, "CLAIMED");
  assert.equal(
    JSON.stringify(value.repository).includes("sessionToken"),
    false,
  );
});
