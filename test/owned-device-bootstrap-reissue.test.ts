import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import {
  classifyPreparationRecord,
  CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
  DomainError,
  mayResolveEmptyPreparationRecord,
  MemoryDeviceRepository,
} from "../src/domain.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js").default;
const addFormats = require("ajv-formats").default;

const contractRoot = path.resolve(
  process.env.CONTRACTS_DIR ?? "../algaguard-contracts",
);
const bootstrapSessionSchema = JSON.parse(
  fs.readFileSync(
    path.join(
      contractRoot,
      "schemas/onboarding/bootstrap-session-v1.schema.json",
    ),
    "utf8",
  ),
) as Record<string, unknown>;
const deviceReferenceSchema = JSON.parse(
  fs.readFileSync(
    path.join(contractRoot, "schemas/common/device-reference-v1.schema.json"),
    "utf8",
  ),
) as Record<string, unknown>;

function bootstrapSessionValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  ajv.addSchema(deviceReferenceSchema);
  return ajv.compile(bootstrapSessionSchema);
}

const organizationId = "10000000-0000-4000-8000-000000000001";
const authenticate: Authenticator = async () => ({
  subjectId: "owner",
  service: false,
});
const allow: AccessAuthorizer = {
  async authorize() {
    return true;
  },
  async registerDevice() {},
};

async function claimed(repository = new MemoryDeviceRepository()) {
  const device = await repository.createDevice({
    organizationId,
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  const claim = await repository.createClaim(device.deviceId, 600_000, "owner");
  const result = await repository.consumeClaim({
    deviceId: device.deviceId,
    secret: claim.c,
    organizationId,
    subjectId: "owner",
  });
  return { repository, device: result.device, original: result.bootstrap };
}

function app(repository: MemoryDeviceRepository, authorize = allow) {
  return buildApp({
    repository,
    authenticate,
    authorize,
    ownedDeviceBootstrapReissueEnabled: true,
  });
}

test("1 current owner can reissue one bootstrap session", async () => {
  const value = await claimed();
  let requestedAction: string | undefined;
  const authorize: AccessAuthorizer = {
    async authorize(input) {
      requestedAction = input.action;
      return true;
    },
    async registerDevice() {},
  };
  const internal = value.repository as unknown as {
    bootstrap: Map<string, { invalidatedAt?: number }>;
  };
  internal.bootstrap.get(value.original.sessionId)!.invalidatedAt = Date.now();
  const response = await request(app(value.repository, authorize))
    .post(`/v1/devices/${value.device.deviceUuid}/bootstrap-sessions/reissue`)
    .set("authorization", "Bearer user")
    .send({
      schema:
        "urn:algaguard:schema:onboarding:owned-device-bootstrap-reissue-request:v1",
      schemaVersion: "1.0.0",
      ownershipVersion: value.device.ownershipVersion,
      expiresInSeconds: 300,
    });
  assert.equal(response.status, 201);
  assert.equal(requestedAction, "device.bootstrap.reissue");
  assert.equal(response.headers["cache-control"], "no-store");
  assert.notEqual(response.body.sessionId, value.original.sessionId);
  assert.equal(response.body.schemaVersion, "1.0.0");
  assert.equal(
    response.body.serviceUuid,
    CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
  );
  assert.equal(bootstrapSessionValidator()(response.body), true);
});

test("reissue response is mobile-compatible and rejects the previous UUID", async () => {
  const value = await claimed();
  const session = await value.repository.reissueBootstrapSession({
    deviceUuid: value.device.deviceUuid,
    organizationId,
    ownershipVersion: value.device.ownershipVersion,
    actorSubjectId: "owner",
    ttlMs: 300_000,
    now: new Date(Date.now() + 301_000),
  });
  const validate = bootstrapSessionValidator();
  assert.equal(validate(session), true, JSON.stringify(validate.errors));
  assert.equal(
    validate({
      ...session,
      serviceUuid: "a19a0001-7e4d-4b1a-9c2d-000000000001",
    }),
    false,
  );
});

test("2 reissue creates no device or ownership row", async () => {
  const value = await claimed();
  const before = await value.repository.listDevices(organizationId);
  await value.repository.reissueBootstrapSession({
    deviceUuid: value.device.deviceUuid,
    organizationId,
    ownershipVersion: "1",
    actorSubjectId: "owner",
    ttlMs: 300_000,
    now: new Date(Date.now() + 301_000),
  });
  assert.deepEqual(await value.repository.listDevices(organizationId), before);
});

test("3 owner and ownershipVersion remain unchanged", async () => {
  const value = await claimed();
  const before = await value.repository.getDevice(value.device.deviceUuid);
  await value.repository.reissueBootstrapSession({
    deviceUuid: value.device.deviceUuid,
    organizationId,
    ownershipVersion: "1",
    actorSubjectId: "owner",
    ttlMs: 300_000,
    now: new Date(Date.now() + 301_000),
  });
  const after = await value.repository.getDevice(value.device.deviceUuid);
  assert.equal(after?.organizationId, before?.organizationId);
  assert.equal(after?.ownershipVersion, before?.ownershipVersion);
});

test("4 expired session is invalidated rather than reused", async () => {
  const value = await claimed();
  const reissued = await value.repository.reissueBootstrapSession({
    deviceUuid: value.device.deviceUuid,
    organizationId,
    ownershipVersion: "1",
    actorSubjectId: "owner",
    ttlMs: 300_000,
    now: new Date(Date.now() + 301_000),
  });
  assert.notEqual(reissued.sessionId, value.original.sessionId);
  await assert.rejects(
    value.repository.validateBootstrapSession(
      value.original.sessionToken,
      value.device.deviceId,
      new Date(Date.now() + 301_000),
    ),
  );
});

test("5 a second request while a session is active is rejected", async () => {
  const value = await claimed();
  await assert.rejects(
    value.repository.reissueBootstrapSession({
      deviceUuid: value.device.deviceUuid,
      organizationId,
      ownershipVersion: "1",
      actorSubjectId: "owner",
      ttlMs: 300_000,
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "ACTIVE_BOOTSTRAP_SESSION_EXISTS",
  );
});

test("6 another organization is denied", async () => {
  const value = await claimed();
  await assert.rejects(
    value.repository.reissueBootstrapSession({
      deviceUuid: value.device.deviceUuid,
      organizationId: "20000000-0000-4000-8000-000000000002",
      ownershipVersion: "1",
      actorSubjectId: "other",
      ttlMs: 300_000,
      now: new Date(Date.now() + 301_000),
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "CROSS_ORGANIZATION_DENIED",
  );
});

test("7 unknown, wrong-lifecycle, wrong-version, and production use fail closed", async () => {
  const repository = new MemoryDeviceRepository();
  const unclaimed = await repository.createDevice({
    organizationId,
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  for (const input of [
    { deviceUuid: randomUUID(), ownershipVersion: "1" },
    { deviceUuid: unclaimed.deviceUuid, ownershipVersion: "1" },
    { deviceUuid: unclaimed.deviceUuid, ownershipVersion: "2" },
  ])
    await assert.rejects(
      repository.reissueBootstrapSession({
        ...input,
        organizationId,
        actorSubjectId: "owner",
        ttlMs: 300_000,
      }),
    );
  assert.throws(() =>
    loadConfig({
      NODE_ENV: "production",
      DATABASE_URL: "postgres://safe.invalid/db",
      REDIS_URL: "redis://safe.invalid:6379",
      ALGAGUARD_ENABLE_OWNED_DEVICE_BOOTSTRAP_REISSUE: "1",
    }),
  );
});

test("8 token is high entropy, hash-only at rest, TTL-bound, and no-store", async () => {
  const value = await claimed();
  const now = new Date(Date.now() + 301_000);
  const session = await value.repository.reissueBootstrapSession({
    deviceUuid: value.device.deviceUuid,
    organizationId,
    ownershipVersion: "1",
    actorSubjectId: "owner",
    ttlMs: 300_000,
    now,
  });
  assert.match(session.sessionToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Date.parse(session.expiresAt) - now.getTime(), 300_000);
  const internal = value.repository as unknown as {
    bootstrap: Map<string, { tokenHash: string }>;
  };
  const stored = internal.bootstrap.get(session.sessionId)!;
  assert.match(stored.tokenHash, /^[0-9a-f]{64}$/);
  assert.notEqual(stored.tokenHash, session.sessionToken);
  assert.equal(
    JSON.stringify(stored).includes(session.sessionToken),
    false,
    "the plaintext token must not exist in repository state",
  );
});

test("9 preparation cleanup refuses every owned or referenced record", () => {
  for (const audit of [
    {
      organizationOwned: true,
      ownershipVersionPresent: true,
      dependencyCount: 0,
      canonicalConflict: false,
      identityConflict: false,
    },
    {
      organizationOwned: false,
      ownershipVersionPresent: false,
      dependencyCount: 1,
      canonicalConflict: false,
      identityConflict: false,
    },
  ]) {
    assert.equal(
      classifyPreparationRecord(audit),
      "OWNED_OR_REFERENCED_LEGITIMATE_RECORD",
    );
    assert.equal(mayResolveEmptyPreparationRecord(audit), false);
  }
});

test("10 only an exact empty unowned preparation record is resolvable", () => {
  const empty = {
    organizationOwned: false,
    ownershipVersionPresent: false,
    dependencyCount: 0,
    canonicalConflict: false,
    identityConflict: false,
  };
  assert.equal(
    classifyPreparationRecord(empty),
    "EMPTY_UNOWNED_PREPARATION_RECORD",
  );
  assert.equal(mayResolveEmptyPreparationRecord(empty), true);
  assert.equal(
    classifyPreparationRecord({ ...empty, canonicalConflict: true }),
    "DUPLICATE_OR_CONFLICTING_RECORD",
  );
});

test("reissue transaction and logs preserve rollback and secret redaction", () => {
  const repositorySource = fs.readFileSync("src/repository.ts", "utf8");
  const appSource = fs.readFileSync("src/app.ts", "utf8");
  const method = repositorySource.slice(
    repositorySource.indexOf("async reissueBootstrapSession"),
    repositorySource.indexOf(
      "async consumeBootstrap",
      repositorySource.indexOf("async reissueBootstrapSession"),
    ),
  );
  assert.match(method, /await client\.query\("BEGIN"\)/);
  assert.match(method, /await client\.query\("COMMIT"\)/);
  assert.match(method, /await client\.query\("ROLLBACK"\)/);
  assert.match(appSource, /"sessionToken"/);
  assert.doesNotMatch(method, /logger\.|console\.|sessionToken\s*:/);
});
