import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import {
  DevelopmentCredentialProvider,
  MemoryDeviceRepository,
} from "../src/domain.js";

const authenticate: Authenticator = async (authorization) => ({
  subjectId: "owner",
  email: "owner@example.test",
  service: authorization === "Bearer service",
});
const authorize: AccessAuthorizer = {
  async authorize() {
    return true;
  },
  async registerDevice() {},
};

function app() {
  return buildApp({
    repository: new MemoryDeviceRepository(),
    authenticate,
    authorize,
    credentials: new DevelopmentCredentialProvider(true),
  });
}

test("liveness, readiness, and correlation middleware are available", async () => {
  const instance = app();
  const live = await request(instance)
    .get("/health/live")
    .set("x-correlation-id", "test-correlation");
  assert.equal(live.status, 200);
  assert.equal(live.headers["x-correlation-id"], "test-correlation");
  assert.equal((await request(instance).get("/health/ready")).status, 200);
});

test("authorized QR claim and bootstrap flow uses the versioned contracts", async () => {
  const instance = app();
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const created = await request(instance)
    .post("/v1/devices")
    .set("authorization", "Bearer user")
    .send({ organizationId });
  const qr = await request(instance)
    .post(`/v1/devices/${created.body.deviceUuid}/setup`)
    .set("authorization", "Bearer user")
    .send({ expiresInSeconds: 600 });
  assert.equal(qr.body.v, 1);
  const claimed = await request(instance)
    .post("/v1/claims/consume")
    .set("authorization", "Bearer user")
    .send({ organizationId, qr: qr.body });
  assert.equal(claimed.body.device.lifecycle, "CLAIMED");
  assert.equal(
    claimed.body.bootstrap.schema,
    "urn:algaguard:schema:onboarding:bootstrap-session:v1",
  );
  const bootstrapped = await request(instance)
    .post(`/v1/devices/${created.body.deviceId}/bootstrap`)
    .send({ sessionToken: claimed.body.bootstrap.sessionToken });
  assert.equal(bootstrapped.status, 200);
  assert.equal(bootstrapped.body.developmentOnly, true);

  const context = await request(instance)
    .get(`/v1/internal/devices/by-device-id/${created.body.deviceId}/context`)
    .set("authorization", "Bearer service")
    .set("x-correlation-id", "identity-test");
  assert.equal(context.status, 200);
  assert.equal(context.headers["x-correlation-id"], "identity-test");
  assert.equal(context.body.deviceUuid, created.body.deviceUuid);
  assert.equal(context.body.deviceId, created.body.deviceId);
  assert.equal(context.body.organizationId, organizationId);
  assert.equal(context.body.status, "ACTIVE");
  assert.equal(context.body.ownershipVersion, "1");
  const uuidContext = await request(instance)
    .get(`/v1/internal/devices/${created.body.deviceUuid}/context`)
    .set("authorization", "Bearer service");
  assert.equal(uuidContext.status, 200);
  assert.equal(uuidContext.body.deviceId, created.body.deviceId);
  assert.equal(uuidContext.body.deviceUuid, created.body.deviceUuid);

  const transferred = await request(instance)
    .post(`/v1/devices/${created.body.deviceUuid}/ownership-transfer`)
    .set("authorization", "Bearer user")
    .send({ organizationId: "20000000-0000-4000-8000-000000000002" });
  assert.equal(transferred.status, 200);
  assert.equal(transferred.body.previousOrganizationId, organizationId);
  assert.equal(transferred.body.device.ownershipVersion, "2");
  const updatedContext = await request(instance)
    .get(`/v1/internal/devices/by-device-id/${created.body.deviceId}/context`)
    .set("authorization", "Bearer service");
  assert.equal(
    updatedContext.body.organizationId,
    "20000000-0000-4000-8000-000000000002",
  );
  assert.equal(updatedContext.body.ownershipVersion, "2");
});

test("setup authorizes the owning organization before an unclaimed device has active context", async () => {
  const decisions: Array<{
    subjectId: string;
    action: string;
    resourceType: "organization" | "device";
    resourceId: string;
    correlationId?: string;
  }> = [];
  const instance = buildApp({
    repository: new MemoryDeviceRepository(),
    authenticate,
    authorize: {
      async authorize(input) {
        decisions.push(input);
        return true;
      },
      async registerDevice() {},
    },
    credentials: new DevelopmentCredentialProvider(true),
  });
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const created = await request(instance)
    .post("/v1/devices")
    .set("authorization", "Bearer user")
    .send({ organizationId });

  const setup = await request(instance)
    .post(`/v1/devices/${created.body.deviceUuid}/setup`)
    .set("authorization", "Bearer user")
    .send({ expiresInSeconds: 600 });

  assert.equal(setup.status, 201);
  const { correlationId: _correlationId, ...decision } = decisions.at(-1)!;
  assert.deepEqual(decision, {
    subjectId: "owner",
    action: "device.manage",
    resourceType: "organization",
    resourceId: organizationId,
  });
});

test("internal context rejects user tokens, unknown devices, and unclaimed devices", async () => {
  const instance = app();
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const created = await request(instance)
    .post("/v1/devices")
    .set("authorization", "Bearer user")
    .send({ organizationId });
  const user = await request(instance)
    .get(`/v1/internal/devices/by-device-id/${created.body.deviceId}/context`)
    .set("authorization", "Bearer user");
  assert.equal(user.status, 403);
  const unclaimed = await request(instance)
    .get(`/v1/internal/devices/by-device-id/${created.body.deviceId}/context`)
    .set("authorization", "Bearer service");
  assert.equal(unclaimed.status, 409);
  assert.equal(unclaimed.body.code, "DEVICE_UNCLAIMED");
  const unknown = await request(instance)
    .get("/v1/internal/devices/by-device-id/AG-999999/context")
    .set("authorization", "Bearer service");
  assert.equal(unknown.status, 404);
  const unknownUuid = await request(instance)
    .get("/v1/internal/devices/30000000-0000-4000-8000-000000000003/context")
    .set("authorization", "Bearer service");
  assert.equal(unknownUuid.status, 404);
});

test("unknown routes use problem details", async () => {
  const response = await request(app()).get("/missing");
  assert.equal(response.status, 404);
  assert.match(
    response.headers["content-type"] ?? "",
    /application\/problem\+json/,
  );
});
