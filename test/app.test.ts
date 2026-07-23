import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import {
  DevelopmentCredentialProvider,
  MemoryDeviceRepository,
} from "../src/domain.js";

const authenticate: Authenticator = async () => ({
  subjectId: "owner",
  email: "owner@example.test",
  service: false,
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
    .post(`/v1/devices/${created.body.deviceId}/setup`)
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
});

test("unknown routes use problem details", async () => {
  const response = await request(app()).get("/missing");
  assert.equal(response.status, 404);
  assert.match(
    response.headers["content-type"] ?? "",
    /application\/problem\+json/,
  );
});
