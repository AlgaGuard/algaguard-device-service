import assert from "node:assert/strict";
import test from "node:test";
import request from "supertest";
import { buildApp } from "../src/app.js";
import type { AccessAuthorizer, Authenticator } from "../src/auth.js";
import { createStaticBrokerAuthenticator } from "../src/credential-service.js";
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

function app(repository = new MemoryDeviceRepository()) {
  return buildApp({
    repository,
    authenticate,
    authorize,
    credentials: new DevelopmentCredentialProvider(true),
    authenticateBroker: createStaticBrokerAuthenticator("broker-secret"),
  });
}

async function createDevice(instance: ReturnType<typeof app>) {
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const created = await request(instance)
    .post("/v1/devices")
    .set("authorization", "Bearer user")
    .send({ organizationId });
  return created.body as { deviceUuid: string; deviceId: string };
}

test("the broker's static token can update device status, and it surfaces as a flat online flag", async () => {
  const instance = app();
  const device = await createDevice(instance);

  const update = await request(instance)
    .put(`/v1/internal/devices/${device.deviceId}/status`)
    .set("authorization", "Bearer broker-secret")
    .send({
      observedAt: new Date().toISOString(),
      status: { online: true },
    });
  assert.equal(update.status, 204);

  const fetched = await request(instance)
    .get(`/v1/devices/${device.deviceUuid}`)
    .set("authorization", "Bearer user");
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.online, true);
  assert.deepEqual(fetched.body.status, { online: true });
});

test("a device with no status update at all is reported offline, not crashing", async () => {
  const instance = app();
  const device = await createDevice(instance);

  const fetched = await request(instance)
    .get(`/v1/devices/${device.deviceUuid}`)
    .set("authorization", "Bearer user");
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.online, false);
  assert.equal(fetched.body.status, null);
});

test("an invalid broker token falls back to the OIDC service-token check rather than being silently trusted", async () => {
  const instance = app();
  const device = await createDevice(instance);

  const wrongBrokerToken = await request(instance)
    .put(`/v1/internal/devices/${device.deviceId}/status`)
    .set("authorization", "Bearer not-the-broker-secret")
    .send({ observedAt: new Date().toISOString(), status: { online: true } });
  assert.equal(wrongBrokerToken.status, 403);

  const validServiceToken = await request(instance)
    .put(`/v1/internal/devices/${device.deviceId}/status`)
    .set("authorization", "Bearer service")
    .send({ observedAt: new Date().toISOString(), status: { online: true } });
  assert.equal(validServiceToken.status, 204);
});
