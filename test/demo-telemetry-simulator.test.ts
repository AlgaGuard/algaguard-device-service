import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import {
  createDemoBatch,
  DEMO_SOURCE,
  DemoSampleBuffer,
  DemoTelemetryGenerator,
} from "../src/demo-telemetry-simulator.js";

const base = {
  NODE_ENV: "test",
  DATABASE_URL: "postgresql://localhost/test",
  REDIS_URL: "redis://localhost:6379",
};
const context = {
  deviceUuid: "10000000-0000-4000-8000-000000000001",
  deviceId: "AG-000001",
  organizationId: "20000000-0000-4000-8000-000000000001",
  ownershipVersion: "1",
};

test("demo simulator is disabled by default", () => {
  assert.equal(loadConfig(base).ALGAGUARD_ENABLE_DEMO_TELEMETRY_SIMULATOR, "0");
});

test("demo simulator is rejected outside development and test", () => {
  assert.throws(() =>
    loadConfig({
      ...base,
      NODE_ENV: "production",
      ALGAGUARD_ENABLE_DEMO_TELEMETRY_SIMULATOR: "1",
      TELEMETRY_SERVICE_URL: "http://telemetry-service:3000",
      KEYCLOAK_TOKEN_URL: "http://keycloak/token",
      SERVICE_CLIENT_ID: "service",
      SERVICE_CLIENT_SECRET: "synthetic-test-secret",
    }),
  );
});

test("enabled simulator requires its private service boundary configuration", () => {
  assert.throws(() =>
    loadConfig({ ...base, ALGAGUARD_ENABLE_DEMO_TELEMETRY_SIMULATOR: "1" }),
  );
});

test("deterministic generator produces identical samples for identical input", () => {
  const time = new Date("2026-07-30T00:00:01.000Z");
  const start = new Date("2026-07-30T00:00:00.000Z");
  assert.deepEqual(
    new DemoTelemetryGenerator(7).sample(42n, time, start),
    new DemoTelemetryGenerator(7).sample(42n, time, start),
  );
});

test("all six presentation values remain bounded and non-negative", () => {
  const generator = new DemoTelemetryGenerator();
  for (let index = 1n; index <= 1000n; index++) {
    const sample = generator.sample(
      index,
      new Date(1_000_000 + Number(index) * 1000),
      new Date(1_000_000),
    );
    assert.ok(
      sample.values.temperatureC >= 20 && sample.values.temperatureC <= 28,
    );
    assert.ok(sample.values.ph >= 0 && sample.values.ph <= 14);
    assert.ok(sample.values.lightLux >= 0);
    assert.ok(sample.values.nitrateMgL >= 0);
    assert.ok(sample.values.phosphateMgL >= 0);
    assert.ok(sample.values.potassiumMgL >= 0);
  }
});

test("every sample carries explicit simulated demo metadata", () => {
  const sample = new DemoTelemetryGenerator().sample(
    1n,
    new Date(1000),
    new Date(0),
  );
  assert.deepEqual(sample.qualityFlags, ["SIMULATED"]);
  assert.equal(sample.extensions["algaguard.demo.source"], DEMO_SOURCE);
  assert.equal(
    sample.extensions["algaguard.demo.generated-at"],
    sample.observedAt,
  );
  assert.equal(sample.extensions["algaguard.demo.profile-version"], "1.0.0");
});

test("buffer persists only each complete five-second group", () => {
  const buffer = new DemoSampleBuffer();
  const generator = new DemoTelemetryGenerator();
  for (let index = 1n; index < 5n; index++)
    assert.equal(
      buffer.add(
        generator.sample(index, new Date(Number(index) * 1000), new Date(0)),
      ),
      true,
    );
  assert.equal(buffer.ready(), false);
  buffer.add(generator.sample(5n, new Date(5000), new Date(0)));
  assert.equal(buffer.ready(), true);
  assert.equal(buffer.take().length, 5);
  assert.equal(buffer.size, 0);
});

test("buffer is bounded and clear is idempotent", () => {
  const buffer = new DemoSampleBuffer();
  const generator = new DemoTelemetryGenerator();
  for (let index = 1n; index <= 5n; index++)
    buffer.add(
      generator.sample(index, new Date(Number(index) * 1000), new Date(0)),
    );
  assert.equal(
    buffer.add(generator.sample(6n, new Date(6000), new Date(0))),
    false,
  );
  buffer.clear();
  buffer.clear();
  assert.equal(buffer.size, 0);
});

test("batch uses the existing ingestion shape without ownership mutation fields", () => {
  const sample = new DemoTelemetryGenerator().sample(
    1n,
    new Date(1000),
    new Date(0),
  );
  const batch = createDemoBatch(context, [sample]);
  assert.equal(batch.deviceUuid, context.deviceUuid);
  assert.equal(batch.organizationId, context.organizationId);
  assert.equal(batch.ownershipVersion, context.ownershipVersion);
  assert.equal("owner" in batch, false);
  assert.equal("mqttCredentials" in batch, false);
});

test("empty and oversized batches are rejected", () => {
  assert.throws(() => createDemoBatch(context, []));
  const sample = new DemoTelemetryGenerator().sample(
    1n,
    new Date(1000),
    new Date(0),
  );
  assert.throws(() => createDemoBatch(context, Array(121).fill(sample)));
});
