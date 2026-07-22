import test from "node:test";
import assert from "node:assert/strict";
import { ClaimStore, DevelopmentCredentialProvider } from "../src/domain.js";
test("claim is one-time and QR contains no Wi-Fi or permanent credential", () => {
  const store = new ClaimStore();
  const payload = store.create(
    "device",
    "https://api.example/bootstrap",
    "development",
    1000,
  );
  assert.equal(store.consume(payload.claimCode, Date.now()), "device");
  assert.equal(store.consume(payload.claimCode, Date.now()), undefined);
  assert.doesNotMatch(
    JSON.stringify(payload),
    /wifi|password|privateKey|mqttPassword/i,
  );
});
test("expired claim is rejected", () => {
  const store = new ClaimStore();
  const payload = store.create(
    "device",
    "https://api.example/bootstrap",
    "development",
    1,
  );
  assert.equal(store.consume(payload.claimCode, Date.now() + 2), undefined);
});
test("development credential provider is disabled by default", async () => {
  await assert.rejects(
    new DevelopmentCredentialProvider(false).issue("device"),
  );
});
