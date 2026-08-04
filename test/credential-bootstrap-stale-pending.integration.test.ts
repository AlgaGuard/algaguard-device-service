import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { PostgresCredentialStore } from "../src/credential-store.js";
import { PostgresDeviceRepository } from "../src/repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

// A PENDING device_credentials row with no time bound at all would permanently
// block re-onboarding a device whose issuance never completed (e.g. it
// received Wi-Fi credentials over BLE but could never reach the cloud to
// finish CSR submission) -- with no recovery path except manual DB surgery.
// This locks in that a stale PENDING credential is treated as abandoned once
// its bootstrap token's own TTL has elapsed, while a still-fresh one keeps
// blocking a concurrent createBootstrap call as before.
test(
  "createBootstrap recovers from a stale PENDING credential but not a fresh one",
  { skip: !databaseUrl },
  async () => {
    const cleanup = new pg.Pool({ connectionString: databaseUrl });
    await cleanup.query(
      `TRUNCATE credential_audit, credential_rotations, device_credentials,
        credential_bootstrap_sessions, device_ownership_history,
        device_health_projection, device_status_projection, device_transitions,
        claim_failures, bootstrap_sessions, device_claims, devices
       RESTART IDENTITY CASCADE`,
    );
    await cleanup.query("ALTER SEQUENCE device_number_sequence RESTART WITH 1");
    await cleanup.end();

    const pool = new pg.Pool({ connectionString: databaseUrl });
    const devices = new PostgresDeviceRepository(pool);
    const store = new PostgresCredentialStore(pool);
    const organizationId = "10000000-0000-4000-8000-000000000001";
    const created = await devices.createDevice({
      organizationId,
      hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
    });
    const claim = await devices.createClaim(created.deviceId, 60_000, "owner");
    await devices.consumeClaim({
      deviceId: created.deviceId,
      secret: claim.c,
      organizationId,
      subjectId: "owner",
    });

    const ttlMs = 60_000;
    const firstBootstrap = await store.createBootstrap({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      createdBy: "owner",
      ttlMs,
      attempts: 5,
      now: new Date("2026-07-24T00:00:00Z"),
    });
    // Issuance starts (PENDING) but never completes -- the abandoned attempt
    // this guards against.
    await store.reserveInitialIssuance({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      tokenHash: firstBootstrap.record.tokenHash,
      idempotencyKey: randomUUID(),
      csrFingerprintSha256: "a".repeat(64),
      now: new Date("2026-07-24T00:00:01Z"),
    });

    // Still within the bootstrap token's own TTL: a concurrent retry must
    // not race the (possibly still in-flight) existing attempt.
    await assert.rejects(
      store.createBootstrap({
        deviceUuid: created.deviceUuid,
        deviceId: created.deviceId,
        createdBy: "owner",
        ttlMs,
        attempts: 5,
        now: new Date("2026-07-24T00:00:30Z"),
      }),
      /already has an initial credential/,
    );

    // Well past the TTL: the token this PENDING row was created under is
    // long expired, so nothing can still legitimately be using it. A retry
    // must succeed, and the stale row must be marked FAILED, not silently
    // left PENDING forever.
    const recovered = await store.createBootstrap({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      createdBy: "owner",
      ttlMs,
      attempts: 5,
      now: new Date("2026-07-24T00:05:00Z"),
    });
    assert.notEqual(
      recovered.record.authorizationId,
      firstBootstrap.record.authorizationId,
    );

    const rows = await pool.query(
      "SELECT status, revocation_reason FROM device_credentials WHERE device_uuid=$1",
      [created.deviceUuid],
    );
    assert.equal(rows.rows.length, 1);
    assert.equal(rows.rows[0].status, "FAILED");
    assert.equal(rows.rows[0].revocation_reason, "ISSUANCE_ERROR");

    // The recovered bootstrap must itself be usable: issuance can proceed
    // as normal from here.
    const secondReservation = await store.reserveInitialIssuance({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      tokenHash: recovered.record.tokenHash,
      idempotencyKey: randomUUID(),
      csrFingerprintSha256: "b".repeat(64),
      now: new Date("2026-07-24T00:05:01Z"),
    });
    assert.equal(secondReservation.credential.status, "PENDING");

    await devices.close();
  },
);
