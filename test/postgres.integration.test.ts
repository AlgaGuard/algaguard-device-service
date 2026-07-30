import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import { DomainError } from "../src/domain.js";
import { PostgresDeviceRepository } from "../src/repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

test(
  "claim hashes, atomic consumption, and bootstrap state survive restart",
  { skip: !databaseUrl },
  async () => {
    const cleanup = new pg.Pool({ connectionString: databaseUrl });
    await cleanup.query(
      "TRUNCATE device_ownership_history, device_health_projection, device_status_projection, device_transitions, claim_failures, bootstrap_sessions, device_claims, devices RESTART IDENTITY CASCADE",
    );
    await cleanup.query("ALTER SEQUENCE device_number_sequence RESTART WITH 1");
    await cleanup.end();

    const organizationId = "10000000-0000-4000-8000-000000000001";
    const first = new PostgresDeviceRepository(
      new pg.Pool({ connectionString: databaseUrl }),
    );
    const created = await first.createDevice({
      organizationId,
      hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
    });
    const qr = await first.createClaim(created.deviceId, 60_000, "owner");
    const stored = await first.pool.query(
      "SELECT token_hash, fallback_hash FROM device_claims WHERE device_id = $1",
      [created.deviceId],
    );
    assert.notEqual(stored.rows[0].token_hash, qr.c);
    assert.notEqual(stored.rows[0].fallback_hash, qr.f);

    const outcomes = await Promise.allSettled([
      first.consumeClaim({
        deviceId: created.deviceId,
        secret: qr.c,
        organizationId,
        subjectId: "owner",
      }),
      first.consumeClaim({
        deviceId: created.deviceId,
        secret: qr.c,
        organizationId,
        subjectId: "owner",
      }),
    ]);
    const successful = outcomes.find((value) => value.status === "fulfilled");
    assert.ok(successful && successful.status === "fulfilled");
    assert.equal(
      outcomes.filter((value) => value.status === "fulfilled").length,
      1,
    );
    await first.close();

    const restarted = new PostgresDeviceRepository(
      new pg.Pool({ connectionString: databaseUrl }),
    );
    assert.equal(
      (await restarted.getDevice(created.deviceUuid))?.lifecycle,
      "CLAIMED",
    );
    await assert.rejects(
      restarted.consumeClaim({
        deviceId: created.deviceId,
        secret: qr.c,
        organizationId,
        subjectId: "owner",
      }),
      (error: unknown) =>
        error instanceof DomainError && error.code === "CLAIM_UNAVAILABLE",
    );
    const deviceBeforeReissue = await restarted.getDevice(created.deviceUuid);
    const reissueNow = new Date(Date.now() + 301_000);
    const reissued = await restarted.reissueBootstrapSession({
      deviceUuid: created.deviceUuid,
      organizationId,
      ownershipVersion: "1",
      actorSubjectId: "owner",
      ttlMs: 300_000,
      now: reissueNow,
    });
    const storedReissue = await restarted.pool.query(
      "SELECT token_hash FROM bootstrap_sessions WHERE id=$1",
      [reissued.sessionId],
    );
    assert.match(String(storedReissue.rows[0].token_hash), /^[0-9a-f]{64}$/);
    assert.notEqual(storedReissue.rows[0].token_hash, reissued.sessionToken);
    const deviceAfterReissue = await restarted.getDevice(created.deviceUuid);
    assert.equal(
      deviceAfterReissue?.organizationId,
      deviceBeforeReissue?.organizationId,
    );
    assert.equal(
      deviceAfterReissue?.ownershipVersion,
      deviceBeforeReissue?.ownershipVersion,
    );
    await restarted.consumeBootstrap(
      created.deviceId,
      reissued.sessionToken,
      new Date(reissueNow.getTime() + 1),
    );
    await restarted.close();

    const afterBootstrapRestart = new PostgresDeviceRepository(
      new pg.Pool({ connectionString: databaseUrl }),
    );
    assert.equal(
      (await afterBootstrapRestart.getDevice(created.deviceUuid))?.lifecycle,
      "ACTIVE",
    );
    const transferred = await afterBootstrapRestart.transferOwnership(
      created.deviceUuid,
      "20000000-0000-4000-8000-000000000002",
      "owner",
    );
    assert.equal(transferred.device.deviceUuid, created.deviceUuid);
    assert.equal(transferred.device.deviceId, created.deviceId);
    assert.equal(transferred.device.ownershipVersion, "2");
    await assert.rejects(
      afterBootstrapRestart.pool.query(
        "UPDATE devices SET device_id = 'AG-999999' WHERE device_uuid = $1",
        [created.deviceUuid],
      ),
      (error: unknown) => (error as { code?: string }).code === "23514",
    );
    await afterBootstrapRestart.close();
  },
);
