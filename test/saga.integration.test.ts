import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  PostgresDeviceOwnershipSagaRepository,
  PostgresDeviceRepository,
} from "../src/repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;

async function freshPool() {
  const cleanup = new pg.Pool({ connectionString: databaseUrl });
  await cleanup.query(
    "TRUNCATE device_ownership_saga_transitions, device_ownership_saga, device_ownership_history, devices RESTART IDENTITY CASCADE",
  );
  await cleanup.end();
  return new pg.Pool({ connectionString: databaseUrl });
}

test(
  "createDevice records a PENDING DEVICE_CREATION saga atomically with the insert",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const organizationId = "10000000-0000-4000-8000-000000000001";
      const created = await repository.createDevice({
        organizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });
      const saga = await pool.query(
        "SELECT * FROM device_ownership_saga WHERE device_uuid = $1",
        [created.deviceUuid],
      );
      assert.equal(saga.rows.length, 1);
      assert.equal(saga.rows[0].saga_type, "DEVICE_CREATION");
      assert.equal(saga.rows[0].state, "PENDING");
      assert.equal(saga.rows[0].to_organization_id, organizationId);
    } finally {
      await pool.end();
    }
  },
);

test(
  "transferOwnership records an OWNERSHIP_TRANSFER saga with both organizations",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const fromOrganizationId = "10000000-0000-4000-8000-000000000001";
      const toOrganizationId = "10000000-0000-4000-8000-000000000002";
      const created = await repository.createDevice({
        organizationId: fromOrganizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });
      await repository.transferOwnership(
        created.deviceUuid,
        toOrganizationId,
        "owner",
      );
      const saga = await pool.query(
        `SELECT * FROM device_ownership_saga
          WHERE device_uuid = $1 AND saga_type = 'OWNERSHIP_TRANSFER'`,
        [created.deviceUuid],
      );
      assert.equal(saga.rows.length, 1);
      assert.equal(saga.rows[0].from_organization_id, fromOrganizationId);
      assert.equal(saga.rows[0].to_organization_id, toOrganizationId);
    } finally {
      await pool.end();
    }
  },
);

test(
  "the saga repository's claim/complete cycle is atomic and SKIP LOCKED-safe under concurrent claimers",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const organizationId = "10000000-0000-4000-8000-000000000001";
      const created = await repository.createDevice({
        organizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });

      const sagaRepository = new PostgresDeviceOwnershipSagaRepository(pool);
      const [first, second] = await Promise.all([
        sagaRepository.claim(),
        sagaRepository.claim(),
      ]);
      // Exactly one of the two concurrent claimers gets the single PENDING
      // saga; SKIP LOCKED means the other sees nothing rather than blocking.
      const claimed = [first, second].filter(Boolean);
      assert.equal(claimed.length, 1);
      assert.equal(claimed[0]?.deviceUuid, created.deviceUuid);
      assert.equal(claimed[0]?.attempts, 1);

      await sagaRepository.complete(claimed[0]!.sagaId);
      const state = await pool.query(
        "SELECT state, completed_at FROM device_ownership_saga WHERE saga_id = $1",
        [claimed[0]!.sagaId],
      );
      assert.equal(state.rows[0].state, "COMPLETED");
      assert.ok(state.rows[0].completed_at);

      // Completed sagas are never claimed again.
      assert.equal(await sagaRepository.claim(), undefined);
    } finally {
      await pool.end();
    }
  },
);

test(
  "retry() sets next_attempt_at so claim() only picks it up once that time has passed",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const organizationId = "10000000-0000-4000-8000-000000000001";
      const created = await repository.createDevice({
        organizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });

      const sagaRepository = new PostgresDeviceOwnershipSagaRepository(pool);
      const claimed = await sagaRepository.claim();
      assert.ok(claimed);
      await sagaRepository.retry(
        claimed!.sagaId,
        "transient failure",
        new Date(Date.now() + 60_000),
      );

      // next_attempt_at is 60s in the future relative to the database's own
      // now(), so a real claim() call right now must not pick it up.
      assert.equal(await sagaRepository.claim(), undefined);

      // Advance it into the past the same way real elapsed time would,
      // rather than trying to fake "now" on the client (claim() correctly
      // ignores a client-supplied clock and always compares against the
      // database's own now() -- see the comment on claim()).
      await pool.query(
        "UPDATE device_ownership_saga SET next_attempt_at = now() - interval '1 second' WHERE saga_id = $1",
        [claimed!.sagaId],
      );
      const laterClaim = await sagaRepository.claim();
      assert.equal(laterClaim?.sagaId, claimed!.sagaId);
      assert.equal(laterClaim?.attempts, 2);
    } finally {
      await pool.end();
    }
  },
);

test(
  "startCompensating then markCompensated transitions the saga to COMPENSATED",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const organizationId = "10000000-0000-4000-8000-000000000001";
      await repository.createDevice({
        organizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });

      const sagaRepository = new PostgresDeviceOwnershipSagaRepository(pool);
      const claimed = await sagaRepository.claim();
      assert.ok(claimed);
      await sagaRepository.startCompensating(claimed!.sagaId);
      let state = await pool.query(
        "SELECT state FROM device_ownership_saga WHERE saga_id = $1",
        [claimed!.sagaId],
      );
      assert.equal(state.rows[0].state, "COMPENSATING");

      await sagaRepository.markCompensated(claimed!.sagaId);
      state = await pool.query(
        "SELECT state, completed_at FROM device_ownership_saga WHERE saga_id = $1",
        [claimed!.sagaId],
      );
      assert.equal(state.rows[0].state, "COMPENSATED");
      assert.ok(state.rows[0].completed_at);

      const transitions = await pool.query(
        `SELECT state FROM device_ownership_saga_transitions
          WHERE saga_id = $1 ORDER BY occurred_at`,
        [claimed!.sagaId],
      );
      assert.deepEqual(
        transitions.rows.map((row: { state: string }) => row.state),
        ["PENDING", "COMPENSATING", "COMPENSATED"],
      );
    } finally {
      await pool.end();
    }
  },
);

test(
  "revertOwnershipForCompensation reverts organization_id without recording a new saga",
  { skip: !databaseUrl },
  async () => {
    const pool = await freshPool();
    try {
      const repository = new PostgresDeviceRepository(pool);
      const fromOrganizationId = "10000000-0000-4000-8000-000000000001";
      const toOrganizationId = "10000000-0000-4000-8000-000000000002";
      const created = await repository.createDevice({
        organizationId: fromOrganizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
      });
      await repository.transferOwnership(
        created.deviceUuid,
        toOrganizationId,
        "owner",
      );
      const beforeCount = await pool.query(
        "SELECT count(*) FROM device_ownership_saga WHERE device_uuid = $1",
        [created.deviceUuid],
      );

      await repository.revertOwnershipForCompensation(
        created.deviceUuid,
        fromOrganizationId,
      );

      const reverted = await repository.getDevice(created.deviceUuid);
      assert.equal(reverted?.organizationId, fromOrganizationId);
      assert.equal(reverted?.ownershipVersion, "3"); // create=1, transfer=2, revert=3

      const afterCount = await pool.query(
        "SELECT count(*) FROM device_ownership_saga WHERE device_uuid = $1",
        [created.deviceUuid],
      );
      assert.equal(afterCount.rows[0].count, beforeCount.rows[0].count);
    } finally {
      await pool.end();
    }
  },
);
