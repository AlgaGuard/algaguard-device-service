import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { PostgresCredentialStore } from "../src/credential-store.js";
import { PostgresDeviceRepository } from "../src/repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;
const publicCertificate =
  "-----BEGIN CERTIFICATE-----\n" +
  "U0lNVUxBVEVELVBVQkxJQy1DRVJUSUZJQ0FURS1CWVRFUy1OT1QtUFJJVkFURS1LRVk=".repeat(
    2,
  ) +
  "\n-----END CERTIFICATE-----\n";

test(
  "credential bootstrap, rotation, audit, and revocation survive PostgreSQL restarts",
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

    const firstPool = new pg.Pool({ connectionString: databaseUrl });
    const devices = new PostgresDeviceRepository(firstPool);
    const store = new PostgresCredentialStore(firstPool);
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
    const bootstrap = await store.createBootstrap({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      createdBy: "owner",
      ttlMs: 60_000,
      attempts: 5,
      now: new Date("2026-07-24T00:00:00Z"),
    });
    const storedBootstrap = await firstPool.query(
      "SELECT token_hash FROM credential_bootstrap_sessions WHERE authorization_id=$1",
      [bootstrap.record.authorizationId],
    );
    assert.notEqual(storedBootstrap.rows[0].token_hash, bootstrap.token);

    const initialReservation = await store.reserveInitialIssuance({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      tokenHash: bootstrap.record.tokenHash,
      idempotencyKey: randomUUID(),
      csrFingerprintSha256: "a".repeat(64),
      now: new Date("2026-07-24T00:00:01Z"),
    });
    const initial = await store.completeIssuance({
      credentialId: initialReservation.credential.credentialId,
      certificateSerial: "01AA",
      fingerprintSha256: "b".repeat(64),
      certificatePem: publicCertificate,
      issuerDistinguishedName: "CN=Development CA",
      subjectDistinguishedName: `CN=${created.deviceId}`,
      sanUris: [`urn:algaguard:device:${created.deviceUuid}`],
      notBefore: "2026-07-24T00:00:00Z",
      notAfter: "2026-10-22T00:00:00Z",
      issuedAt: "2026-07-24T00:00:02Z",
    });
    assert.equal(initial.status, "ACTIVE");
    await devices.close();

    const secondPool = new pg.Pool({ connectionString: databaseUrl });
    const restarted = new PostgresCredentialStore(secondPool);
    assert.equal(
      (await restarted.getCredentialByFingerprint("b".repeat(64)))
        ?.credentialId,
      initial.credentialId,
    );
    const rotation = await restarted.beginRotation({
      deviceUuid: created.deviceUuid,
      deviceId: created.deviceId,
      requestedBy: "owner",
      requestKey: randomUUID(),
      reason: "ADMIN_REQUESTED",
      overlapSeconds: 300,
      now: new Date("2026-07-24T01:00:00Z"),
    });
    const replacementReservation = await restarted.reserveRotationIssuance({
      rotationId: rotation.rotationId,
      currentCredentialId: initial.credentialId,
      idempotencyKey: randomUUID(),
      csrFingerprintSha256: "c".repeat(64),
      now: new Date("2026-07-24T01:00:01Z"),
    });
    const replacement = await restarted.completeRotationIssuance({
      credentialId: replacementReservation.credential.credentialId,
      certificateSerial: "02BB",
      fingerprintSha256: "d".repeat(64),
      certificatePem: publicCertificate.replace("U0lN", "VVBM"),
      issuerDistinguishedName: "CN=Development CA",
      subjectDistinguishedName: `CN=${created.deviceId}`,
      sanUris: [`urn:algaguard:device:${created.deviceUuid}`],
      notBefore: "2026-07-24T01:00:00Z",
      notAfter: "2026-10-22T01:00:00Z",
      issuedAt: "2026-07-24T01:00:02Z",
    });
    await restarted.recordAuthenticated(
      replacement.credentialId,
      new Date("2026-07-24T01:00:03Z"),
    );
    const completed = await restarted.acknowledgeRotation({
      rotationId: rotation.rotationId,
      newCredentialId: replacement.credentialId,
      result: "CONNECTED",
      now: new Date("2026-07-24T01:00:04Z"),
    });
    assert.equal(completed.status, "COMPLETED");
    assert.equal(
      (await restarted.getCredential(initial.credentialId))?.status,
      "REVOKED",
    );
    assert.equal(
      (await restarted.getCredential(replacement.credentialId))?.status,
      "ACTIVE",
    );
    await secondPool.end();

    const thirdPool = new pg.Pool({ connectionString: databaseUrl });
    const afterRestart = new PostgresCredentialStore(thirdPool);
    assert.equal(
      (await afterRestart.getCredential(initial.credentialId))
        ?.revocationReason,
      "ROTATED",
    );
    await afterRestart.revokeCredential({
      credentialId: replacement.credentialId,
      reason: "COMPROMISED",
      actorId: "owner",
      actorType: "HUMAN",
      now: new Date("2026-07-24T01:01:00Z"),
    });
    assert.equal(
      (await afterRestart.getCredential(replacement.credentialId))?.status,
      "COMPROMISED",
    );
    const audit = await afterRestart.listAudit(created.deviceUuid);
    assert.ok(audit.some((entry) => entry.action === "ROTATION_COMPLETED"));
    assert.ok(audit.some((entry) => entry.action === "CREDENTIAL_COMPROMISED"));
    const columns = await thirdPool.query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name IN ('device_credentials','credential_bootstrap_sessions')`,
    );
    assert.equal(
      columns.rows.some((row) => /private.*key/i.test(String(row.column_name))),
      false,
    );
    const serialized = await thirdPool.query(
      "SELECT certificate_pem, csr_fingerprint_sha256 FROM device_credentials",
    );
    assert.doesNotMatch(
      JSON.stringify(serialized.rows),
      /BEGIN (?:EC |RSA )?PRIVATE KEY/,
    );
    await assert.rejects(
      thirdPool.query("DELETE FROM device_credentials WHERE credential_id=$1", [
        replacement.credentialId,
      ]),
      (error: unknown) => (error as { code?: string }).code === "23514",
    );
    await thirdPool.end();
  },
);
