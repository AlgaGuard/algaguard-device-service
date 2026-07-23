import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import {
  BLE_SERVICE_UUID,
  DomainError,
  fallbackCode,
  secretDigest,
  type BootstrapSession,
  type ClaimQrPayload,
  type DeviceLifecycle,
  type DeviceRecord,
  type DeviceRepository,
} from "./domain.js";

function iso(value: Date | string) {
  return value instanceof Date
    ? value.toISOString()
    : new Date(value).toISOString();
}

function device(row: Record<string, unknown>): DeviceRecord {
  return {
    deviceUuid: String(row.device_uuid),
    deviceId: String(row.device_id),
    organizationId: String(row.organization_id),
    ...(row.tank_id ? { tankId: String(row.tank_id) } : {}),
    hardwareModel: String(row.hardware_model),
    firmwareVersion: String(row.firmware_version),
    lifecycle: row.lifecycle as DeviceLifecycle,
    ownershipVersion: String(row.ownership_version),
    createdAt: iso(row.created_at as Date),
    updatedAt: iso(row.updated_at as Date),
  };
}

export class PostgresDeviceRepository implements DeviceRepository {
  constructor(readonly pool: pg.Pool) {}

  async createDevice(input: {
    organizationId: string;
    tankId?: string;
    hardwareModel: string;
  }) {
    const result = await this.pool.query(
      `INSERT INTO devices
         (device_uuid, device_id, organization_id, tank_id, hardware_model, firmware_version, lifecycle)
       VALUES (
         $4,
         'AG-' || lpad(nextval('device_number_sequence')::text, 6, '0'),
         $1, $2, $3, '0.0.0-development', 'UNCLAIMED'
       ) RETURNING *`,
      [
        input.organizationId,
        input.tankId ?? null,
        input.hardwareModel,
        randomUUID(),
      ],
    );
    return device(result.rows[0] as Record<string, unknown>);
  }

  async listDevices(organizationId: string) {
    const result = await this.pool.query(
      "SELECT * FROM devices WHERE organization_id = $1 ORDER BY device_id",
      [organizationId],
    );
    return result.rows.map((row) => device(row as Record<string, unknown>));
  }

  async getDevice(deviceUuid: string) {
    const result = await this.pool.query(
      "SELECT * FROM devices WHERE device_uuid = $1",
      [deviceUuid],
    );
    return result.rows[0]
      ? device(result.rows[0] as Record<string, unknown>)
      : undefined;
  }

  async getDeviceById(deviceId: string) {
    const result = await this.pool.query(
      "SELECT * FROM devices WHERE device_id = $1",
      [deviceId],
    );
    return result.rows[0]
      ? device(result.rows[0] as Record<string, unknown>)
      : undefined;
  }

  async assignTank(
    deviceUuid: string,
    tankId: string | undefined,
    actorSubjectId: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        "UPDATE devices SET tank_id = $2, updated_at = now() WHERE device_uuid = $1 RETURNING *",
        [deviceUuid, tankId ?? null],
      );
      if (!updated.rows[0])
        throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
      await client.query(
        `INSERT INTO device_transitions
           (device_id, from_lifecycle, to_lifecycle, actor_subject_id, reason)
         VALUES ($1, $2, $2, $3, 'TANK_ASSIGNMENT_CHANGED')`,
        [updated.rows[0].device_id, updated.rows[0].lifecycle, actorSubjectId],
      );
      await client.query("COMMIT");
      return device(updated.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async transferOwnership(
    deviceUuid: string,
    organizationId: string,
    actorSubjectId: string,
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(
        "SELECT * FROM devices WHERE device_uuid = $1 FOR UPDATE",
        [deviceUuid],
      );
      const row = current.rows[0] as Record<string, unknown> | undefined;
      if (!row)
        throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
      const previousOrganizationId = String(row.organization_id);
      if (previousOrganizationId === organizationId)
        throw new DomainError(
          "OWNERSHIP_UNCHANGED",
          409,
          "Device already belongs to this organization",
        );
      const updated = await client.query(
        `UPDATE devices
            SET organization_id = $2,
                ownership_version = ownership_version + 1,
                updated_at = now()
          WHERE device_uuid = $1
          RETURNING *`,
        [deviceUuid, organizationId],
      );
      await client.query(
        `INSERT INTO device_ownership_history
           (device_uuid, device_id, previous_organization_id, organization_id,
            ownership_version, actor_subject_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          deviceUuid,
          updated.rows[0].device_id,
          previousOrganizationId,
          organizationId,
          updated.rows[0].ownership_version,
          actorSubjectId,
        ],
      );
      await client.query("COMMIT");
      return {
        device: device(updated.rows[0] as Record<string, unknown>),
        previousOrganizationId,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async createClaim(
    deviceId: string,
    ttlMs: number,
    actorSubjectId: string,
  ): Promise<ClaimQrPayload> {
    const token = randomBytes(24).toString("base64url");
    const fallback = fallbackCode();
    const expiresAt = new Date(Date.now() + ttlMs);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(
        "SELECT 1 FROM devices WHERE device_id = $1 FOR UPDATE",
        [deviceId],
      );
      if (!locked.rowCount)
        throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
      await client.query(
        `UPDATE device_claims SET invalidated_at = now()
          WHERE device_id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL`,
        [deviceId],
      );
      await client.query(
        `INSERT INTO device_claims
           (id, device_id, token_hash, fallback_hash, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          randomUUID(),
          deviceId,
          secretDigest(token),
          secretDigest(fallback),
          expiresAt,
          actorSubjectId,
        ],
      );
      await client.query("COMMIT");
      return {
        v: 1,
        d: deviceId,
        c: token,
        e: expiresAt.toISOString(),
        f: fallback,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private async recentFailureCount(
    subjectId: string,
    deviceId: string,
    now: Date,
  ) {
    const result = await this.pool.query(
      `SELECT count(*)::integer AS count FROM claim_failures
        WHERE subject_id = $1 AND device_id = $2 AND attempted_at > $3::timestamptz - interval '15 minutes'`,
      [subjectId, deviceId, now],
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  private async recordFailure(subjectId: string, deviceId: string, now: Date) {
    await this.pool.query(
      "INSERT INTO claim_failures(device_id, subject_id, attempted_at) VALUES ($1, $2, $3)",
      [deviceId, subjectId, now],
    );
  }

  async consumeClaim(input: {
    deviceId: string;
    secret: string;
    organizationId: string;
    subjectId: string;
    now?: Date;
  }) {
    const now = input.now ?? new Date();
    if (
      (await this.recentFailureCount(input.subjectId, input.deviceId, now)) >= 5
    )
      throw new DomainError(
        "CLAIM_RATE_LIMITED",
        429,
        "Claim attempts are rate limited",
      );
    const digest = secretDigest(input.secret);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT c.*, d.organization_id, d.tank_id, d.hardware_model,
                d.firmware_version, d.lifecycle, d.created_at
           FROM device_claims c JOIN devices d ON d.device_id = c.device_id
          WHERE c.device_id = $1 AND (c.token_hash = $2 OR c.fallback_hash = $2)
          FOR UPDATE OF c, d`,
        [input.deviceId, digest],
      );
      const row = found.rows[0] as Record<string, unknown> | undefined;
      if (
        !row ||
        row.consumed_at ||
        row.invalidated_at ||
        new Date(row.expires_at as Date | string).getTime() <= now.getTime()
      )
        throw new DomainError(
          "CLAIM_UNAVAILABLE",
          410,
          "Claim expired, used, or invalid",
        );
      if (String(row.organization_id) !== input.organizationId)
        throw new DomainError(
          "CROSS_ORGANIZATION_DENIED",
          403,
          "Claim is not authorized for this organization",
        );
      await client.query(
        "UPDATE device_claims SET consumed_at = $2 WHERE id = $1",
        [row.id, now],
      );
      const transitioned = await client.query(
        "UPDATE devices SET lifecycle = 'CLAIMED', updated_at = $2 WHERE device_id = $1 RETURNING *",
        [input.deviceId, now],
      );
      await client.query(
        `INSERT INTO device_transitions
           (device_id, from_lifecycle, to_lifecycle, actor_subject_id, reason, occurred_at)
         VALUES ($1, $2, 'CLAIMED', $3, 'CLAIM_CONSUMED', $4)`,
        [input.deviceId, row.lifecycle, input.subjectId, now],
      );
      const sessionToken = randomBytes(32).toString("base64url");
      const sessionId = randomUUID();
      const expiresAt = new Date(now.getTime() + 5 * 60_000);
      const inserted = await client.query(
        `INSERT INTO bootstrap_sessions(id, device_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5) RETURNING created_at`,
        [sessionId, input.deviceId, secretDigest(sessionToken), expiresAt, now],
      );
      await client.query("COMMIT");
      const bootstrap: BootstrapSession = {
        schema: "urn:algaguard:schema:onboarding:bootstrap-session:v1",
        schemaVersion: "1.0.0",
        sessionId,
        deviceId: input.deviceId,
        createdAt: iso(inserted.rows[0].created_at as Date),
        expiresAt: expiresAt.toISOString(),
        serviceUuid: BLE_SERVICE_UUID,
        sessionToken,
      };
      return {
        device: device(transitioned.rows[0] as Record<string, unknown>),
        bootstrap,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      if (error instanceof DomainError && error.code === "CLAIM_UNAVAILABLE")
        await this.recordFailure(input.subjectId, input.deviceId, now);
      throw error;
    } finally {
      client.release();
    }
  }

  async consumeBootstrap(
    deviceId: string,
    sessionToken: string,
    now = new Date(),
  ) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT b.*, d.lifecycle FROM bootstrap_sessions b
          JOIN devices d ON d.device_id = b.device_id
         WHERE b.device_id = $1 AND b.token_hash = $2
         FOR UPDATE OF b, d`,
        [deviceId, secretDigest(sessionToken)],
      );
      const row = found.rows[0] as Record<string, unknown> | undefined;
      if (
        !row ||
        row.consumed_at ||
        new Date(row.expires_at as Date | string).getTime() <= now.getTime()
      )
        throw new DomainError(
          "BOOTSTRAP_UNAVAILABLE",
          410,
          "Bootstrap session expired, used, or invalid",
        );
      await client.query(
        "UPDATE bootstrap_sessions SET consumed_at = $2 WHERE id = $1",
        [row.id, now],
      );
      const updated = await client.query(
        "UPDATE devices SET lifecycle = 'ACTIVE', updated_at = $2 WHERE device_id = $1 RETURNING *",
        [deviceId, now],
      );
      await client.query(
        `INSERT INTO device_transitions
           (device_id, from_lifecycle, to_lifecycle, actor_subject_id, reason, occurred_at)
         VALUES ($1, $2, 'ACTIVE', 'bootstrap-session', 'CREDENTIAL_ISSUED', $3)`,
        [deviceId, row.lifecycle, now],
      );
      await client.query("COMMIT");
      return device(updated.rows[0] as Record<string, unknown>);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async updateStatus(
    deviceId: string,
    status: Record<string, unknown>,
    observedAt: Date,
  ) {
    await this.pool.query(
      `INSERT INTO device_status_projection(device_id, status, observed_at)
       VALUES ($1, $2::jsonb, $3)
       ON CONFLICT(device_id) DO UPDATE SET status = EXCLUDED.status,
         observed_at = EXCLUDED.observed_at, updated_at = now()
       WHERE device_status_projection.observed_at <= EXCLUDED.observed_at`,
      [deviceId, JSON.stringify(status), observedAt],
    );
  }

  async updateHealth(
    deviceId: string,
    health: Record<string, unknown>,
    observedAt: Date,
  ) {
    await this.pool.query(
      `INSERT INTO device_health_projection(device_id, health, observed_at)
       VALUES ($1, $2::jsonb, $3)
       ON CONFLICT(device_id) DO UPDATE SET health = EXCLUDED.health,
         observed_at = EXCLUDED.observed_at, updated_at = now()
       WHERE device_health_projection.observed_at <= EXCLUDED.observed_at`,
      [deviceId, JSON.stringify(health), observedAt],
    );
  }

  async latestStatus(deviceId: string) {
    const result = await this.pool.query(
      `SELECT status, observed_at AS "observedAt" FROM device_status_projection WHERE device_id = $1`,
      [deviceId],
    );
    return result.rows[0] as Record<string, unknown> | undefined;
  }

  async latestHealth(deviceId: string) {
    const result = await this.pool.query(
      `SELECT health, observed_at AS "observedAt" FROM device_health_projection WHERE device_id = $1`,
      [deviceId],
    );
    return result.rows[0] as Record<string, unknown> | undefined;
  }

  async health() {
    await this.pool.query("SELECT 1");
  }
  async close() {
    await this.pool.end();
  }
}
