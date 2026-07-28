import { createHash, randomBytes, randomUUID } from "node:crypto";

export const BLE_SERVICE_UUID = "a19a0001-7e4d-4b1a-9c2d-000000000001";

export type DeviceLifecycle =
  | "UNCLAIMED"
  | "CLAIMED"
  | "PROVISIONING"
  | "PROVISIONED"
  | "ACTIVE"
  | "INACTIVE"
  | "REVOKED";

export interface DeviceRecord {
  deviceUuid: string;
  deviceId: string;
  organizationId: string;
  tankId?: string;
  hardwareModel: string;
  firmwareVersion: string;
  lifecycle: DeviceLifecycle;
  ownershipVersion: string;
  createdAt: string;
  updatedAt: string;
}

export interface ResolvedDeviceContext {
  schema: "urn:algaguard:schema:internal:device-context:v1";
  schemaVersion: "1.0.0";
  deviceUuid: string;
  deviceId: string;
  organizationId: string;
  status: "ACTIVE";
  ownershipVersion: string;
  resolvedAt: string;
  tankId?: string;
  contextVersion: "1";
}

export interface OwnershipTransfer {
  device: DeviceRecord;
  previousOrganizationId: string;
}

export interface ClaimQrPayload {
  v: 1;
  d: string;
  c: string;
  e: string;
  f: string;
}

export interface BootstrapSession {
  schema: "urn:algaguard:schema:onboarding:bootstrap-session:v1";
  schemaVersion: "1.0.0";
  sessionId: string;
  deviceId: string;
  createdAt: string;
  expiresAt: string;
  serviceUuid: string;
  sessionToken: string;
}

export interface BootstrapExchangeContext {
  sessionId: string;
  device: DeviceRecord;
}

export interface BootstrapSessionValidationContext {
  sessionId: string;
  device: DeviceRecord;
  expiresAt: string;
}

export class DomainError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function resolveDeviceContext(
  device: DeviceRecord | undefined,
  now = new Date(),
): ResolvedDeviceContext {
  if (!device)
    throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
  if (device.lifecycle === "UNCLAIMED")
    throw new DomainError(
      "DEVICE_UNCLAIMED",
      409,
      "Device has no accepted runtime context",
    );
  if (device.lifecycle === "INACTIVE")
    throw new DomainError("DEVICE_INACTIVE", 409, "Device is inactive");
  if (device.lifecycle === "REVOKED")
    throw new DomainError("DEVICE_REVOKED", 410, "Device is revoked");
  if (device.lifecycle !== "ACTIVE" && device.lifecycle !== "PROVISIONED")
    throw new DomainError("DEVICE_NOT_ACTIVE", 409, "Device is not active");
  return {
    schema: "urn:algaguard:schema:internal:device-context:v1",
    schemaVersion: "1.0.0",
    deviceUuid: device.deviceUuid,
    deviceId: device.deviceId,
    organizationId: device.organizationId,
    status: "ACTIVE",
    ownershipVersion: device.ownershipVersion,
    resolvedAt: now.toISOString(),
    ...(device.tankId ? { tankId: device.tankId } : {}),
    contextVersion: "1",
  };
}

export function secretDigest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

export function fallbackCode(length = 10) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return [...randomBytes(length)]
    .map((value) => alphabet[value % alphabet.length])
    .join("");
}

export interface DeviceCredentialProvider {
  issue(
    deviceId: string,
  ): Promise<{ username: string; password: string; expiresInSeconds: number }>;
}

export class DevelopmentCredentialProvider implements DeviceCredentialProvider {
  constructor(
    private readonly enabled = process.env.ALLOW_DEVELOPMENT_CREDENTIALS ===
      "true" && process.env.NODE_ENV !== "production",
  ) {}
  async issue(deviceId: string) {
    if (!this.enabled)
      throw new DomainError(
        "DEVELOPMENT_PROVIDER_DISABLED",
        503,
        "Development credential provider is disabled",
      );
    return {
      username: deviceId,
      password: randomBytes(32).toString("base64url"),
      expiresInSeconds: 900,
    };
  }
}

export interface DeviceRepository {
  createDevice(input: {
    organizationId: string;
    tankId?: string;
    hardwareModel: string;
  }): Promise<DeviceRecord>;
  listDevices(organizationId: string): Promise<DeviceRecord[]>;
  getDevice(deviceUuid: string): Promise<DeviceRecord | undefined>;
  getDeviceById(deviceId: string): Promise<DeviceRecord | undefined>;
  assignTank(
    deviceUuid: string,
    tankId: string | undefined,
    actorSubjectId: string,
  ): Promise<DeviceRecord>;
  transferOwnership(
    deviceUuid: string,
    organizationId: string,
    actorSubjectId: string,
  ): Promise<OwnershipTransfer>;
  createClaim(
    deviceId: string,
    ttlMs: number,
    actorSubjectId: string,
  ): Promise<ClaimQrPayload>;
  consumeClaim(input: {
    deviceId: string;
    secret: string;
    organizationId: string;
    subjectId: string;
    now?: Date;
  }): Promise<{ device: DeviceRecord; bootstrap: BootstrapSession }>;
  consumeBootstrap(
    deviceId: string,
    sessionToken: string,
    now?: Date,
  ): Promise<DeviceRecord>;
  exchangeBootstrapSession(
    sessionToken: string,
    expectedDeviceId?: string,
    now?: Date,
  ): Promise<BootstrapExchangeContext>;
  validateBootstrapSession(
    sessionToken: string,
    expectedDeviceId: string,
    now?: Date,
  ): Promise<BootstrapSessionValidationContext>;
  activateDevice(
    deviceId: string,
    actorSubjectId: string,
    reason: string,
    now?: Date,
  ): Promise<DeviceRecord>;
  updateStatus(
    deviceId: string,
    status: Record<string, unknown>,
    observedAt: Date,
  ): Promise<void>;
  updateHealth(
    deviceId: string,
    health: Record<string, unknown>,
    observedAt: Date,
  ): Promise<void>;
  latestStatus(deviceId: string): Promise<Record<string, unknown> | undefined>;
  latestHealth(deviceId: string): Promise<Record<string, unknown> | undefined>;
  health(): Promise<void>;
  close(): Promise<void>;
}

interface MemoryClaim {
  id: string;
  deviceId: string;
  tokenHash: string;
  fallbackHash: string;
  expiresAt: number;
  consumedAt?: number;
}

interface MemoryBootstrap {
  id: string;
  deviceId: string;
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  consumedAt?: number;
}

export class MemoryDeviceRepository implements DeviceRepository {
  private nextDevice = 1;
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly claims = new Map<string, MemoryClaim>();
  private readonly bootstrap = new Map<string, MemoryBootstrap>();
  private readonly failures = new Map<string, number[]>();
  private readonly statuses = new Map<string, Record<string, unknown>>();
  private readonly healthValues = new Map<string, Record<string, unknown>>();

  async createDevice(input: {
    organizationId: string;
    tankId?: string;
    hardwareModel: string;
  }) {
    const device: DeviceRecord = {
      deviceUuid: randomUUID(),
      deviceId: `AG-${String(this.nextDevice++).padStart(6, "0")}`,
      organizationId: input.organizationId,
      ...(input.tankId ? { tankId: input.tankId } : {}),
      hardwareModel: input.hardwareModel,
      firmwareVersion: "0.0.0-development",
      lifecycle: "UNCLAIMED",
      ownershipVersion: "1",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.devices.set(device.deviceId, device);
    return structuredClone(device);
  }

  async listDevices(organizationId: string) {
    return [...this.devices.values()]
      .filter((value) => value.organizationId === organizationId)
      .map((value) => structuredClone(value));
  }

  async getDevice(deviceUuid: string) {
    const value = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === deviceUuid,
    );
    return value ? structuredClone(value) : undefined;
  }

  async getDeviceById(deviceId: string) {
    const value = this.devices.get(deviceId);
    return value ? structuredClone(value) : undefined;
  }

  async assignTank(
    deviceUuid: string,
    tankId: string | undefined,
    _actorSubjectId: string,
  ) {
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (tankId) device.tankId = tankId;
    else delete device.tankId;
    device.updatedAt = new Date().toISOString();
    return structuredClone(device);
  }

  async transferOwnership(
    deviceUuid: string,
    organizationId: string,
    _actorSubjectId: string,
  ): Promise<OwnershipTransfer> {
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    const previousOrganizationId = device.organizationId;
    if (previousOrganizationId === organizationId)
      throw new DomainError(
        "OWNERSHIP_UNCHANGED",
        409,
        "Device already belongs to this organization",
      );
    device.organizationId = organizationId;
    device.ownershipVersion = (BigInt(device.ownershipVersion) + 1n).toString();
    device.updatedAt = new Date().toISOString();
    return { device: structuredClone(device), previousOrganizationId };
  }

  async createClaim(deviceId: string, ttlMs: number, _actorSubjectId: string) {
    const device = this.devices.get(deviceId);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    for (const claim of this.claims.values())
      if (claim.deviceId === deviceId && !claim.consumedAt)
        claim.consumedAt = Date.now();
    const token = randomBytes(24).toString("base64url");
    const fallback = fallbackCode();
    const expiresAt = Date.now() + ttlMs;
    const claim: MemoryClaim = {
      id: randomUUID(),
      deviceId,
      tokenHash: secretDigest(token),
      fallbackHash: secretDigest(fallback),
      expiresAt,
    };
    this.claims.set(claim.id, claim);
    return {
      v: 1,
      d: deviceId,
      c: token,
      e: new Date(expiresAt).toISOString(),
      f: fallback,
    } as const;
  }

  async consumeClaim(input: {
    deviceId: string;
    secret: string;
    organizationId: string;
    subjectId: string;
    now?: Date;
  }): Promise<{ device: DeviceRecord; bootstrap: BootstrapSession }> {
    const now = input.now?.getTime() ?? Date.now();
    const failureKey = `${input.subjectId}:${input.deviceId}`;
    const recent = (this.failures.get(failureKey) ?? []).filter(
      (value) => value > now - 15 * 60_000,
    );
    if (recent.length >= 5)
      throw new DomainError(
        "CLAIM_RATE_LIMITED",
        429,
        "Claim attempts are rate limited",
      );
    const digest = secretDigest(input.secret);
    const claim = [...this.claims.values()].find(
      (value) =>
        value.deviceId === input.deviceId &&
        (value.tokenHash === digest || value.fallbackHash === digest),
    );
    const device = this.devices.get(input.deviceId);
    if (!claim || !device || claim.consumedAt || claim.expiresAt <= now) {
      recent.push(now);
      this.failures.set(failureKey, recent);
      throw new DomainError(
        "CLAIM_UNAVAILABLE",
        410,
        "Claim expired, used, or invalid",
      );
    }
    if (device.organizationId !== input.organizationId)
      throw new DomainError(
        "CROSS_ORGANIZATION_DENIED",
        403,
        "Claim is not authorized for this organization",
      );
    claim.consumedAt = now;
    device.lifecycle = "CLAIMED";
    device.updatedAt = new Date(now).toISOString();
    const sessionToken = randomBytes(32).toString("base64url");
    const session: MemoryBootstrap = {
      id: randomUUID(),
      deviceId: device.deviceId,
      tokenHash: secretDigest(sessionToken),
      createdAt: now,
      expiresAt: now + 5 * 60_000,
    };
    this.bootstrap.set(session.id, session);
    return {
      device: structuredClone(device),
      bootstrap: {
        schema: "urn:algaguard:schema:onboarding:bootstrap-session:v1",
        schemaVersion: "1.0.0",
        sessionId: session.id,
        deviceId: device.deviceId,
        createdAt: new Date(session.createdAt).toISOString(),
        expiresAt: new Date(session.expiresAt).toISOString(),
        serviceUuid: BLE_SERVICE_UUID,
        sessionToken,
      },
    };
  }

  async consumeBootstrap(
    deviceId: string,
    sessionToken: string,
    now = new Date(),
  ) {
    const digest = secretDigest(sessionToken);
    const session = [...this.bootstrap.values()].find(
      (value) => value.deviceId === deviceId && value.tokenHash === digest,
    );
    if (!session || session.consumedAt || session.expiresAt <= now.getTime())
      throw new DomainError(
        "BOOTSTRAP_UNAVAILABLE",
        410,
        "Bootstrap session expired, used, or invalid",
      );
    session.consumedAt = now.getTime();
    const device = this.devices.get(deviceId);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    device.lifecycle = "ACTIVE";
    device.updatedAt = now.toISOString();
    return structuredClone(device);
  }

  async exchangeBootstrapSession(
    sessionToken: string,
    expectedDeviceId?: string,
    now = new Date(),
  ): Promise<BootstrapExchangeContext> {
    const session = [...this.bootstrap.values()].find(
      (value) => value.tokenHash === secretDigest(sessionToken),
    );
    if (!session)
      throw new DomainError(
        "INVALID_SESSION_TOKEN",
        401,
        "Session token is invalid",
      );
    if (expectedDeviceId && session.deviceId !== expectedDeviceId)
      throw new DomainError(
        "DEVICE_MISMATCH",
        400,
        "Session does not match device",
      );
    if (session.consumedAt)
      throw new DomainError(
        "USED_SESSION_TOKEN",
        401,
        "Session token was already used",
      );
    if (session.expiresAt <= now.getTime())
      throw new DomainError(
        "EXPIRED_SESSION_TOKEN",
        401,
        "Session token expired",
      );
    const device = this.devices.get(session.deviceId);
    if (
      !device ||
      ["INACTIVE", "REVOKED", "UNCLAIMED"].includes(device.lifecycle)
    )
      throw new DomainError(
        "DEVICE_INACTIVE",
        403,
        "Device is not eligible for bootstrap",
      );
    session.consumedAt = now.getTime();
    return { sessionId: session.id, device: structuredClone(device) };
  }

  async validateBootstrapSession(
    sessionToken: string,
    expectedDeviceId: string,
    now = new Date(),
  ): Promise<BootstrapSessionValidationContext> {
    const session = [...this.bootstrap.values()].find(
      (value) => value.tokenHash === secretDigest(sessionToken),
    );
    if (!session || session.deviceId !== expectedDeviceId)
      throw new DomainError(
        "INVALID_SESSION_TOKEN",
        401,
        "Session token is unavailable",
      );
    if (session.consumedAt || session.expiresAt <= now.getTime())
      throw new DomainError(
        "EXPIRED_SESSION_TOKEN",
        401,
        "Session token is unavailable",
      );
    const device = this.devices.get(session.deviceId);
    if (
      !device ||
      ["INACTIVE", "REVOKED", "UNCLAIMED"].includes(device.lifecycle)
    )
      throw new DomainError(
        "DEVICE_INACTIVE",
        403,
        "Device is not eligible for bootstrap",
      );
    return {
      sessionId: session.id,
      device: structuredClone(device),
      expiresAt: new Date(session.expiresAt).toISOString(),
    };
  }

  async activateDevice(
    deviceId: string,
    _actorSubjectId: string,
    _reason: string,
    now = new Date(),
  ) {
    const device = this.devices.get(deviceId);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (["INACTIVE", "REVOKED", "UNCLAIMED"].includes(device.lifecycle))
      throw new DomainError(
        "DEVICE_NOT_ACTIVE",
        409,
        "Device cannot be activated by credential issuance",
      );
    device.lifecycle = "ACTIVE";
    device.updatedAt = now.toISOString();
    return structuredClone(device);
  }

  async updateStatus(
    deviceId: string,
    status: Record<string, unknown>,
    observedAt: Date,
  ) {
    this.statuses.set(deviceId, {
      ...structuredClone(status),
      observedAt: observedAt.toISOString(),
    });
  }
  async updateHealth(
    deviceId: string,
    health: Record<string, unknown>,
    observedAt: Date,
  ) {
    this.healthValues.set(deviceId, {
      ...structuredClone(health),
      observedAt: observedAt.toISOString(),
    });
  }
  async latestStatus(deviceId: string) {
    return this.statuses.get(deviceId);
  }
  async latestHealth(deviceId: string) {
    return this.healthValues.get(deviceId);
  }
  async health() {}
  async close() {}
}
