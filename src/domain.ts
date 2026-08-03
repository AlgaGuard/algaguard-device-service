import { createHash, randomBytes, randomUUID } from "node:crypto";

/** Generated from bootstrap-session-v1.schema.json. */
export const CANONICAL_BLE_PROVISIONING_SERVICE_UUID =
  "0000a1a0-0000-1000-8000-00805f9b34fb" as const;

export type DeviceLifecycle =
  | "UNCLAIMED"
  | "CLAIMED"
  | "PROVISIONING"
  | "PROVISIONED"
  | "ACTIVE"
  | "INACTIVE"
  | "REVOKED";

const QR_ONBOARDING_ELIGIBLE_LIFECYCLES: ReadonlySet<DeviceLifecycle> = new Set(
  ["CLAIMED", "PROVISIONED", "ACTIVE", "INACTIVE"],
);

export function qrOnboardingEligibleLifecycle(lifecycle: DeviceLifecycle) {
  return QR_ONBOARDING_ELIGIBLE_LIFECYCLES.has(lifecycle);
}

export interface DeviceRecord {
  deviceUuid: string;
  deviceId: string;
  displayName?: string;
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

export interface PhysicalUnpairResult {
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
  serviceUuid: typeof CANONICAL_BLE_PROVISIONING_SERVICE_UUID;
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
  renameDevice(
    deviceUuid: string,
    displayName: string,
    actorSubjectId: string,
  ): Promise<DeviceRecord>;
  retireDevice(
    deviceUuid: string,
    actorSubjectId: string,
  ): Promise<DeviceRecord>;
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
  confirmPhysicalUnpair(input: {
    deviceUuid: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    commandId: string;
  }): Promise<PhysicalUnpairResult>;
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
  reissueBootstrapSession(input: {
    deviceUuid: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    ttlMs: number;
    now?: Date;
  }): Promise<BootstrapSession>;
  createQrOnboardingSession(input: {
    deviceId: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    nonceHash: string;
    invitationIssuedAt: Date;
    invitationExpiresAt: Date;
    capabilityVersion: number;
    ttlMs: number;
    registerIfMissing?: boolean;
    now?: Date;
  }): Promise<BootstrapSession>;
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
  invalidatedAt?: number;
}

export interface PreparationRecordAudit {
  organizationOwned: boolean;
  ownershipVersionPresent: boolean;
  dependencyCount: number;
  canonicalConflict: boolean;
  identityConflict: boolean;
}

export type PreparationRecordDisposition =
  | "EMPTY_UNOWNED_PREPARATION_RECORD"
  | "OWNED_OR_REFERENCED_LEGITIMATE_RECORD"
  | "DUPLICATE_OR_CONFLICTING_RECORD"
  | "UNKNOWN_UNSAFE_TO_CHANGE";

export function classifyPreparationRecord(
  audit: PreparationRecordAudit,
): PreparationRecordDisposition {
  if (audit.canonicalConflict || audit.identityConflict)
    return "DUPLICATE_OR_CONFLICTING_RECORD";
  if (audit.organizationOwned || audit.dependencyCount > 0)
    return "OWNED_OR_REFERENCED_LEGITIMATE_RECORD";
  if (!audit.ownershipVersionPresent && audit.dependencyCount === 0)
    return "EMPTY_UNOWNED_PREPARATION_RECORD";
  return "UNKNOWN_UNSAFE_TO_CHANGE";
}

export function mayResolveEmptyPreparationRecord(
  audit: PreparationRecordAudit,
) {
  return (
    classifyPreparationRecord(audit) === "EMPTY_UNOWNED_PREPARATION_RECORD"
  );
}

export class MemoryDeviceRepository implements DeviceRepository {
  private nextDevice = 1;
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly claims = new Map<string, MemoryClaim>();
  private readonly bootstrap = new Map<string, MemoryBootstrap>();
  private readonly qrNonceHashes = new Set<string>();
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

  async renameDevice(
    deviceUuid: string,
    displayName: string,
    _actorSubjectId: string,
  ) {
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (device.lifecycle === "REVOKED")
      throw new DomainError("DEVICE_REVOKED", 410, "Device is revoked");
    device.displayName = displayName;
    device.updatedAt = new Date().toISOString();
    return structuredClone(device);
  }

  async retireDevice(deviceUuid: string, _actorSubjectId: string) {
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (device.lifecycle === "REVOKED") return structuredClone(device);
    device.lifecycle = "REVOKED";
    device.ownershipVersion = String(BigInt(device.ownershipVersion) + 1n);
    device.updatedAt = new Date().toISOString();
    return structuredClone(device);
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

  async confirmPhysicalUnpair(input: {
    deviceUuid: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    commandId: string;
  }): Promise<PhysicalUnpairResult> {
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === input.deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (device.organizationId !== input.organizationId)
      throw new DomainError(
        "CROSS_ORGANIZATION_DENIED",
        403,
        "Device ownership changed",
      );
    if (device.ownershipVersion !== input.ownershipVersion)
      throw new DomainError(
        "OWNERSHIP_VERSION_MISMATCH",
        409,
        "Device ownership changed",
      );
    if (!["PROVISIONED", "ACTIVE", "INACTIVE"].includes(device.lifecycle))
      throw new DomainError(
        "UNPAIR_NOT_ALLOWED",
        409,
        "Device cannot be unpaired",
      );
    const previousOrganizationId = device.organizationId;
    device.lifecycle = "UNCLAIMED";
    device.ownershipVersion = (BigInt(device.ownershipVersion) + 1n).toString();
    delete device.displayName;
    delete device.tankId;
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
    const openSessions = [...this.bootstrap.values()].filter(
      (value) =>
        value.deviceId === device.deviceId &&
        !value.consumedAt &&
        !value.invalidatedAt,
    );
    if (openSessions.some((value) => value.expiresAt > now))
      throw new DomainError(
        "ACTIVE_BOOTSTRAP_SESSION_EXISTS",
        409,
        "An active bootstrap session already exists",
      );
    for (const value of openSessions) value.invalidatedAt = now;
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
        serviceUuid: CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
        sessionToken,
      },
    };
  }

  async reissueBootstrapSession(input: {
    deviceUuid: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    ttlMs: number;
    now?: Date;
  }): Promise<BootstrapSession> {
    const now = input.now?.getTime() ?? Date.now();
    const device = [...this.devices.values()].find(
      (candidate) => candidate.deviceUuid === input.deviceUuid,
    );
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (device.organizationId !== input.organizationId)
      throw new DomainError(
        "CROSS_ORGANIZATION_DENIED",
        403,
        "Device is not owned by this organization",
      );
    if (device.ownershipVersion !== input.ownershipVersion)
      throw new DomainError(
        "OWNERSHIP_VERSION_MISMATCH",
        409,
        "Device ownership changed",
      );
    if (device.lifecycle !== "CLAIMED")
      throw new DomainError(
        "BOOTSTRAP_REISSUE_NOT_ALLOWED",
        409,
        "Device lifecycle is not eligible for reissue",
      );
    const sessions = [...this.bootstrap.values()].filter(
      (value) => value.deviceId === device.deviceId && !value.consumedAt,
    );
    if (sessions.some((value) => !value.invalidatedAt && value.expiresAt > now))
      throw new DomainError(
        "ACTIVE_BOOTSTRAP_SESSION_EXISTS",
        409,
        "An active bootstrap session already exists",
      );
    for (const session of sessions)
      if (!session.invalidatedAt) session.invalidatedAt = now;
    const sessionToken = randomBytes(32).toString("base64url");
    const session: MemoryBootstrap = {
      id: randomUUID(),
      deviceId: device.deviceId,
      tokenHash: secretDigest(sessionToken),
      createdAt: now,
      expiresAt: now + input.ttlMs,
    };
    this.bootstrap.set(session.id, session);
    return {
      schema: "urn:algaguard:schema:onboarding:bootstrap-session:v1",
      schemaVersion: "1.0.0",
      sessionId: session.id,
      deviceId: device.deviceId,
      createdAt: new Date(session.createdAt).toISOString(),
      expiresAt: new Date(session.expiresAt).toISOString(),
      serviceUuid: CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
      sessionToken,
    };
  }

  async createQrOnboardingSession(input: {
    deviceId: string;
    organizationId: string;
    ownershipVersion: string;
    actorSubjectId: string;
    nonceHash: string;
    invitationIssuedAt: Date;
    invitationExpiresAt: Date;
    capabilityVersion: number;
    ttlMs: number;
    registerIfMissing?: boolean;
    now?: Date;
  }): Promise<BootstrapSession> {
    const now = input.now ?? new Date();
    const nowMs = now.getTime();
    if (
      !/^[0-9a-f]{64}$/.test(input.nonceHash) ||
      input.capabilityVersion !== 1 ||
      input.invitationIssuedAt >= input.invitationExpiresAt ||
      input.invitationExpiresAt.getTime() + 15_000 < now.getTime()
    )
      throw new DomainError(
        "QR_INVITATION_INVALID",
        400,
        "Invitation is invalid",
      );
    if (this.qrNonceHashes.has(input.nonceHash))
      throw new DomainError(
        "QR_INVITATION_REPLAYED",
        409,
        "Invitation was already used",
      );
    let device = this.devices.get(input.deviceId);
    let provisionalCreated = false;
    if (!device && input.registerIfMissing) {
      if (!/^AG-[0-9]{6}$/.test(input.deviceId))
        throw new DomainError(
          "QR_INVITATION_INVALID",
          400,
          "Invitation is invalid",
        );
      const timestamp = now.toISOString();
      device = {
        deviceUuid: randomUUID(),
        deviceId: input.deviceId,
        organizationId: input.organizationId,
        hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
        firmwareVersion: "0.0.0-development",
        lifecycle: "CLAIMED",
        ownershipVersion: "1",
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      this.devices.set(input.deviceId, device);
      this.nextDevice = Math.max(
        this.nextDevice,
        Number.parseInt(input.deviceId.slice(3), 10) + 1,
      );
      provisionalCreated = true;
    }
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    if (device.lifecycle === "UNCLAIMED" && input.registerIfMissing) {
      device.organizationId = input.organizationId;
      device.ownershipVersion = (
        BigInt(device.ownershipVersion) + 1n
      ).toString();
      device.lifecycle = "CLAIMED";
      device.updatedAt = now.toISOString();
    }
    this.qrNonceHashes.add(input.nonceHash);
    try {
      if (device.organizationId !== input.organizationId)
        throw new DomainError(
          "CROSS_ORGANIZATION_DENIED",
          403,
          "Device is not owned by this organization",
        );
      if (
        !input.registerIfMissing &&
        device.ownershipVersion !== input.ownershipVersion
      )
        throw new DomainError(
          "OWNERSHIP_VERSION_MISMATCH",
          409,
          "Device ownership changed",
        );
      if (!qrOnboardingEligibleLifecycle(device.lifecycle))
        throw new DomainError(
          "QR_ONBOARDING_NOT_ALLOWED",
          409,
          "Device lifecycle is not eligible for onboarding",
        );
      for (const session of this.bootstrap.values()) {
        if (
          session.deviceId === device.deviceId &&
          !session.consumedAt &&
          !session.invalidatedAt
        ) {
          session.invalidatedAt = nowMs;
        }
      }
      const sessionToken = randomBytes(32).toString("base64url");
      const session: MemoryBootstrap = {
        id: randomUUID(),
        deviceId: device.deviceId,
        tokenHash: secretDigest(sessionToken),
        createdAt: nowMs,
        expiresAt: nowMs + input.ttlMs,
      };
      this.bootstrap.set(session.id, session);
      return {
        schema: "urn:algaguard:schema:onboarding:bootstrap-session:v1",
        schemaVersion: "1.0.0",
        sessionId: session.id,
        deviceId: device.deviceId,
        createdAt: new Date(session.createdAt).toISOString(),
        expiresAt: new Date(session.expiresAt).toISOString(),
        serviceUuid: CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
        sessionToken,
      };
    } catch (error) {
      this.qrNonceHashes.delete(input.nonceHash);
      if (provisionalCreated) this.devices.delete(input.deviceId);
      throw error;
    }
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
    if (
      !session ||
      session.consumedAt ||
      session.invalidatedAt ||
      session.expiresAt <= now.getTime()
    )
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
    if (session.consumedAt || session.invalidatedAt)
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
    if (
      session.consumedAt ||
      session.invalidatedAt ||
      session.expiresAt <= now.getTime()
    )
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
