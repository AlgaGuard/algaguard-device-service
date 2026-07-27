import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { DomainError, secretDigest } from "./domain.js";

export type CredentialStatus =
  | "PENDING"
  | "ACTIVE"
  | "ROTATING"
  | "REVOKED"
  | "EXPIRED"
  | "COMPROMISED"
  | "FAILED";

export type RevocationReason =
  | "ROTATED"
  | "EXPIRED"
  | "COMPROMISED"
  | "ADMIN_REVOKED"
  | "DEVICE_RETIRED"
  | "ISSUANCE_ERROR"
  | "RECOVERY_REPLACED";

export type CredentialPurpose = "INITIAL" | "ROTATION" | "RECOVERY";

export interface DeviceCredentialRecord {
  credentialId: string;
  deviceUuid: string;
  deviceId: string;
  purpose: CredentialPurpose;
  idempotencyKey: string;
  csrFingerprintSha256: string;
  certificateSerial?: string;
  fingerprintSha256?: string;
  certificatePem?: string;
  issuerDistinguishedName?: string;
  subjectDistinguishedName?: string;
  sanUris: string[];
  notBefore?: string;
  notAfter?: string;
  issuedAt?: string;
  activatedAt?: string;
  revokedAt?: string;
  revocationReason?: RevocationReason;
  status: CredentialStatus;
  parentCredentialId?: string;
  childCredentialId?: string;
  rotationId?: string;
  lastAuthenticatedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialBootstrapRecord {
  authorizationId: string;
  deviceUuid: string;
  deviceId: string;
  organizationId?: string;
  ownershipVersion?: string;
  claimSessionId?: string;
  purpose?: "CSR_ISSUE";
  tokenHash: string;
  attemptsRemaining: number;
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
  invalidatedAt?: string;
}

export type RotationStatus =
  "REQUESTED" | "ISSUING" | "OVERLAP" | "COMPLETED" | "FAILED" | "EXPIRED";

export interface CredentialRotationRecord {
  rotationId: string;
  deviceUuid: string;
  deviceId: string;
  currentCredentialId: string;
  newCredentialId?: string;
  requestedBy: string;
  requestKey: string;
  reason: "SCHEDULED" | "EXPIRING" | "ADMIN_REQUESTED" | "RECOVERY";
  overlapSeconds: number;
  requestedAt: string;
  expiresAt: string;
  acknowledgedAt?: string;
  status: RotationStatus;
  failureCode?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialAuditRecord {
  auditId: string;
  deviceUuid: string;
  deviceId: string;
  credentialId?: string;
  rotationId?: string;
  action: string;
  actorType: "HUMAN" | "DEVICE" | "SERVICE" | "SYSTEM";
  actorId: string;
  details: Record<string, unknown>;
  occurredAt: string;
}

export interface CompleteCredentialInput {
  credentialId: string;
  certificateSerial: string;
  fingerprintSha256: string;
  certificatePem: string;
  issuerDistinguishedName: string;
  subjectDistinguishedName: string;
  sanUris: string[];
  notBefore: string;
  notAfter: string;
  issuedAt: string;
}

export interface CredentialStore {
  createBootstrap(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    claimSessionId?: string;
    createdBy: string;
    ttlMs: number;
    attempts: number;
    now: Date;
  }): Promise<{ record: CredentialBootstrapRecord; token: string }>;
  reserveInitialIssuance(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    tokenHash: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }): Promise<{ credential: DeviceCredentialRecord; replay: boolean }>;
  completeIssuance(
    input: CompleteCredentialInput,
  ): Promise<DeviceCredentialRecord>;
  failIssuance(credentialId: string, now: Date): Promise<void>;
  listCredentials(deviceUuid: string): Promise<DeviceCredentialRecord[]>;
  getCredential(
    credentialId: string,
  ): Promise<DeviceCredentialRecord | undefined>;
  getCredentialByFingerprint(
    fingerprint: string,
  ): Promise<DeviceCredentialRecord | undefined>;
  beginRotation(input: {
    deviceUuid: string;
    deviceId: string;
    requestedBy: string;
    requestKey: string;
    reason: CredentialRotationRecord["reason"];
    overlapSeconds: number;
    now: Date;
  }): Promise<CredentialRotationRecord>;
  getRotation(
    rotationId: string,
  ): Promise<CredentialRotationRecord | undefined>;
  reserveRotationIssuance(input: {
    rotationId: string;
    currentCredentialId: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }): Promise<{ credential: DeviceCredentialRecord; replay: boolean }>;
  completeRotationIssuance(
    input: CompleteCredentialInput,
  ): Promise<DeviceCredentialRecord>;
  recordAuthenticated(credentialId: string, now: Date): Promise<void>;
  acknowledgeRotation(input: {
    rotationId: string;
    newCredentialId: string;
    result: "CONNECTED" | "FAILED";
    failureCode?: string;
    now: Date;
  }): Promise<CredentialRotationRecord>;
  revokeCredential(input: {
    credentialId: string;
    reason: RevocationReason;
    actorId: string;
    actorType: CredentialAuditRecord["actorType"];
    now: Date;
  }): Promise<DeviceCredentialRecord>;
  listAudit(deviceUuid: string): Promise<CredentialAuditRecord[]>;
  health(): Promise<void>;
  close(): Promise<void>;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function activeCredential(status: CredentialStatus) {
  return status === "PENDING" || status === "ACTIVE" || status === "ROTATING";
}

export class MemoryCredentialStore implements CredentialStore {
  private readonly bootstraps = new Map<string, CredentialBootstrapRecord>();
  private readonly credentials = new Map<string, DeviceCredentialRecord>();
  private readonly rotations = new Map<string, CredentialRotationRecord>();
  private readonly audits: CredentialAuditRecord[] = [];

  private audit(
    input: Omit<CredentialAuditRecord, "auditId" | "occurredAt">,
    now: Date,
  ) {
    this.audits.push({
      ...clone(input),
      auditId: randomUUID(),
      occurredAt: now.toISOString(),
    });
  }

  async createBootstrap(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    claimSessionId?: string;
    createdBy: string;
    ttlMs: number;
    attempts: number;
    now: Date;
  }) {
    const activeInitial = [...this.credentials.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid &&
        value.purpose === "INITIAL" &&
        activeCredential(value.status),
    );
    if (activeInitial)
      throw new DomainError(
        "INITIAL_CREDENTIAL_EXISTS",
        409,
        "Device already has an initial credential",
      );
    for (const record of this.bootstraps.values())
      if (
        record.deviceUuid === input.deviceUuid &&
        !record.consumedAt &&
        !record.invalidatedAt
      )
        record.invalidatedAt = input.now.toISOString();
    const token = randomBytes(32).toString("base64url");
    const record: CredentialBootstrapRecord = {
      authorizationId: randomUUID(),
      deviceUuid: input.deviceUuid,
      deviceId: input.deviceId,
      ...(input.organizationId ? { organizationId: input.organizationId } : {}),
      ...(input.ownershipVersion
        ? { ownershipVersion: input.ownershipVersion }
        : {}),
      ...(input.claimSessionId ? { claimSessionId: input.claimSessionId } : {}),
      ...(input.claimSessionId ? { purpose: "CSR_ISSUE" as const } : {}),
      tokenHash: secretDigest(token),
      attemptsRemaining: input.attempts,
      createdBy: input.createdBy,
      createdAt: input.now.toISOString(),
      expiresAt: new Date(input.now.getTime() + input.ttlMs).toISOString(),
    };
    this.bootstraps.set(record.authorizationId, record);
    this.audit(
      {
        deviceUuid: input.deviceUuid,
        deviceId: input.deviceId,
        action: "BOOTSTRAP_CREATED",
        actorType: "HUMAN",
        actorId: input.createdBy,
        details: { authorizationId: record.authorizationId },
      },
      input.now,
    );
    return { record: clone(record), token };
  }

  async reserveInitialIssuance(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    tokenHash: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }) {
    const replay = [...this.credentials.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid &&
        value.idempotencyKey === input.idempotencyKey,
    );
    if (replay) return { credential: clone(replay), replay: true };
    const authorization = [...this.bootstraps.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid &&
        value.deviceId === input.deviceId &&
        !value.consumedAt &&
        !value.invalidatedAt,
    );
    if (
      !authorization ||
      Date.parse(authorization.expiresAt) <= input.now.getTime()
    )
      throw new DomainError(
        "BOOTSTRAP_UNAVAILABLE",
        410,
        "Bootstrap authorization expired, used, or invalid",
      );
    if (
      (authorization.organizationId &&
        authorization.organizationId !== input.organizationId) ||
      (authorization.ownershipVersion &&
        authorization.ownershipVersion !== input.ownershipVersion)
    )
      throw new DomainError(
        "OWNERSHIP_VERSION_CHANGED",
        403,
        "Bootstrap authorization is no longer valid",
      );
    if (authorization.tokenHash !== input.tokenHash) {
      authorization.attemptsRemaining -= 1;
      if (authorization.attemptsRemaining <= 0)
        authorization.invalidatedAt = input.now.toISOString();
      throw new DomainError(
        "BOOTSTRAP_UNAVAILABLE",
        authorization.attemptsRemaining <= 0 ? 429 : 401,
        "Bootstrap authorization expired, used, or invalid",
      );
    }
    if (
      [...this.credentials.values()].some(
        (value) =>
          value.deviceUuid === input.deviceUuid &&
          value.purpose === "INITIAL" &&
          activeCredential(value.status),
      )
    )
      throw new DomainError(
        "INITIAL_CREDENTIAL_EXISTS",
        409,
        "Concurrent initial credential issuance is not allowed",
      );
    authorization.consumedAt = input.now.toISOString();
    const credential: DeviceCredentialRecord = {
      credentialId: randomUUID(),
      deviceUuid: input.deviceUuid,
      deviceId: input.deviceId,
      purpose: "INITIAL",
      idempotencyKey: input.idempotencyKey,
      csrFingerprintSha256: input.csrFingerprintSha256,
      sanUris: [],
      status: "PENDING",
      createdAt: input.now.toISOString(),
      updatedAt: input.now.toISOString(),
    };
    this.credentials.set(credential.credentialId, credential);
    this.audit(
      {
        deviceUuid: input.deviceUuid,
        deviceId: input.deviceId,
        credentialId: credential.credentialId,
        action: "INITIAL_ISSUANCE_RESERVED",
        actorType: "DEVICE",
        actorId: input.deviceId,
        details: { authorizationId: authorization.authorizationId },
      },
      input.now,
    );
    return { credential: clone(credential), replay: false };
  }

  async completeIssuance(input: CompleteCredentialInput) {
    const credential = this.credentials.get(input.credentialId);
    if (!credential)
      throw new DomainError(
        "CREDENTIAL_NOT_FOUND",
        404,
        "Credential not found",
      );
    if (credential.certificatePem) return clone(credential);
    Object.assign(credential, input, {
      status: "ACTIVE" as const,
      activatedAt: input.issuedAt,
      updatedAt: input.issuedAt,
    });
    this.audit(
      {
        deviceUuid: credential.deviceUuid,
        deviceId: credential.deviceId,
        credentialId: credential.credentialId,
        action: "CREDENTIAL_ISSUED",
        actorType: "SYSTEM",
        actorId: "certificate-authority-adapter",
        details: { certificateSerial: input.certificateSerial },
      },
      new Date(input.issuedAt),
    );
    return clone(credential);
  }

  async failIssuance(credentialId: string, now: Date) {
    const credential = this.credentials.get(credentialId);
    if (!credential || credential.certificatePem) return;
    credential.status = "FAILED";
    credential.revocationReason = "ISSUANCE_ERROR";
    credential.updatedAt = now.toISOString();
    this.audit(
      {
        deviceUuid: credential.deviceUuid,
        deviceId: credential.deviceId,
        credentialId,
        action: "CREDENTIAL_ISSUANCE_FAILED",
        actorType: "SYSTEM",
        actorId: "certificate-authority-adapter",
        details: {},
      },
      now,
    );
  }

  async listCredentials(deviceUuid: string) {
    return [...this.credentials.values()]
      .filter((value) => value.deviceUuid === deviceUuid)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .map(clone);
  }

  async getCredential(credentialId: string) {
    const value = this.credentials.get(credentialId);
    return value ? clone(value) : undefined;
  }

  async getCredentialByFingerprint(fingerprint: string) {
    const value = [...this.credentials.values()].find(
      (credential) => credential.fingerprintSha256 === fingerprint,
    );
    return value ? clone(value) : undefined;
  }

  async beginRotation(input: {
    deviceUuid: string;
    deviceId: string;
    requestedBy: string;
    requestKey: string;
    reason: CredentialRotationRecord["reason"];
    overlapSeconds: number;
    now: Date;
  }) {
    const replay = [...this.rotations.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid &&
        value.requestKey === input.requestKey,
    );
    if (replay) return clone(replay);
    const existing = [...this.rotations.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid &&
        ["REQUESTED", "ISSUING", "OVERLAP"].includes(value.status),
    );
    if (existing)
      throw new DomainError(
        "ROTATION_IN_PROGRESS",
        409,
        "Credential rotation is already in progress",
      );
    const current = [...this.credentials.values()].find(
      (value) =>
        value.deviceUuid === input.deviceUuid && value.status === "ACTIVE",
    );
    if (!current)
      throw new DomainError(
        "ACTIVE_CREDENTIAL_NOT_FOUND",
        409,
        "An active credential is required",
      );
    current.status = "ROTATING";
    current.updatedAt = input.now.toISOString();
    const rotation: CredentialRotationRecord = {
      rotationId: randomUUID(),
      deviceUuid: input.deviceUuid,
      deviceId: input.deviceId,
      currentCredentialId: current.credentialId,
      requestedBy: input.requestedBy,
      requestKey: input.requestKey,
      reason: input.reason,
      overlapSeconds: input.overlapSeconds,
      requestedAt: input.now.toISOString(),
      expiresAt: new Date(
        input.now.getTime() + input.overlapSeconds * 1000,
      ).toISOString(),
      status: "REQUESTED",
      createdAt: input.now.toISOString(),
      updatedAt: input.now.toISOString(),
    };
    current.rotationId = rotation.rotationId;
    this.rotations.set(rotation.rotationId, rotation);
    this.audit(
      {
        deviceUuid: input.deviceUuid,
        deviceId: input.deviceId,
        credentialId: current.credentialId,
        rotationId: rotation.rotationId,
        action: "ROTATION_STARTED",
        actorType: "HUMAN",
        actorId: input.requestedBy,
        details: { overlapSeconds: input.overlapSeconds, reason: input.reason },
      },
      input.now,
    );
    return clone(rotation);
  }

  async getRotation(rotationId: string) {
    const value = this.rotations.get(rotationId);
    return value ? clone(value) : undefined;
  }

  async reserveRotationIssuance(input: {
    rotationId: string;
    currentCredentialId: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }) {
    const rotation = this.rotations.get(input.rotationId);
    if (!rotation || rotation.currentCredentialId !== input.currentCredentialId)
      throw new DomainError("ROTATION_NOT_FOUND", 404, "Rotation not found");
    if (Date.parse(rotation.expiresAt) <= input.now.getTime()) {
      rotation.status = "EXPIRED";
      const current = this.credentials.get(rotation.currentCredentialId);
      if (current?.status === "ROTATING") current.status = "ACTIVE";
      throw new DomainError(
        "ROTATION_EXPIRED",
        410,
        "Rotation request expired",
      );
    }
    const replay = [...this.credentials.values()].find(
      (value) =>
        value.rotationId === input.rotationId &&
        value.idempotencyKey === input.idempotencyKey,
    );
    if (replay) return { credential: clone(replay), replay: true };
    if (rotation.newCredentialId)
      throw new DomainError(
        "ROTATION_CREDENTIAL_EXISTS",
        409,
        "Rotation already has a replacement credential",
      );
    const credential: DeviceCredentialRecord = {
      credentialId: randomUUID(),
      deviceUuid: rotation.deviceUuid,
      deviceId: rotation.deviceId,
      purpose: rotation.reason === "RECOVERY" ? "RECOVERY" : "ROTATION",
      idempotencyKey: input.idempotencyKey,
      csrFingerprintSha256: input.csrFingerprintSha256,
      sanUris: [],
      status: "PENDING",
      parentCredentialId: rotation.currentCredentialId,
      rotationId: rotation.rotationId,
      createdAt: input.now.toISOString(),
      updatedAt: input.now.toISOString(),
    };
    rotation.newCredentialId = credential.credentialId;
    rotation.status = "ISSUING";
    rotation.updatedAt = input.now.toISOString();
    this.credentials.set(credential.credentialId, credential);
    return { credential: clone(credential), replay: false };
  }

  async completeRotationIssuance(input: CompleteCredentialInput) {
    const credential = this.credentials.get(input.credentialId);
    if (!credential || !credential.rotationId || !credential.parentCredentialId)
      throw new DomainError(
        "ROTATION_NOT_FOUND",
        404,
        "Rotation credential not found",
      );
    if (credential.certificatePem) return clone(credential);
    Object.assign(credential, input, {
      status: "ROTATING" as const,
      updatedAt: input.issuedAt,
    });
    const parent = this.credentials.get(credential.parentCredentialId);
    if (parent) {
      parent.childCredentialId = credential.credentialId;
      parent.updatedAt = input.issuedAt;
    }
    const rotation = this.rotations.get(credential.rotationId)!;
    rotation.status = "OVERLAP";
    rotation.updatedAt = input.issuedAt;
    return clone(credential);
  }

  async recordAuthenticated(credentialId: string, now: Date) {
    const credential = this.credentials.get(credentialId);
    if (!credential) return;
    credential.lastAuthenticatedAt = now.toISOString();
    credential.updatedAt = now.toISOString();
  }

  async acknowledgeRotation(input: {
    rotationId: string;
    newCredentialId: string;
    result: "CONNECTED" | "FAILED";
    failureCode?: string;
    now: Date;
  }) {
    const rotation = this.rotations.get(input.rotationId);
    if (!rotation || rotation.newCredentialId !== input.newCredentialId)
      throw new DomainError("ROTATION_NOT_FOUND", 404, "Rotation not found");
    if (rotation.status === "COMPLETED" || rotation.status === "FAILED")
      return clone(rotation);
    const current = this.credentials.get(rotation.currentCredentialId)!;
    const replacement = this.credentials.get(input.newCredentialId)!;
    if (input.result === "CONNECTED") {
      if (!replacement.lastAuthenticatedAt)
        throw new DomainError(
          "ROTATION_CONNECTION_UNPROVEN",
          409,
          "Replacement credential has not authenticated to the broker",
        );
      replacement.status = "ACTIVE";
      replacement.activatedAt = input.now.toISOString();
      current.status = "REVOKED";
      current.revocationReason = "ROTATED";
      current.revokedAt = input.now.toISOString();
      rotation.status = "COMPLETED";
      rotation.acknowledgedAt = input.now.toISOString();
    } else {
      replacement.status = "FAILED";
      replacement.revocationReason = "ISSUANCE_ERROR";
      current.status = "ACTIVE";
      delete current.childCredentialId;
      rotation.status = "FAILED";
      rotation.failureCode = input.failureCode ?? "UNKNOWN";
    }
    current.updatedAt = input.now.toISOString();
    replacement.updatedAt = input.now.toISOString();
    rotation.updatedAt = input.now.toISOString();
    this.audit(
      {
        deviceUuid: rotation.deviceUuid,
        deviceId: rotation.deviceId,
        credentialId: replacement.credentialId,
        rotationId: rotation.rotationId,
        action:
          input.result === "CONNECTED"
            ? "ROTATION_COMPLETED"
            : "ROTATION_FAILED",
        actorType: "DEVICE",
        actorId: rotation.deviceId,
        details: input.failureCode ? { failureCode: input.failureCode } : {},
      },
      input.now,
    );
    return clone(rotation);
  }

  async revokeCredential(input: {
    credentialId: string;
    reason: RevocationReason;
    actorId: string;
    actorType: CredentialAuditRecord["actorType"];
    now: Date;
  }) {
    const credential = this.credentials.get(input.credentialId);
    if (!credential)
      throw new DomainError(
        "CREDENTIAL_NOT_FOUND",
        404,
        "Credential not found",
      );
    if (["REVOKED", "COMPROMISED", "EXPIRED"].includes(credential.status))
      return clone(credential);
    credential.status =
      input.reason === "COMPROMISED"
        ? "COMPROMISED"
        : input.reason === "EXPIRED"
          ? "EXPIRED"
          : "REVOKED";
    credential.revocationReason = input.reason;
    credential.revokedAt = input.now.toISOString();
    credential.updatedAt = input.now.toISOString();
    this.audit(
      {
        deviceUuid: credential.deviceUuid,
        deviceId: credential.deviceId,
        credentialId: credential.credentialId,
        action:
          credential.status === "COMPROMISED"
            ? "CREDENTIAL_COMPROMISED"
            : "CREDENTIAL_REVOKED",
        actorType: input.actorType,
        actorId: input.actorId,
        details: { reason: input.reason },
      },
      input.now,
    );
    return clone(credential);
  }

  async listAudit(deviceUuid: string) {
    return this.audits
      .filter((value) => value.deviceUuid === deviceUuid)
      .map(clone);
  }

  async health() {}
  async close() {}
}

function iso(value: Date | string | undefined | null) {
  return value ? new Date(value).toISOString() : undefined;
}

function credentialFromRow(
  row: Record<string, unknown>,
): DeviceCredentialRecord {
  return {
    credentialId: String(row.credential_id),
    deviceUuid: String(row.device_uuid),
    deviceId: String(row.device_id),
    purpose: row.purpose as CredentialPurpose,
    idempotencyKey: String(row.idempotency_key),
    csrFingerprintSha256: String(row.csr_fingerprint_sha256),
    ...(row.certificate_serial
      ? { certificateSerial: String(row.certificate_serial) }
      : {}),
    ...(row.fingerprint_sha256
      ? { fingerprintSha256: String(row.fingerprint_sha256) }
      : {}),
    ...(row.certificate_pem
      ? { certificatePem: String(row.certificate_pem) }
      : {}),
    ...(row.issuer_dn
      ? { issuerDistinguishedName: String(row.issuer_dn) }
      : {}),
    ...(row.subject_dn
      ? { subjectDistinguishedName: String(row.subject_dn) }
      : {}),
    sanUris: (row.san_uris as string[] | null) ?? [],
    ...(iso(row.not_before as Date | undefined)
      ? { notBefore: iso(row.not_before as Date)! }
      : {}),
    ...(iso(row.not_after as Date | undefined)
      ? { notAfter: iso(row.not_after as Date)! }
      : {}),
    ...(iso(row.issued_at as Date | undefined)
      ? { issuedAt: iso(row.issued_at as Date)! }
      : {}),
    ...(iso(row.activated_at as Date | undefined)
      ? { activatedAt: iso(row.activated_at as Date)! }
      : {}),
    ...(iso(row.revoked_at as Date | undefined)
      ? { revokedAt: iso(row.revoked_at as Date)! }
      : {}),
    ...(row.revocation_reason
      ? { revocationReason: row.revocation_reason as RevocationReason }
      : {}),
    status: row.status as CredentialStatus,
    ...(row.parent_credential_id
      ? { parentCredentialId: String(row.parent_credential_id) }
      : {}),
    ...(row.child_credential_id
      ? { childCredentialId: String(row.child_credential_id) }
      : {}),
    ...(row.rotation_id ? { rotationId: String(row.rotation_id) } : {}),
    ...(iso(row.last_authenticated_at as Date | undefined)
      ? { lastAuthenticatedAt: iso(row.last_authenticated_at as Date)! }
      : {}),
    createdAt: iso(row.created_at as Date)!,
    updatedAt: iso(row.updated_at as Date)!,
  };
}

function rotationFromRow(
  row: Record<string, unknown>,
): CredentialRotationRecord {
  return {
    rotationId: String(row.rotation_id),
    deviceUuid: String(row.device_uuid),
    deviceId: String(row.device_id),
    currentCredentialId: String(row.current_credential_id),
    ...(row.new_credential_id
      ? { newCredentialId: String(row.new_credential_id) }
      : {}),
    requestedBy: String(row.requested_by),
    requestKey: String(row.request_key),
    reason: row.reason as CredentialRotationRecord["reason"],
    overlapSeconds: Number(row.overlap_seconds),
    requestedAt: iso(row.requested_at as Date)!,
    expiresAt: iso(row.expires_at as Date)!,
    ...(iso(row.acknowledged_at as Date | undefined)
      ? { acknowledgedAt: iso(row.acknowledged_at as Date)! }
      : {}),
    status: row.status as RotationStatus,
    ...(row.failure_code ? { failureCode: String(row.failure_code) } : {}),
    createdAt: iso(row.created_at as Date)!,
    updatedAt: iso(row.updated_at as Date)!,
  };
}

export class PostgresCredentialStore implements CredentialStore {
  constructor(readonly pool: pg.Pool) {}

  private async audit(
    client: pg.PoolClient,
    input: Omit<CredentialAuditRecord, "auditId" | "occurredAt">,
    now: Date,
  ) {
    await client.query(
      `INSERT INTO credential_audit
         (audit_id, device_uuid, device_id, credential_id, rotation_id, action, actor_type, actor_id, details, occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        randomUUID(),
        input.deviceUuid,
        input.deviceId,
        input.credentialId ?? null,
        input.rotationId ?? null,
        input.action,
        input.actorType,
        input.actorId,
        input.details,
        now,
      ],
    );
  }

  async createBootstrap(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    claimSessionId?: string;
    createdBy: string;
    ttlMs: number;
    attempts: number;
    now: Date;
  }) {
    const client = await this.pool.connect();
    const token = randomBytes(32).toString("base64url");
    try {
      await client.query("BEGIN");
      const active = await client.query(
        `SELECT 1 FROM device_credentials
          WHERE device_uuid=$1 AND purpose='INITIAL' AND status IN ('PENDING','ACTIVE','ROTATING')
          LIMIT 1 FOR UPDATE`,
        [input.deviceUuid],
      );
      if (active.rowCount)
        throw new DomainError(
          "INITIAL_CREDENTIAL_EXISTS",
          409,
          "Device already has an initial credential",
        );
      await client.query(
        `UPDATE credential_bootstrap_sessions SET invalidated_at=$2
          WHERE device_uuid=$1 AND consumed_at IS NULL AND invalidated_at IS NULL`,
        [input.deviceUuid, input.now],
      );
      const authorizationId = randomUUID();
      const result = await client.query(
        `INSERT INTO credential_bootstrap_sessions
          (authorization_id, device_uuid, device_id, organization_id, ownership_version, claim_session_id, token_hash, attempts_remaining, created_by, created_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [
          authorizationId,
          input.deviceUuid,
          input.deviceId,
          input.organizationId ?? null,
          input.ownershipVersion ?? null,
          input.claimSessionId ?? null,
          secretDigest(token),
          input.attempts,
          input.createdBy,
          input.now,
          new Date(input.now.getTime() + input.ttlMs),
        ],
      );
      await this.audit(
        client,
        {
          deviceUuid: input.deviceUuid,
          deviceId: input.deviceId,
          action: "BOOTSTRAP_CREATED",
          actorType: "HUMAN",
          actorId: input.createdBy,
          details: { authorizationId },
        },
        input.now,
      );
      await client.query("COMMIT");
      const row = result.rows[0] as Record<string, unknown>;
      return {
        token,
        record: {
          authorizationId,
          deviceUuid: String(row.device_uuid),
          deviceId: String(row.device_id),
          ...(row.organization_id
            ? { organizationId: String(row.organization_id) }
            : {}),
          ...(row.ownership_version
            ? { ownershipVersion: String(row.ownership_version) }
            : {}),
          ...(row.claim_session_id
            ? { claimSessionId: String(row.claim_session_id) }
            : {}),
          ...(row.claim_session_id ? { purpose: "CSR_ISSUE" as const } : {}),
          tokenHash: String(row.token_hash),
          attemptsRemaining: Number(row.attempts_remaining),
          createdBy: String(row.created_by),
          createdAt: iso(row.created_at as Date)!,
          expiresAt: iso(row.expires_at as Date)!,
        },
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async reserveInitialIssuance(input: {
    deviceUuid: string;
    deviceId: string;
    organizationId?: string;
    ownershipVersion?: string;
    tokenHash: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const replay = await client.query(
        "SELECT * FROM device_credentials WHERE device_uuid=$1 AND idempotency_key=$2",
        [input.deviceUuid, input.idempotencyKey],
      );
      if (replay.rows[0]) {
        await client.query("COMMIT");
        return { credential: credentialFromRow(replay.rows[0]), replay: true };
      }
      const selected = await client.query(
        `SELECT * FROM credential_bootstrap_sessions
          WHERE device_uuid=$1 AND device_id=$2 AND consumed_at IS NULL AND invalidated_at IS NULL
          ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
        [input.deviceUuid, input.deviceId],
      );
      const authorization = selected.rows[0] as
        Record<string, unknown> | undefined;
      if (
        !authorization ||
        new Date(authorization.expires_at as Date).getTime() <=
          input.now.getTime()
      )
        throw new DomainError(
          "BOOTSTRAP_UNAVAILABLE",
          410,
          "Bootstrap authorization expired, used, or invalid",
        );
      if (String(authorization.token_hash) !== input.tokenHash) {
        const remaining = Number(authorization.attempts_remaining) - 1;
        await client.query(
          `UPDATE credential_bootstrap_sessions
              SET attempts_remaining=$2, invalidated_at=CASE WHEN $2 <= 0 THEN $3 ELSE invalidated_at END
            WHERE authorization_id=$1`,
          [authorization.authorization_id, remaining, input.now],
        );
        await client.query("COMMIT");
        throw new DomainError(
          "BOOTSTRAP_UNAVAILABLE",
          remaining <= 0 ? 429 : 401,
          "Bootstrap authorization expired, used, or invalid",
        );
      }
      if (
        (authorization.organization_id &&
          String(authorization.organization_id) !== input.organizationId) ||
        (authorization.ownership_version &&
          String(authorization.ownership_version) !== input.ownershipVersion)
      )
        throw new DomainError(
          "OWNERSHIP_VERSION_CHANGED",
          403,
          "Bootstrap authorization is no longer valid",
        );
      const active = await client.query(
        `SELECT 1 FROM device_credentials
          WHERE device_uuid=$1 AND purpose='INITIAL' AND status IN ('PENDING','ACTIVE','ROTATING')
          LIMIT 1 FOR UPDATE`,
        [input.deviceUuid],
      );
      if (active.rowCount)
        throw new DomainError(
          "INITIAL_CREDENTIAL_EXISTS",
          409,
          "Concurrent initial credential issuance is not allowed",
        );
      await client.query(
        "UPDATE credential_bootstrap_sessions SET consumed_at=$2 WHERE authorization_id=$1",
        [authorization.authorization_id, input.now],
      );
      const credentialId = randomUUID();
      const inserted = await client.query(
        `INSERT INTO device_credentials
          (credential_id, device_uuid, device_id, purpose, idempotency_key, csr_fingerprint_sha256, status, created_at, updated_at)
         VALUES ($1,$2,$3,'INITIAL',$4,$5,'PENDING',$6,$6) RETURNING *`,
        [
          credentialId,
          input.deviceUuid,
          input.deviceId,
          input.idempotencyKey,
          input.csrFingerprintSha256,
          input.now,
        ],
      );
      await this.audit(
        client,
        {
          deviceUuid: input.deviceUuid,
          deviceId: input.deviceId,
          credentialId,
          action: "INITIAL_ISSUANCE_RESERVED",
          actorType: "DEVICE",
          actorId: input.deviceId,
          details: { authorizationId: authorization.authorization_id },
        },
        input.now,
      );
      await client.query("COMMIT");
      return { credential: credentialFromRow(inserted.rows[0]), replay: false };
    } catch (error) {
      if ((client as unknown as { _ending?: boolean })._ending !== true)
        await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async completeIssuance(input: CompleteCredentialInput) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        `UPDATE device_credentials SET
          certificate_serial=$2, fingerprint_sha256=$3, certificate_pem=$4,
          issuer_dn=$5, subject_dn=$6, san_uris=$7, not_before=$8, not_after=$9,
          issued_at=$10, activated_at=$10, status='ACTIVE', updated_at=$10
         WHERE credential_id=$1 AND certificate_pem IS NULL RETURNING *`,
        [
          input.credentialId,
          input.certificateSerial,
          input.fingerprintSha256,
          input.certificatePem,
          input.issuerDistinguishedName,
          input.subjectDistinguishedName,
          input.sanUris,
          input.notBefore,
          input.notAfter,
          input.issuedAt,
        ],
      );
      const existing = updated.rows[0]
        ? undefined
        : await client.query(
            "SELECT * FROM device_credentials WHERE credential_id=$1",
            [input.credentialId],
          );
      const row = (updated.rows[0] ?? existing?.rows[0]) as
        Record<string, unknown> | undefined;
      if (!row)
        throw new DomainError(
          "CREDENTIAL_NOT_FOUND",
          404,
          "Credential not found",
        );
      if (updated.rows[0])
        await this.audit(
          client,
          {
            deviceUuid: String(row.device_uuid),
            deviceId: String(row.device_id),
            credentialId: input.credentialId,
            action: "CREDENTIAL_ISSUED",
            actorType: "SYSTEM",
            actorId: "certificate-authority-adapter",
            details: { certificateSerial: input.certificateSerial },
          },
          new Date(input.issuedAt),
        );
      await client.query("COMMIT");
      return credentialFromRow(row);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async failIssuance(credentialId: string, now: Date) {
    await this.pool.query(
      `UPDATE device_credentials
          SET status='FAILED', revocation_reason='ISSUANCE_ERROR', updated_at=$2
        WHERE credential_id=$1 AND certificate_pem IS NULL`,
      [credentialId, now],
    );
  }

  async listCredentials(deviceUuid: string) {
    const result = await this.pool.query(
      "SELECT * FROM device_credentials WHERE device_uuid=$1 ORDER BY created_at DESC",
      [deviceUuid],
    );
    return result.rows.map(credentialFromRow);
  }

  async getCredential(credentialId: string) {
    const result = await this.pool.query(
      "SELECT * FROM device_credentials WHERE credential_id=$1",
      [credentialId],
    );
    return result.rows[0] ? credentialFromRow(result.rows[0]) : undefined;
  }

  async getCredentialByFingerprint(fingerprint: string) {
    const result = await this.pool.query(
      "SELECT * FROM device_credentials WHERE fingerprint_sha256=$1",
      [fingerprint],
    );
    return result.rows[0] ? credentialFromRow(result.rows[0]) : undefined;
  }

  async beginRotation(input: {
    deviceUuid: string;
    deviceId: string;
    requestedBy: string;
    requestKey: string;
    reason: CredentialRotationRecord["reason"];
    overlapSeconds: number;
    now: Date;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const replay = await client.query(
        "SELECT * FROM credential_rotations WHERE device_uuid=$1 AND request_key=$2",
        [input.deviceUuid, input.requestKey],
      );
      if (replay.rows[0]) {
        await client.query("COMMIT");
        return rotationFromRow(replay.rows[0]);
      }
      const ongoing = await client.query(
        `SELECT 1 FROM credential_rotations
          WHERE device_uuid=$1 AND status IN ('REQUESTED','ISSUING','OVERLAP') LIMIT 1 FOR UPDATE`,
        [input.deviceUuid],
      );
      if (ongoing.rowCount)
        throw new DomainError(
          "ROTATION_IN_PROGRESS",
          409,
          "Credential rotation is already in progress",
        );
      const active = await client.query(
        "SELECT * FROM device_credentials WHERE device_uuid=$1 AND status='ACTIVE' FOR UPDATE",
        [input.deviceUuid],
      );
      const current = active.rows[0] as Record<string, unknown> | undefined;
      if (!current)
        throw new DomainError(
          "ACTIVE_CREDENTIAL_NOT_FOUND",
          409,
          "An active credential is required",
        );
      const rotationId = randomUUID();
      const expiresAt = new Date(
        input.now.getTime() + input.overlapSeconds * 1000,
      );
      const inserted = await client.query(
        `INSERT INTO credential_rotations
          (rotation_id, device_uuid, device_id, current_credential_id, requested_by, request_key, reason,
           overlap_seconds, requested_at, expires_at, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'REQUESTED',$9,$9) RETURNING *`,
        [
          rotationId,
          input.deviceUuid,
          input.deviceId,
          current.credential_id,
          input.requestedBy,
          input.requestKey,
          input.reason,
          input.overlapSeconds,
          input.now,
          expiresAt,
        ],
      );
      await client.query(
        "UPDATE device_credentials SET status='ROTATING', rotation_id=$2, updated_at=$3 WHERE credential_id=$1",
        [current.credential_id, rotationId, input.now],
      );
      await this.audit(
        client,
        {
          deviceUuid: input.deviceUuid,
          deviceId: input.deviceId,
          credentialId: String(current.credential_id),
          rotationId,
          action: "ROTATION_STARTED",
          actorType: "HUMAN",
          actorId: input.requestedBy,
          details: {
            overlapSeconds: input.overlapSeconds,
            reason: input.reason,
          },
        },
        input.now,
      );
      await client.query("COMMIT");
      return rotationFromRow(inserted.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async getRotation(rotationId: string) {
    const result = await this.pool.query(
      "SELECT * FROM credential_rotations WHERE rotation_id=$1",
      [rotationId],
    );
    return result.rows[0] ? rotationFromRow(result.rows[0]) : undefined;
  }

  async reserveRotationIssuance(input: {
    rotationId: string;
    currentCredentialId: string;
    idempotencyKey: string;
    csrFingerprintSha256: string;
    now: Date;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const rotationResult = await client.query(
        "SELECT * FROM credential_rotations WHERE rotation_id=$1 FOR UPDATE",
        [input.rotationId],
      );
      const rotation = rotationResult.rows[0] as
        Record<string, unknown> | undefined;
      if (
        !rotation ||
        String(rotation.current_credential_id) !== input.currentCredentialId
      )
        throw new DomainError("ROTATION_NOT_FOUND", 404, "Rotation not found");
      if (
        new Date(rotation.expires_at as Date).getTime() <= input.now.getTime()
      ) {
        await client.query(
          "UPDATE credential_rotations SET status='EXPIRED', updated_at=$2 WHERE rotation_id=$1",
          [input.rotationId, input.now],
        );
        await client.query(
          "UPDATE device_credentials SET status='ACTIVE', updated_at=$2 WHERE credential_id=$1 AND status='ROTATING'",
          [input.currentCredentialId, input.now],
        );
        await client.query("COMMIT");
        throw new DomainError(
          "ROTATION_EXPIRED",
          410,
          "Rotation request expired",
        );
      }
      const replay = await client.query(
        "SELECT * FROM device_credentials WHERE rotation_id=$1 AND idempotency_key=$2",
        [input.rotationId, input.idempotencyKey],
      );
      if (replay.rows[0]) {
        await client.query("COMMIT");
        return { credential: credentialFromRow(replay.rows[0]), replay: true };
      }
      if (rotation.new_credential_id)
        throw new DomainError(
          "ROTATION_CREDENTIAL_EXISTS",
          409,
          "Rotation already has a replacement credential",
        );
      const credentialId = randomUUID();
      const inserted = await client.query(
        `INSERT INTO device_credentials
          (credential_id, device_uuid, device_id, purpose, idempotency_key, csr_fingerprint_sha256,
           status, parent_credential_id, rotation_id, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,'PENDING',$7,$8,$9,$9) RETURNING *`,
        [
          credentialId,
          rotation.device_uuid,
          rotation.device_id,
          rotation.reason === "RECOVERY" ? "RECOVERY" : "ROTATION",
          input.idempotencyKey,
          input.csrFingerprintSha256,
          input.currentCredentialId,
          input.rotationId,
          input.now,
        ],
      );
      await client.query(
        "UPDATE credential_rotations SET new_credential_id=$2, status='ISSUING', updated_at=$3 WHERE rotation_id=$1",
        [input.rotationId, credentialId, input.now],
      );
      await client.query("COMMIT");
      return { credential: credentialFromRow(inserted.rows[0]), replay: false };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async completeRotationIssuance(input: CompleteCredentialInput) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        `UPDATE device_credentials SET
          certificate_serial=$2, fingerprint_sha256=$3, certificate_pem=$4,
          issuer_dn=$5, subject_dn=$6, san_uris=$7, not_before=$8, not_after=$9,
          issued_at=$10, status='ROTATING', updated_at=$10
         WHERE credential_id=$1 AND certificate_pem IS NULL RETURNING *`,
        [
          input.credentialId,
          input.certificateSerial,
          input.fingerprintSha256,
          input.certificatePem,
          input.issuerDistinguishedName,
          input.subjectDistinguishedName,
          input.sanUris,
          input.notBefore,
          input.notAfter,
          input.issuedAt,
        ],
      );
      const existing = updated.rows[0]
        ? undefined
        : await client.query(
            "SELECT * FROM device_credentials WHERE credential_id=$1",
            [input.credentialId],
          );
      const row = (updated.rows[0] ?? existing?.rows[0]) as
        Record<string, unknown> | undefined;
      if (!row || !row.rotation_id || !row.parent_credential_id)
        throw new DomainError(
          "ROTATION_NOT_FOUND",
          404,
          "Rotation credential not found",
        );
      await client.query(
        "UPDATE device_credentials SET child_credential_id=$2, updated_at=$3 WHERE credential_id=$1",
        [row.parent_credential_id, input.credentialId, input.issuedAt],
      );
      await client.query(
        "UPDATE credential_rotations SET status='OVERLAP', updated_at=$2 WHERE rotation_id=$1",
        [row.rotation_id, input.issuedAt],
      );
      await client.query("COMMIT");
      return credentialFromRow(row);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async recordAuthenticated(credentialId: string, now: Date) {
    await this.pool.query(
      "UPDATE device_credentials SET last_authenticated_at=$2, updated_at=$2 WHERE credential_id=$1",
      [credentialId, now],
    );
  }

  async acknowledgeRotation(input: {
    rotationId: string;
    newCredentialId: string;
    result: "CONNECTED" | "FAILED";
    failureCode?: string;
    now: Date;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const selected = await client.query(
        "SELECT * FROM credential_rotations WHERE rotation_id=$1 FOR UPDATE",
        [input.rotationId],
      );
      const rotation = selected.rows[0] as Record<string, unknown> | undefined;
      if (
        !rotation ||
        String(rotation.new_credential_id) !== input.newCredentialId
      )
        throw new DomainError("ROTATION_NOT_FOUND", 404, "Rotation not found");
      if (["COMPLETED", "FAILED"].includes(String(rotation.status))) {
        await client.query("COMMIT");
        return rotationFromRow(rotation);
      }
      const replacementResult = await client.query(
        "SELECT * FROM device_credentials WHERE credential_id=$1 FOR UPDATE",
        [input.newCredentialId],
      );
      const replacement = replacementResult.rows[0] as Record<string, unknown>;
      if (input.result === "CONNECTED") {
        if (!replacement.last_authenticated_at)
          throw new DomainError(
            "ROTATION_CONNECTION_UNPROVEN",
            409,
            "Replacement credential has not authenticated to the broker",
          );
        await client.query(
          "UPDATE device_credentials SET status='ACTIVE', activated_at=$2, updated_at=$2 WHERE credential_id=$1",
          [input.newCredentialId, input.now],
        );
        await client.query(
          `UPDATE device_credentials SET status='REVOKED', revocation_reason='ROTATED', revoked_at=$2, updated_at=$2
            WHERE credential_id=$1`,
          [rotation.current_credential_id, input.now],
        );
        await client.query(
          "UPDATE credential_rotations SET status='COMPLETED', acknowledged_at=$2, updated_at=$2 WHERE rotation_id=$1",
          [input.rotationId, input.now],
        );
      } else {
        await client.query(
          "UPDATE device_credentials SET status='FAILED', revocation_reason='ISSUANCE_ERROR', updated_at=$2 WHERE credential_id=$1",
          [input.newCredentialId, input.now],
        );
        await client.query(
          "UPDATE device_credentials SET status='ACTIVE', child_credential_id=NULL, updated_at=$2 WHERE credential_id=$1",
          [rotation.current_credential_id, input.now],
        );
        await client.query(
          "UPDATE credential_rotations SET status='FAILED', failure_code=$2, updated_at=$3 WHERE rotation_id=$1",
          [input.rotationId, input.failureCode ?? "UNKNOWN", input.now],
        );
      }
      await this.audit(
        client,
        {
          deviceUuid: String(rotation.device_uuid),
          deviceId: String(rotation.device_id),
          credentialId: input.newCredentialId,
          rotationId: input.rotationId,
          action:
            input.result === "CONNECTED"
              ? "ROTATION_COMPLETED"
              : "ROTATION_FAILED",
          actorType: "DEVICE",
          actorId: String(rotation.device_id),
          details: input.failureCode ? { failureCode: input.failureCode } : {},
        },
        input.now,
      );
      const result = await client.query(
        "SELECT * FROM credential_rotations WHERE rotation_id=$1",
        [input.rotationId],
      );
      await client.query("COMMIT");
      return rotationFromRow(result.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async revokeCredential(input: {
    credentialId: string;
    reason: RevocationReason;
    actorId: string;
    actorType: CredentialAuditRecord["actorType"];
    now: Date;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const selected = await client.query(
        "SELECT * FROM device_credentials WHERE credential_id=$1 FOR UPDATE",
        [input.credentialId],
      );
      const row = selected.rows[0] as Record<string, unknown> | undefined;
      if (!row)
        throw new DomainError(
          "CREDENTIAL_NOT_FOUND",
          404,
          "Credential not found",
        );
      if (!["REVOKED", "COMPROMISED", "EXPIRED"].includes(String(row.status))) {
        const status =
          input.reason === "COMPROMISED"
            ? "COMPROMISED"
            : input.reason === "EXPIRED"
              ? "EXPIRED"
              : "REVOKED";
        const updated = await client.query(
          `UPDATE device_credentials SET status=$2, revocation_reason=$3, revoked_at=$4, updated_at=$4
            WHERE credential_id=$1 RETURNING *`,
          [input.credentialId, status, input.reason, input.now],
        );
        Object.assign(row, updated.rows[0]);
        await this.audit(
          client,
          {
            deviceUuid: String(row.device_uuid),
            deviceId: String(row.device_id),
            credentialId: input.credentialId,
            action:
              status === "COMPROMISED"
                ? "CREDENTIAL_COMPROMISED"
                : "CREDENTIAL_REVOKED",
            actorType: input.actorType,
            actorId: input.actorId,
            details: { reason: input.reason },
          },
          input.now,
        );
      }
      await client.query("COMMIT");
      return credentialFromRow(row);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async listAudit(deviceUuid: string) {
    const result = await this.pool.query(
      "SELECT * FROM credential_audit WHERE device_uuid=$1 ORDER BY occurred_at, audit_id",
      [deviceUuid],
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      auditId: String(row.audit_id),
      deviceUuid: String(row.device_uuid),
      deviceId: String(row.device_id),
      ...(row.credential_id ? { credentialId: String(row.credential_id) } : {}),
      ...(row.rotation_id ? { rotationId: String(row.rotation_id) } : {}),
      action: String(row.action),
      actorType: row.actor_type as CredentialAuditRecord["actorType"],
      actorId: String(row.actor_id),
      details: row.details as Record<string, unknown>,
      occurredAt: iso(row.occurred_at as Date)!,
    }));
  }

  async health() {
    await this.pool.query("SELECT 1");
  }

  async close() {}
}
