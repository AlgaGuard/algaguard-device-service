import { createHash, timingSafeEqual } from "node:crypto";
import type { CertificateAuthorityAdapter } from "./credential-ca.js";
import type {
  CredentialAuditRecord,
  CredentialRotationRecord,
  CredentialStore,
  DeviceCredentialRecord,
  RevocationReason,
  CredentialStatus,
} from "./credential-store.js";
import {
  DomainError,
  type DeviceRecord,
  type DeviceRepository,
  secretDigest,
} from "./domain.js";

export interface BrokerSessionAdapter {
  disconnectClient(deviceId: string): Promise<void>;
}

export class NoopBrokerSessionAdapter implements BrokerSessionAdapter {
  async disconnectClient() {}
}

export class HttpBrokerSessionAdapter implements BrokerSessionAdapter {
  constructor(
    private readonly baseUrl: string,
    private readonly authorization: string,
  ) {}

  async disconnectClient(deviceId: string) {
    const response = await fetch(
      `${this.baseUrl.replace(/\/$/, "")}/api/v5/clients/${encodeURIComponent(deviceId)}`,
      {
        method: "DELETE",
        headers: { authorization: this.authorization },
        signal: AbortSignal.timeout(3_000),
      },
    );
    if (!response.ok && response.status !== 404)
      throw new Error(`Broker disconnect failed with ${response.status}`);
  }
}

export interface CredentialServiceOptions {
  bootstrapTtlMs: number;
  bootstrapAttempts: number;
  certificateValidityDays: number;
  rotationOverlapSeconds: number;
  brokerHost: string;
  brokerPort: number;
  brokerServerName: string;
  brokerKeepAliveSeconds: number;
  brokerSessionExpirySeconds: number;
  brokerAuthCacheSeconds: number;
  revocationEffectiveWithinSeconds: number;
}

export interface CredentialMetrics {
  mtlsAccepted: number;
  credentialMismatch: number;
  revokedOrExpired: number;
  inactiveDevice: number;
}

const schema = {
  metadata: "urn:algaguard:schema:onboarding:device-credential-metadata:v1",
  issuance: "urn:algaguard:schema:onboarding:credential-issuance:v1",
  bootstrap: "urn:algaguard:schema:onboarding:bootstrap-authorization:v1",
  status: "urn:algaguard:schema:onboarding:credential-status:v1",
  rotation: "urn:algaguard:schema:onboarding:credential-rotation-request:v1",
  revocation: "urn:algaguard:schema:onboarding:credential-revocation-status:v1",
} as const;

function csrFingerprint(csrPem: string) {
  return createHash("sha256").update(csrPem).digest("hex");
}

function safeEqual(left: string, right: string) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function assertCredentialEligibleDevice(device: DeviceRecord | undefined) {
  if (!device)
    throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
  if (device.lifecycle === "UNCLAIMED")
    throw new DomainError(
      "DEVICE_UNCLAIMED",
      409,
      "Device must be claimed before credential issuance",
    );
  if (device.lifecycle === "INACTIVE")
    throw new DomainError("DEVICE_INACTIVE", 409, "Device is inactive");
  if (device.lifecycle === "REVOKED")
    throw new DomainError("DEVICE_REVOKED", 410, "Device is revoked");
  if (!["CLAIMED", "PROVISIONED", "ACTIVE"].includes(device.lifecycle))
    throw new DomainError(
      "DEVICE_NOT_ACTIVE",
      409,
      "Device is not eligible for credentials",
    );
  return device;
}

function requireIssued(credential: DeviceCredentialRecord) {
  if (
    !credential.certificateSerial ||
    !credential.fingerprintSha256 ||
    !credential.certificatePem ||
    !credential.issuerDistinguishedName ||
    !credential.subjectDistinguishedName ||
    !credential.notBefore ||
    !credential.notAfter ||
    !credential.issuedAt
  )
    throw new DomainError(
      credential.status === "FAILED"
        ? "ISSUANCE_FAILED"
        : "ISSUANCE_IN_PROGRESS",
      409,
      "Credential issuance is not complete",
    );
  return credential as DeviceCredentialRecord & {
    certificateSerial: string;
    fingerprintSha256: string;
    certificatePem: string;
    issuerDistinguishedName: string;
    subjectDistinguishedName: string;
    notBefore: string;
    notAfter: string;
    issuedAt: string;
  };
}

function publicMetadata(credential: DeviceCredentialRecord) {
  return {
    schema: schema.metadata,
    schemaVersion: "1.0.0" as const,
    credentialId: credential.credentialId,
    deviceUuid: credential.deviceUuid,
    deviceId: credential.deviceId,
    certificateSerial: credential.certificateSerial ?? null,
    fingerprintSha256: credential.fingerprintSha256 ?? null,
    certificatePem: credential.certificatePem ?? null,
    issuerDistinguishedName: credential.issuerDistinguishedName ?? null,
    subjectDistinguishedName: credential.subjectDistinguishedName ?? null,
    sanUris: credential.sanUris,
    notBefore: credential.notBefore ?? null,
    notAfter: credential.notAfter ?? null,
    issuedAt: credential.issuedAt ?? null,
    activatedAt: credential.activatedAt ?? null,
    revokedAt: credential.revokedAt ?? null,
    revocationReason: credential.revocationReason ?? null,
    status: credential.status,
    parentCredentialId: credential.parentCredentialId ?? null,
    childCredentialId: credential.childCredentialId ?? null,
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt,
  };
}

export class DeviceCredentialService {
  private readonly metrics: CredentialMetrics = {
    mtlsAccepted: 0,
    credentialMismatch: 0,
    revokedOrExpired: 0,
    inactiveDevice: 0,
  };

  constructor(
    private readonly devices: DeviceRepository,
    private readonly store: CredentialStore,
    private readonly ca: CertificateAuthorityAdapter,
    private readonly broker: BrokerSessionAdapter,
    private readonly options: CredentialServiceOptions,
  ) {}

  getMetrics() {
    return { ...this.metrics };
  }

  async createBootstrap(deviceUuid: string, actorId: string, now = new Date()) {
    const device = assertCredentialEligibleDevice(
      await this.devices.getDevice(deviceUuid),
    );
    const created = await this.store.createBootstrap({
      deviceUuid: device.deviceUuid,
      deviceId: device.deviceId,
      createdBy: actorId,
      ttlMs: this.options.bootstrapTtlMs,
      attempts: this.options.bootstrapAttempts,
      now,
    });
    return {
      schema: schema.bootstrap,
      schemaVersion: "1.0.0" as const,
      authorizationId: created.record.authorizationId,
      deviceUuid: created.record.deviceUuid,
      deviceId: created.record.deviceId,
      bootstrapToken: created.token,
      createdAt: created.record.createdAt,
      expiresAt: created.record.expiresAt,
      attemptsRemaining: created.record.attemptsRemaining,
      consumedAt: null,
    };
  }

  private async issue(
    credential: DeviceCredentialRecord,
    csrPem: string,
    complete: (
      input: Parameters<CredentialStore["completeIssuance"]>[0],
    ) => Promise<DeviceCredentialRecord>,
  ) {
    if (credential.certificatePem)
      return this.issuanceResponse(
        requireIssued(credential),
        await this.ca.getCaChain(),
      );
    try {
      const issued = await this.ca.issueClientCertificate({
        csrPem,
        deviceUuid: credential.deviceUuid,
        deviceId: credential.deviceId,
        validityDays: this.options.certificateValidityDays,
      });
      const completed = await complete({
        credentialId: credential.credentialId,
        certificateSerial: issued.certificateSerial,
        fingerprintSha256: issued.fingerprintSha256,
        certificatePem: issued.certificatePem,
        issuerDistinguishedName: issued.issuerDistinguishedName,
        subjectDistinguishedName: issued.subjectDistinguishedName,
        sanUris: issued.sanUris,
        notBefore: issued.notBefore,
        notAfter: issued.notAfter,
        issuedAt: new Date().toISOString(),
      });
      if (completed.purpose === "INITIAL")
        await this.devices.activateDevice(
          completed.deviceId,
          completed.credentialId,
          "CREDENTIAL_ISSUED",
        );
      return this.issuanceResponse(requireIssued(completed), issued.caChainPem);
    } catch (error) {
      await this.store.failIssuance(credential.credentialId, new Date());
      throw error;
    }
  }

  async issueInitial(input: {
    token: string;
    deviceUuid: string;
    deviceId: string;
    idempotencyKey: string;
    keyAlgorithm: "EC_P256" | "RSA_3072";
    csrPem: string;
  }) {
    const device = assertCredentialEligibleDevice(
      await this.devices.getDevice(input.deviceUuid),
    );
    if (device.deviceId !== input.deviceId)
      throw new DomainError(
        "DEVICE_IDENTITY_MISMATCH",
        400,
        "Device identifiers do not agree",
      );
    const reserved = await this.store.reserveInitialIssuance({
      deviceUuid: input.deviceUuid,
      deviceId: input.deviceId,
      tokenHash: secretDigest(input.token),
      idempotencyKey: input.idempotencyKey,
      csrFingerprintSha256: csrFingerprint(input.csrPem),
      now: new Date(),
    });
    if (
      reserved.replay &&
      reserved.credential.csrFingerprintSha256 !== csrFingerprint(input.csrPem)
    )
      throw new DomainError(
        "IDEMPOTENCY_CONFLICT",
        409,
        "Idempotency key was used with another CSR",
      );
    try {
      const inspected = await this.ca.inspectCertificateSigningRequest(
        input.csrPem,
      );
      if (inspected.keyAlgorithm !== input.keyAlgorithm)
        throw new DomainError(
          "CSR_ALGORITHM_MISMATCH",
          400,
          "Declared CSR algorithm does not match",
        );
      if (
        inspected.subjectCommonName !== input.deviceId ||
        inspected.sanUris.length !== 1 ||
        inspected.sanUris[0] !== `urn:algaguard:device:${input.deviceUuid}`
      )
        throw new DomainError(
          "CSR_IDENTITY_MISMATCH",
          400,
          "CSR identity does not match the device",
        );
    } catch (error) {
      await this.store.failIssuance(
        reserved.credential.credentialId,
        new Date(),
      );
      throw error;
    }
    return this.issue(reserved.credential, input.csrPem, (value) =>
      this.store.completeIssuance(value),
    );
  }

  private issuanceResponse(
    credential: ReturnType<typeof requireIssued>,
    caChainPem: string[],
  ) {
    return {
      schema: schema.issuance,
      schemaVersion: "1.0.0" as const,
      credential: publicMetadata(credential),
      caChainPem,
      broker: {
        host: this.options.brokerHost,
        port: this.options.brokerPort,
        serverName: this.options.brokerServerName,
        tlsRequired: true as const,
        keepAliveSeconds: this.options.brokerKeepAliveSeconds,
        sessionExpirySeconds: this.options.brokerSessionExpirySeconds,
      },
    };
  }

  async listCredentials(deviceUuid: string) {
    return (await this.store.listCredentials(deviceUuid)).map(publicMetadata);
  }

  async listAudit(deviceUuid: string): Promise<CredentialAuditRecord[]> {
    return this.store.listAudit(deviceUuid);
  }

  async credentialStatus(deviceUuid: string, now = new Date()) {
    const device = assertCredentialEligibleDevice(
      await this.devices.getDevice(deviceUuid),
    );
    const credentials = await this.store.listCredentials(deviceUuid);
    const live = credentials.filter((value) =>
      ["ACTIVE", "ROTATING"].includes(value.status),
    );
    const rotation = credentials.map((value) => value.rotationId).find(Boolean);
    const rotationRecord = rotation
      ? await this.store.getRotation(rotation)
      : undefined;
    const status: CredentialStatus =
      live.find((value) => value.status === "ROTATING")?.status ??
      live.find((value) => value.status === "ACTIVE")?.status ??
      credentials[0]?.status ??
      "PENDING";
    return {
      schema: schema.status,
      schemaVersion: "1.0.0" as const,
      deviceUuid: device.deviceUuid,
      deviceId: device.deviceId,
      lifecycleStatus: status,
      activeCredentialIds: live.map((value) => value.credentialId).slice(0, 2),
      rotationId: rotationRecord?.rotationId ?? null,
      rotationExpiresAt: rotationRecord?.expiresAt ?? null,
      recoveryRequired: credentials[0]?.status === "FAILED",
      updatedAt: now.toISOString(),
    };
  }

  async beginRotation(input: {
    deviceUuid: string;
    actorId: string;
    requestKey: string;
    reason: CredentialRotationRecord["reason"];
    overlapSeconds?: number;
    now?: Date;
  }) {
    const device = assertCredentialEligibleDevice(
      await this.devices.getDevice(input.deviceUuid),
    );
    if (device.lifecycle !== "ACTIVE" && device.lifecycle !== "PROVISIONED")
      throw new DomainError(
        "DEVICE_NOT_ACTIVE",
        409,
        "Device must be active before rotation",
      );
    const now = input.now ?? new Date();
    const rotation = await this.store.beginRotation({
      deviceUuid: device.deviceUuid,
      deviceId: device.deviceId,
      requestedBy: input.actorId,
      requestKey: input.requestKey,
      reason: input.reason,
      overlapSeconds:
        input.overlapSeconds ?? this.options.rotationOverlapSeconds,
      now,
    });
    return {
      schema: schema.rotation,
      schemaVersion: "1.0.0" as const,
      rotationId: rotation.rotationId,
      deviceUuid: rotation.deviceUuid,
      deviceId: rotation.deviceId,
      currentCredentialId: rotation.currentCredentialId,
      requestedAt: rotation.requestedAt,
      expiresAt: rotation.expiresAt,
      overlapSeconds: rotation.overlapSeconds,
      reason: rotation.reason,
    };
  }

  async issueRotation(input: {
    rotationId: string;
    currentCertificatePem: string;
    idempotencyKey: string;
    keyAlgorithm: "EC_P256" | "RSA_3072";
    csrPem: string;
  }) {
    const currentInspection = await this.ca.inspectCertificate(
      input.currentCertificatePem,
    );
    const current = await this.store.getCredentialByFingerprint(
      currentInspection.fingerprintSha256,
    );
    if (
      !current ||
      current.status !== "ROTATING" ||
      current.rotationId !== input.rotationId
    )
      throw new DomainError(
        "CURRENT_CREDENTIAL_INVALID",
        401,
        "Current credential is not eligible for rotation",
      );
    if (
      current.deviceId !== currentInspection.subjectCommonName ||
      currentInspection.sanUris.length !== 1 ||
      currentInspection.sanUris[0] !==
        `urn:algaguard:device:${current.deviceUuid}`
    )
      throw new DomainError(
        "CURRENT_CREDENTIAL_INVALID",
        401,
        "Current certificate identity is invalid",
      );
    const inspected = await this.ca.inspectCertificateSigningRequest(
      input.csrPem,
    );
    if (
      inspected.keyAlgorithm !== input.keyAlgorithm ||
      inspected.subjectCommonName !== current.deviceId ||
      inspected.sanUris.length !== 1 ||
      inspected.sanUris[0] !== `urn:algaguard:device:${current.deviceUuid}`
    )
      throw new DomainError(
        "CSR_IDENTITY_MISMATCH",
        400,
        "Replacement CSR does not match the device",
      );
    const reserved = await this.store.reserveRotationIssuance({
      rotationId: input.rotationId,
      currentCredentialId: current.credentialId,
      idempotencyKey: input.idempotencyKey,
      csrFingerprintSha256: csrFingerprint(input.csrPem),
      now: new Date(),
    });
    if (
      reserved.replay &&
      reserved.credential.csrFingerprintSha256 !== csrFingerprint(input.csrPem)
    )
      throw new DomainError(
        "IDEMPOTENCY_CONFLICT",
        409,
        "Idempotency key was used with another CSR",
      );
    return this.issue(reserved.credential, input.csrPem, (value) =>
      this.store.completeRotationIssuance(value),
    );
  }

  async acknowledgeRotation(input: {
    rotationId: string;
    newCredentialId: string;
    result: "CONNECTED" | "FAILED";
    failureCode?: string;
    now?: Date;
  }) {
    const rotation = await this.store.acknowledgeRotation({
      ...input,
      now: input.now ?? new Date(),
    });
    if (rotation.status === "COMPLETED") {
      const oldCredential = await this.store.getCredential(
        rotation.currentCredentialId,
      );
      if (oldCredential?.certificateSerial)
        await this.ca
          .revokeCertificate({
            certificateSerial: oldCredential.certificateSerial,
            reason: "ROTATED",
            revokedAt: rotation.acknowledgedAt!,
          })
          .catch(() => undefined);
      await this.broker
        .disconnectClient(rotation.deviceId)
        .catch(() => undefined);
    }
    return this.credentialStatus(rotation.deviceUuid, input.now ?? new Date());
  }

  async revoke(input: {
    deviceUuid: string;
    credentialId: string;
    reason: RevocationReason;
    actorId: string;
    actorType?: CredentialAuditRecord["actorType"];
    now?: Date;
  }) {
    const current = await this.store.getCredential(input.credentialId);
    if (!current || current.deviceUuid !== input.deviceUuid)
      throw new DomainError(
        "CREDENTIAL_NOT_FOUND",
        404,
        "Credential not found",
      );
    const now = input.now ?? new Date();
    const revoked = await this.store.revokeCredential({
      credentialId: input.credentialId,
      reason: input.reason,
      actorId: input.actorId,
      actorType: input.actorType ?? "HUMAN",
      now,
    });
    if (revoked.certificateSerial)
      await this.ca
        .revokeCertificate({
          certificateSerial: revoked.certificateSerial,
          reason: input.reason,
          revokedAt: now.toISOString(),
        })
        .catch(() => undefined);
    await this.broker.disconnectClient(revoked.deviceId).catch(() => undefined);
    return {
      schema: schema.revocation,
      schemaVersion: "1.0.0" as const,
      credentialId: revoked.credentialId,
      deviceUuid: revoked.deviceUuid,
      deviceId: revoked.deviceId,
      status: revoked.status,
      revokedAt: revoked.revokedAt ?? now.toISOString(),
      revocationReason: revoked.revocationReason ?? input.reason,
      effectiveWithinSeconds: this.options.revocationEffectiveWithinSeconds,
      updatedAt: revoked.updatedAt,
    };
  }

  private acl(deviceId: string) {
    const root = `algaguard/v1/devices/${deviceId}`;
    return [
      ...[
        "telemetry",
        "health",
        "status",
        "command-results",
        "configuration/ack",
        "ota/status",
      ].map((suffix) => ({
        permission: "allow",
        action: "publish",
        topic: `${root}/${suffix}`,
        qos: [1],
      })),
      ...["telemetry/ack", "commands", "configuration", "ota"].map(
        (suffix) => ({
          permission: "allow",
          action: "subscribe",
          topic: `${root}/${suffix}`,
          qos: [1],
        }),
      ),
      { permission: "deny", action: "all", topic: "#" },
    ];
  }

  async authenticateBroker(
    input: { clientId: string; certificatePem: string },
    now = new Date(),
  ) {
    try {
      const inspected = await this.ca.inspectCertificate(input.certificatePem);
      const credential = await this.store.getCredentialByFingerprint(
        inspected.fingerprintSha256,
      );
      if (
        !credential ||
        credential.deviceId !== input.clientId ||
        credential.deviceId !== inspected.subjectCommonName ||
        credential.fingerprintSha256 !== inspected.fingerprintSha256 ||
        credential.certificateSerial !== inspected.certificateSerial ||
        inspected.sanUris.length !== 1 ||
        inspected.sanUris[0] !== `urn:algaguard:device:${credential.deviceUuid}`
      ) {
        this.metrics.credentialMismatch += 1;
        return { result: "deny", is_superuser: false } as const;
      }
      if (!["ACTIVE", "ROTATING"].includes(credential.status)) {
        this.metrics.revokedOrExpired += 1;
        return { result: "deny", is_superuser: false } as const;
      }
      if (
        Date.parse(credential.notBefore!) > now.getTime() ||
        Date.parse(credential.notAfter!) <= now.getTime()
      ) {
        this.metrics.revokedOrExpired += 1;
        if (Date.parse(credential.notAfter!) <= now.getTime())
          await this.store.revokeCredential({
            credentialId: credential.credentialId,
            reason: "EXPIRED",
            actorId: "broker-authenticator",
            actorType: "SYSTEM",
            now,
          });
        return { result: "deny", is_superuser: false } as const;
      }
      if (credential.status === "ROTATING" && credential.rotationId) {
        const rotation = await this.store.getRotation(credential.rotationId);
        if (
          !rotation ||
          !["REQUESTED", "ISSUING", "OVERLAP"].includes(rotation.status) ||
          Date.parse(rotation.expiresAt) <= now.getTime()
        ) {
          this.metrics.revokedOrExpired += 1;
          return { result: "deny", is_superuser: false } as const;
        }
      }
      const device = await this.devices.getDevice(credential.deviceUuid);
      if (!device || !["ACTIVE", "PROVISIONED"].includes(device.lifecycle)) {
        this.metrics.inactiveDevice += 1;
        return { result: "deny", is_superuser: false } as const;
      }
      await this.ca.validateIssuedCertificate({
        certificatePem: input.certificatePem,
        deviceUuid: credential.deviceUuid,
        deviceId: credential.deviceId,
      });
      await this.store.recordAuthenticated(credential.credentialId, now);
      this.metrics.mtlsAccepted += 1;
      return {
        result: "allow",
        is_superuser: false,
        expire_at: Math.floor(
          Math.min(
            Date.parse(credential.notAfter!),
            now.getTime() + this.options.brokerAuthCacheSeconds * 1000,
          ) / 1000,
        ),
        client_attrs: {
          device_uuid: credential.deviceUuid,
          credential_id: credential.credentialId,
        },
        acl: this.acl(credential.deviceId),
      } as const;
    } catch {
      this.metrics.credentialMismatch += 1;
      return { result: "deny", is_superuser: false } as const;
    }
  }
}

export function createStaticBrokerAuthenticator(expectedToken: string) {
  const expectedDigest = secretDigest(expectedToken);
  return (authorization: string | undefined) => {
    const supplied = authorization?.match(/^Bearer (.+)$/)?.[1];
    if (!supplied || !safeEqual(secretDigest(supplied), expectedDigest))
      throw new DomainError(
        "SERVICE_TOKEN_REQUIRED",
        403,
        "Broker service token required",
      );
  };
}
