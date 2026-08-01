import {
  createHash,
  createPrivateKey,
  sign,
  type KeyObject,
} from "node:crypto";
import {
  CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
  DomainError,
  type BootstrapSession,
  type DeviceRepository,
} from "./domain.js";

export const QR_ONBOARDING_URI_LENGTH = 49;
export const QR_ONBOARDING_MAX_LIFETIME_SECONDS = 300;

export interface QrOnboardingInvitation {
  version: 1;
  deviceId: string;
  nonce: Buffer;
  issuedAt: number;
  expiresAt: number;
  capabilityVersion: 1;
}

function crc16(bytes: Uint8Array) {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1)
      crc =
        (crc & 0x8000) !== 0
          ? ((crc << 1) ^ 0x1021) & 0xffff
          : (crc << 1) & 0xffff;
  }
  return crc;
}

export function decodeQrOnboardingInvitation(
  uri: string,
): QrOnboardingInvitation {
  if (
    !/^ag:\/\/q\/[A-Za-z0-9_-]{42}$/.test(uri) ||
    uri.length !== QR_ONBOARDING_URI_LENGTH
  )
    throw new DomainError(
      "QR_INVITATION_INVALID",
      400,
      "Invitation is invalid",
    );
  const bytes = Buffer.from(uri.slice(7), "base64url");
  if (bytes.length !== 31 || bytes[0] !== 1 || bytes[28] !== 1)
    throw new DomainError(
      "QR_INVITATION_UNSUPPORTED",
      400,
      "Invitation is unsupported",
    );
  const expected = bytes.readUInt16BE(29);
  if (crc16(bytes.subarray(0, 29)) !== expected)
    throw new DomainError(
      "QR_INVITATION_INVALID",
      400,
      "Invitation is invalid",
    );
  const numericDevice = bytes.readUIntBE(1, 3);
  if (numericDevice < 1 || numericDevice > 999999)
    throw new DomainError(
      "QR_INVITATION_INVALID",
      400,
      "Invitation is invalid",
    );
  const issuedAt = bytes.readUInt32BE(20);
  const expiresAt = bytes.readUInt32BE(24);
  if (
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > QR_ONBOARDING_MAX_LIFETIME_SECONDS
  )
    throw new DomainError(
      "QR_INVITATION_INVALID",
      400,
      "Invitation timing is invalid",
    );
  return {
    version: 1,
    deviceId: `AG-${numericDevice.toString().padStart(6, "0")}`,
    nonce: Buffer.from(bytes.subarray(4, 20)),
    issuedAt,
    expiresAt,
    capabilityVersion: 1,
  };
}

function uuidBytes(uuid: string) {
  const value = uuid.replaceAll("-", "");
  if (!/^[0-9a-f]{32}$/i.test(value)) throw new Error("invalid UUID");
  return Buffer.from(value, "hex");
}

function grantData(
  session: BootstrapSession,
  invitation: QrOnboardingInvitation,
  ownershipVersion: string,
) {
  const result = Buffer.alloc(81);
  result[0] = 1;
  result.writeUIntBE(Number(invitation.deviceId.slice(3)), 1, 3);
  invitation.nonce.copy(result, 4);
  uuidBytes(session.sessionId).copy(result, 20);
  result.writeUInt32BE(Math.floor(Date.parse(session.expiresAt) / 1000), 36);
  result.writeBigUInt64BE(BigInt(ownershipVersion), 40);
  createHash("sha256").update(session.sessionToken).digest().copy(result, 48);
  result[80] = invitation.capabilityVersion;
  return result;
}

export class QrOnboardingGrantSigner {
  private readonly key: KeyObject;

  constructor(privateKeyPkcs8Base64Url: string) {
    try {
      this.key = createPrivateKey({
        key: Buffer.from(privateKeyPkcs8Base64Url, "base64url"),
        format: "der",
        type: "pkcs8",
      });
      if (
        this.key.asymmetricKeyType !== "ec" ||
        this.key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
      )
        throw new Error("not P-256");
    } catch {
      throw new Error("QR onboarding signing key is invalid");
    }
  }

  createGrant(
    session: BootstrapSession,
    invitation: QrOnboardingInvitation,
    ownershipVersion: string,
  ) {
    const data = grantData(session, invitation, ownershipVersion);
    const signature = sign("sha256", data, {
      key: this.key,
      dsaEncoding: "ieee-p1363",
    });
    if (signature.length !== 64) throw new Error("QR grant signing failed");
    return Buffer.concat([data, signature]).toString("base64url");
  }
}

export class QrOnboardingService {
  private readonly attempts = new Map<string, number[]>();

  constructor(
    private readonly repository: DeviceRepository,
    private readonly signer: QrOnboardingGrantSigner,
    private readonly sessionLifetimeMs: number,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async exchange(input: {
    invitationUri: string;
    ownershipVersion: string;
    actorSubjectId: string;
    expectedOrganizationId: string;
  }) {
    return this.exchangeBound({ ...input, registerIfMissing: false });
  }

  async exchangeScanFirst(input: {
    invitationUri: string;
    actorSubjectId: string;
    expectedOrganizationId: string;
  }) {
    return this.exchangeBound({
      ...input,
      ownershipVersion: "1",
      registerIfMissing: true,
    });
  }

  private async exchangeBound(input: {
    invitationUri: string;
    ownershipVersion: string;
    actorSubjectId: string;
    expectedOrganizationId: string;
    registerIfMissing: boolean;
  }) {
    const now = this.clock();
    const invitation = decodeQrOnboardingInvitation(input.invitationUri);
    const rateKey = createHash("sha256")
      .update(`${input.actorSubjectId}:${invitation.deviceId}`)
      .digest("hex");
    const recent = (this.attempts.get(rateKey) ?? []).filter(
      (value) => value > now.getTime() - 60_000,
    );
    if (recent.length >= 3)
      throw new DomainError(
        "QR_EXCHANGE_RATE_LIMITED",
        429,
        "Exchange is temporarily unavailable",
      );
    recent.push(now.getTime());
    this.attempts.set(rateKey, recent);
    const session = await this.repository.createQrOnboardingSession({
      deviceId: invitation.deviceId,
      organizationId: input.expectedOrganizationId,
      ownershipVersion: input.ownershipVersion,
      actorSubjectId: input.actorSubjectId,
      nonceHash: createHash("sha256").update(invitation.nonce).digest("hex"),
      // The offline ESP32 has no trusted wall clock before Wi-Fi. Its compact
      // invitation therefore carries monotonic boot seconds. Convert only the
      // signed bounded lifetime into server time for storage/TTL. The device
      // independently rejects a photographed or rotated nonce.
      invitationIssuedAt: now,
      invitationExpiresAt: new Date(
        now.getTime() + (invitation.expiresAt - invitation.issuedAt) * 1000,
      ),
      capabilityVersion: invitation.capabilityVersion,
      ttlMs: this.sessionLifetimeMs,
      registerIfMissing: input.registerIfMissing,
      now,
    });
    return {
      schema:
        "urn:algaguard:schema:onboarding:qr-onboarding-exchange-response:v1" as const,
      schemaVersion: "1.0.0" as const,
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      serviceUuid: CANONICAL_BLE_PROVISIONING_SERVICE_UUID,
      sessionToken: session.sessionToken,
      bindingGrant: this.signer.createGrant(
        session,
        invitation,
        input.ownershipVersion,
      ),
    };
  }
}
