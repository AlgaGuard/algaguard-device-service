import { createHash, randomBytes, randomUUID } from "node:crypto";
export interface QrPayload {
  schema: "algaguard.device.setup";
  schemaVersion: "1.0.0";
  deviceId: string;
  claimCode: string;
  bootstrapUrl: string;
  environment: string;
  bleServiceId: string;
  expiresAt: string;
}
interface Claim {
  deviceId: string;
  digest: string;
  expiresAt: number;
  consumed: boolean;
}
export class ClaimStore {
  private readonly claims = new Map<string, Claim>();
  create(
    deviceId: string,
    bootstrapUrl: string,
    environment: string,
    ttlMs = 10 * 60_000,
  ): QrPayload {
    const claimCode = randomBytes(18).toString("base64url");
    const id = randomUUID();
    const expiresAt = Date.now() + ttlMs;
    this.claims.set(id, {
      deviceId,
      digest: createHash("sha256").update(claimCode).digest("hex"),
      expiresAt,
      consumed: false,
    });
    return {
      schema: "algaguard.device.setup",
      schemaVersion: "1.0.0",
      deviceId,
      claimCode: `${id}.${claimCode}`,
      bootstrapUrl,
      environment,
      bleServiceId: "7f640001-b5a3-f393-e0a9-e50e24dcca9e",
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }
  consume(encoded: string, now = Date.now()) {
    const deviceId = this.peek(encoded, now);
    if (!deviceId) return undefined;
    const [id] = encoded.split(".");
    const claim = id ? this.claims.get(id) : undefined;
    if (!claim) return undefined;
    claim.consumed = true;
    return deviceId;
  }
  peek(encoded: string, now = Date.now()) {
    const [id, code] = encoded.split(".");
    const claim = id ? this.claims.get(id) : undefined;
    if (!claim || !code || claim.consumed || claim.expiresAt <= now)
      return undefined;
    if (createHash("sha256").update(code).digest("hex") !== claim.digest)
      return undefined;
    return claim.deviceId;
  }
}
export interface DeviceCredentialProvider {
  issue(deviceId: string): Promise<{ username: string; password: string }>;
}
export class DevelopmentCredentialProvider implements DeviceCredentialProvider {
  constructor(
    private readonly enabled = process.env.ALLOW_DEVELOPMENT_CREDENTIALS ===
      "true" && process.env.NODE_ENV !== "production",
  ) {}
  async issue(deviceId: string) {
    if (!this.enabled)
      throw new Error("Development credential provider is disabled");
    return {
      username: deviceId,
      password: randomBytes(24).toString("base64url"),
    };
  }
}
