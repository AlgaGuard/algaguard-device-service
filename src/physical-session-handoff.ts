import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  DomainError,
  fallbackCode,
  secretDigest,
  type DeviceRepository,
} from "./domain.js";

export const physicalSessionHandoffProtocolVersion = 1;
const pollIntervalSeconds = 5;

export interface PhysicalSessionBundle {
  sessionId: string;
  deviceId: string;
  sessionToken: string;
  expiresAt: string;
}

interface EncryptedBundle {
  ciphertext: string;
  nonce: string;
  tag: string;
}

export interface PhysicalSessionHandoffRecord {
  handoffId: string;
  deviceId: string;
  deviceCodeHash: string;
  userCodeHash: string;
  expiresAt: string;
  createdAt: string;
  state: "PENDING" | "APPROVED";
  lastPollAt?: string;
  organizationId?: string;
  ownershipVersion?: string;
  encryptedBundle?: EncryptedBundle;
}

export interface PhysicalSessionHandoffStore {
  create(
    record: PhysicalSessionHandoffRecord,
    ttlSeconds: number,
  ): Promise<void>;
  byDeviceCodeHash(
    hash: string,
  ): Promise<PhysicalSessionHandoffRecord | undefined>;
  byUserCodeHash(
    hash: string,
  ): Promise<PhysicalSessionHandoffRecord | undefined>;
  replace(
    record: PhysicalSessionHandoffRecord,
    ttlSeconds: number,
  ): Promise<void>;
  approve(
    record: PhysicalSessionHandoffRecord,
    ttlSeconds: number,
  ): Promise<boolean>;
  consume(
    deviceCodeHash: string,
  ): Promise<PhysicalSessionHandoffRecord | undefined>;
  remove(deviceCodeHash: string): Promise<void>;
}

export class MemoryPhysicalSessionHandoffStore implements PhysicalSessionHandoffStore {
  private readonly records = new Map<string, PhysicalSessionHandoffRecord>();
  private readonly userCodes = new Map<string, string>();

  async create(record: PhysicalSessionHandoffRecord): Promise<void> {
    if (
      this.records.has(record.deviceCodeHash) ||
      this.userCodes.has(record.userCodeHash)
    ) {
      throw new Error("handoff collision");
    }
    this.records.set(record.deviceCodeHash, structuredClone(record));
    this.userCodes.set(record.userCodeHash, record.deviceCodeHash);
  }

  async byDeviceCodeHash(hash: string) {
    const value = this.records.get(hash);
    return value ? structuredClone(value) : undefined;
  }

  async byUserCodeHash(hash: string) {
    const deviceCodeHash = this.userCodes.get(hash);
    return deviceCodeHash ? this.byDeviceCodeHash(deviceCodeHash) : undefined;
  }

  async replace(record: PhysicalSessionHandoffRecord): Promise<void> {
    if (!this.records.has(record.deviceCodeHash))
      throw new Error("handoff unavailable");
    this.records.set(record.deviceCodeHash, structuredClone(record));
  }

  async approve(record: PhysicalSessionHandoffRecord): Promise<boolean> {
    const existing = this.records.get(record.deviceCodeHash);
    if (!existing || existing.state !== "PENDING") return false;
    this.records.set(record.deviceCodeHash, structuredClone(record));
    return true;
  }

  async consume(deviceCodeHash: string) {
    const value = this.records.get(deviceCodeHash);
    if (!value) return undefined;
    this.records.delete(deviceCodeHash);
    this.userCodes.delete(value.userCodeHash);
    return structuredClone(value);
  }

  async remove(deviceCodeHash: string): Promise<void> {
    const value = this.records.get(deviceCodeHash);
    this.records.delete(deviceCodeHash);
    if (value) this.userCodes.delete(value.userCodeHash);
  }
}

export interface RedisHandoffClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    options: { EX: number; NX?: true },
  ): Promise<unknown>;
  del(keys: string | string[]): Promise<number>;
  eval(
    script: string,
    options: { keys: string[]; arguments: string[] },
  ): Promise<unknown>;
}

export class RedisPhysicalSessionHandoffStore implements PhysicalSessionHandoffStore {
  constructor(private readonly redis: RedisHandoffClient) {}

  private recordKey(hash: string) {
    return `algaguard:physical-session-handoff:device:${hash}`;
  }

  private userKey(hash: string) {
    return `algaguard:physical-session-handoff:user:${hash}`;
  }

  async create(record: PhysicalSessionHandoffRecord, ttlSeconds: number) {
    const recordCreated = await this.redis.set(
      this.recordKey(record.deviceCodeHash),
      JSON.stringify(record),
      { EX: ttlSeconds, NX: true },
    );
    if (recordCreated !== "OK") throw new Error("handoff collision");
    const userCodeCreated = await this.redis.set(
      this.userKey(record.userCodeHash),
      record.deviceCodeHash,
      { EX: ttlSeconds, NX: true },
    );
    if (userCodeCreated !== "OK") {
      await this.redis.del(this.recordKey(record.deviceCodeHash));
      throw new Error("handoff collision");
    }
  }

  async byDeviceCodeHash(hash: string) {
    const value = await this.redis.get(this.recordKey(hash));
    return value
      ? (JSON.parse(value) as PhysicalSessionHandoffRecord)
      : undefined;
  }

  async byUserCodeHash(hash: string) {
    const deviceCodeHash = await this.redis.get(this.userKey(hash));
    return deviceCodeHash ? this.byDeviceCodeHash(deviceCodeHash) : undefined;
  }

  async replace(record: PhysicalSessionHandoffRecord, ttlSeconds: number) {
    await this.redis.set(
      this.recordKey(record.deviceCodeHash),
      JSON.stringify(record),
      {
        EX: ttlSeconds,
      },
    );
    await this.redis.set(
      this.userKey(record.userCodeHash),
      record.deviceCodeHash,
      {
        EX: ttlSeconds,
      },
    );
  }

  async approve(record: PhysicalSessionHandoffRecord, ttlSeconds: number) {
    const result = await this.redis.eval(
      "local value=redis.call('GET',KEYS[1]); if not value then return 0 end; local current=cjson.decode(value); if current.state ~= 'PENDING' then return 0 end; redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[2]); redis.call('SET',KEYS[2],ARGV[3],'EX',ARGV[2]); return 1",
      {
        keys: [
          this.recordKey(record.deviceCodeHash),
          this.userKey(record.userCodeHash),
        ],
        arguments: [
          JSON.stringify(record),
          String(ttlSeconds),
          record.deviceCodeHash,
        ],
      },
    );
    return result === 1 || result === "1";
  }

  async consume(deviceCodeHash: string) {
    const result = await this.redis.eval(
      "local value=redis.call('GET',KEYS[1]); if not value then return nil end; local record=cjson.decode(value); redis.call('DEL',KEYS[1]); redis.call('DEL',ARGV[1]..record.userCodeHash); return value",
      {
        keys: [this.recordKey(deviceCodeHash)],
        arguments: ["algaguard:physical-session-handoff:user:"],
      },
    );
    return typeof result === "string"
      ? (JSON.parse(result) as PhysicalSessionHandoffRecord)
      : undefined;
  }

  async remove(deviceCodeHash: string) {
    const value = await this.byDeviceCodeHash(deviceCodeHash);
    await this.redis.del([
      this.recordKey(deviceCodeHash),
      ...(value ? [this.userKey(value.userCodeHash)] : []),
    ]);
  }
}

export class PhysicalSessionCipher {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32)
      throw new Error("invalid physical session handoff key");
  }

  static fromBase64Url(value: string) {
    return new PhysicalSessionCipher(Buffer.from(value, "base64url"));
  }

  seal(bundle: PhysicalSessionBundle, associatedData: string): EncryptedBundle {
    const nonce = randomBytes(12);
    const plaintext = Buffer.from(JSON.stringify(bundle), "utf8");
    try {
      const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
      cipher.setAAD(Buffer.from(associatedData, "utf8"));
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
      ]);
      return {
        ciphertext: ciphertext.toString("base64url"),
        nonce: nonce.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
      };
    } finally {
      plaintext.fill(0);
    }
  }

  open(value: EncryptedBundle, associatedData: string): PhysicalSessionBundle {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(value.nonce, "base64url"),
    );
    decipher.setAAD(Buffer.from(associatedData, "utf8"));
    decipher.setAuthTag(Buffer.from(value.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(value.ciphertext, "base64url")),
      decipher.final(),
    ]);
    try {
      return JSON.parse(plaintext.toString("utf8")) as PhysicalSessionBundle;
    } finally {
      plaintext.fill(0);
    }
  }
}

export class PhysicalSessionHandoffService {
  constructor(
    private readonly repository: DeviceRepository,
    private readonly store: PhysicalSessionHandoffStore,
    private readonly cipher: PhysicalSessionCipher,
    private readonly now: () => Date = () => new Date(),
    private readonly handoffLifetimeMs: number = 5 * 60_000,
  ) {}

  async start(deviceId: string) {
    const now = this.now();
    const deviceCode = randomBytes(32).toString("base64url");
    const userCode = fallbackCode(8);
    const expiresAt = new Date(now.getTime() + this.handoffLifetimeMs);
    const record: PhysicalSessionHandoffRecord = {
      handoffId: randomUUID(),
      deviceId,
      deviceCodeHash: secretDigest(deviceCode),
      userCodeHash: secretDigest(userCode),
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      state: "PENDING",
    };
    await this.store.create(record, secondsUntil(expiresAt, now));
    return {
      handoffId: record.handoffId,
      deviceCode,
      userCode,
      expiresAt: record.expiresAt,
      pollIntervalSeconds,
    };
  }

  async approve(input: {
    userCode: string;
    sessionId: string;
    deviceId: string;
    sessionToken: string;
    authorizedOrganizationId: string;
    authorizedOwnershipVersion: string;
  }) {
    const userCodeHash = secretDigest(normalizeUserCode(input.userCode));
    const record = await this.store.byUserCodeHash(userCodeHash);
    if (!record || !secureEqual(record.userCodeHash, userCodeHash)) {
      throw unavailable();
    }
    const now = this.now();
    if (expired(record, now)) {
      await this.store.remove(record.deviceCodeHash);
      throw unavailable();
    }
    if (record.state !== "PENDING" || record.deviceId !== input.deviceId)
      throw unavailable();
    const session = await this.repository.validateBootstrapSession(
      input.sessionToken,
      input.deviceId,
      now,
    );
    if (
      session.sessionId !== input.sessionId ||
      session.device.organizationId !== input.authorizedOrganizationId ||
      session.device.ownershipVersion !== input.authorizedOwnershipVersion
    ) {
      throw unavailable();
    }
    const sessionExpiry = new Date(session.expiresAt);
    const handoffExpiry = new Date(record.expiresAt);
    const expiresAt =
      sessionExpiry < handoffExpiry ? sessionExpiry : handoffExpiry;
    const approved: PhysicalSessionHandoffRecord = {
      ...record,
      expiresAt: expiresAt.toISOString(),
      state: "APPROVED",
      organizationId: session.device.organizationId,
      ownershipVersion: session.device.ownershipVersion,
      encryptedBundle: this.cipher.seal(
        {
          sessionId: input.sessionId,
          deviceId: input.deviceId,
          sessionToken: input.sessionToken,
          expiresAt: expiresAt.toISOString(),
        },
        associatedData(record.handoffId, input.deviceId, expiresAt),
      ),
    };
    if (!(await this.store.approve(approved, secondsUntil(expiresAt, now))))
      throw unavailable();
  }

  async redeem(deviceCode: string) {
    const deviceCodeHash = secretDigest(deviceCode);
    const existing = await this.store.byDeviceCodeHash(deviceCodeHash);
    const now = this.now();
    if (!existing || !secureEqual(existing.deviceCodeHash, deviceCodeHash)) {
      throw unavailable();
    }
    if (expired(existing, now)) {
      await this.store.remove(deviceCodeHash);
      return { status: "EXPIRED" as const };
    }
    if (existing.state === "PENDING") {
      if (
        existing.lastPollAt &&
        now.getTime() - new Date(existing.lastPollAt).getTime() <
          pollIntervalSeconds * 1000
      ) {
        return { status: "SLOW_DOWN" as const, pollIntervalSeconds };
      }
      await this.store.replace(
        { ...existing, lastPollAt: now.toISOString() },
        secondsUntil(new Date(existing.expiresAt), now),
      );
      return { status: "PENDING" as const, pollIntervalSeconds };
    }
    const record = await this.store.consume(deviceCodeHash);
    if (!record || !record.encryptedBundle || expired(record, now)) {
      throw unavailable();
    }
    const current = await this.repository.getDeviceById(record.deviceId);
    if (
      !current ||
      current.organizationId !== record.organizationId ||
      current.ownershipVersion !== record.ownershipVersion
    ) {
      throw unavailable();
    }
    const bundle = this.cipher.open(
      record.encryptedBundle,
      associatedData(
        record.handoffId,
        record.deviceId,
        new Date(record.expiresAt),
      ),
    );
    return { status: "REDEEMED" as const, ...bundle };
  }
}

function normalizeUserCode(value: string) {
  return value.replace(/[-\s]/g, "").toUpperCase();
}

function associatedData(handoffId: string, deviceId: string, expiresAt: Date) {
  return `${physicalSessionHandoffProtocolVersion}:${handoffId}:${deviceId}:${expiresAt.toISOString()}`;
}

function secondsUntil(expiresAt: Date, now: Date) {
  return Math.max(1, Math.floor((expiresAt.getTime() - now.getTime()) / 1000));
}

function expired(record: PhysicalSessionHandoffRecord, now: Date) {
  return new Date(record.expiresAt).getTime() <= now.getTime();
}

function unavailable() {
  return new DomainError(
    "PHYSICAL_SESSION_HANDOFF_UNAVAILABLE",
    410,
    "Handoff unavailable",
  );
}

function secureEqual(left: string, right: string) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}
