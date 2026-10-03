import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {
  createServiceTokenProvider,
  metadataWithServiceToken,
} from "./grpc-client.js";

const here = path.dirname(fileURLToPath(import.meta.url));
function loadProto(file: string) {
  const protoPath = path.resolve(here, "..", "proto", file);
  const packageDefinition = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(protoPath)],
  });
  return grpc.loadPackageDefinition(packageDefinition) as any;
}

export interface VerifiedPhysicalUnpair {
  commandId: string;
  deviceId: string;
  organizationId: string;
  physicallyConfirmed: true;
}

export interface PhysicalUnpairCommandVerifier {
  verify(input: {
    commandId: string;
    deviceId: string;
    organizationId: string;
    authorization: string;
  }): Promise<VerifiedPhysicalUnpair>;
}

export interface PhysicalUnpairNotifier {
  notify(input: { organizationId: string; commandId: string }): Promise<void>;
}

export class HttpPhysicalUnpairNotifier implements PhysicalUnpairNotifier {
  private token?: { value: string; expiresAt: number };

  constructor(
    private readonly baseUrl: string,
    private readonly environment: NodeJS.ProcessEnv = process.env,
  ) {}

  private async serviceToken() {
    if (this.token && this.token.expiresAt > Date.now() + 10_000)
      return this.token.value;
    const issuer =
      this.environment.KEYCLOAK_ISSUER ??
      "http://keycloak:8080/realms/algaguard";
    const tokenUrl =
      this.environment.KEYCLOAK_TOKEN_URL ??
      `${issuer}/protocol/openid-connect/token`;
    if (!this.environment.SERVICE_CLIENT_SECRET)
      throw new Error("Service authentication is unavailable");
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id:
          this.environment.SERVICE_CLIENT_ID ?? "algaguard-device-service",
        client_secret: this.environment.SERVICE_CLIENT_SECRET,
      }),
    });
    if (!response.ok) throw new Error("Service authentication failed");
    const value = (await response.json()) as {
      access_token?: string;
      expires_in?: number;
    };
    if (!value.access_token)
      throw new Error("Service authentication response was invalid");
    this.token = {
      value: value.access_token,
      expiresAt: Date.now() + Math.max(value.expires_in ?? 30, 1) * 1_000,
    };
    return this.token.value;
  }

  async notify(input: { organizationId: string; commandId: string }) {
    const response = await fetch(
      `${this.baseUrl}/v1/internal/notifications/device-unpaired`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${await this.serviceToken()}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          organizationId: input.organizationId,
          eventId: input.commandId,
        }),
        redirect: "error",
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (!response.ok) throw new Error("Organization notification failed");
  }
}

const command = z
  .object({
    commandId: z.string().uuid(),
    deviceId: z.string().regex(/^AG-[0-9]{6}$/),
    organizationId: z.string().uuid(),
    commandType: z.literal("REQUEST_PHYSICAL_UNPAIR"),
    status: z.literal("SUCCEEDED"),
  })
  .passthrough();

export class GrpcPhysicalUnpairNotifier implements PhysicalUnpairNotifier {
  private readonly client: any;
  private readonly serviceToken: () => Promise<string>;

  constructor(
    address: string,
    environment: NodeJS.ProcessEnv = process.env,
    serviceToken = createServiceTokenProvider(environment),
  ) {
    const proto = loadProto("realtime_service.proto");
    this.serviceToken = serviceToken;
    this.client = new proto.algaguard.realtime.v1.DeviceNotificationService(
      address,
      grpc.credentials.createInsecure(),
    );
  }

  async notify(input: { organizationId: string; commandId: string }) {
    const metadata = await metadataWithServiceToken(this.serviceToken);
    await new Promise<void>((resolve, reject) => {
      const deadline = new Date(Date.now() + 8_000);
      this.client.deviceUnpaired(
        { organizationId: input.organizationId, eventId: input.commandId },
        metadata,
        { deadline },
        (error: grpc.ServiceError) =>
          error
            ? reject(new Error("Organization notification failed"))
            : resolve(),
      );
    });
  }
}

// Unlike the other gRPC clients in this file, GetCommand is authorized
// against the ORIGINAL caller's own identity (matching the HTTP version this
// replaces, which forwarded the caller's Authorization header as-is) rather
// than this service's own service-to-service token -- command-service
// decides access the same way its public GET /v1/commands/:id does.
export class GrpcPhysicalUnpairCommandVerifier implements PhysicalUnpairCommandVerifier {
  private readonly client: any;

  constructor(address: string) {
    const proto = loadProto("command_service.proto");
    this.client = new proto.algaguard.command.v1.CommandLookupService(
      address,
      grpc.credentials.createInsecure(),
    );
  }

  async verify(input: {
    commandId: string;
    deviceId: string;
    organizationId: string;
    authorization: string;
  }) {
    const metadata = new grpc.Metadata();
    metadata.set("authorization", input.authorization);
    const response = await new Promise<any>((resolve, reject) => {
      const deadline = new Date(Date.now() + 8_000);
      this.client.getCommand(
        { commandId: input.commandId },
        metadata,
        { deadline },
        (error: grpc.ServiceError, value: unknown) =>
          error
            ? reject(new Error("Physical confirmation is unavailable"))
            : resolve(value),
      );
    });
    const value = command.parse({
      commandId: response.commandId,
      deviceId: response.deviceId,
      organizationId: response.organizationId,
      commandType: response.commandType,
      status: response.status,
    });
    if (
      value.deviceId !== input.deviceId ||
      value.organizationId !== input.organizationId
    )
      throw new Error("Physical confirmation binding mismatch");
    return { ...value, physicallyConfirmed: true as const };
  }
}

export class HttpPhysicalUnpairCommandVerifier implements PhysicalUnpairCommandVerifier {
  constructor(private readonly baseUrl: string) {}

  async verify(input: {
    commandId: string;
    deviceId: string;
    organizationId: string;
    authorization: string;
  }) {
    const response = await fetch(
      `${this.baseUrl}/v1/commands/${input.commandId}`,
      {
        headers: { authorization: input.authorization },
        redirect: "error",
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (!response.ok) throw new Error("Physical confirmation is unavailable");
    const value = command.parse(await response.json());
    if (
      value.deviceId !== input.deviceId ||
      value.organizationId !== input.organizationId
    )
      throw new Error("Physical confirmation binding mismatch");
    return { ...value, physicallyConfirmed: true as const };
  }
}
