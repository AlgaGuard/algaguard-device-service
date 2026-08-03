import { z } from "zod";

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
      `${this.baseUrl}/internal/notifications/device-unpaired`,
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

export class HttpPhysicalUnpairCommandVerifier implements PhysicalUnpairCommandVerifier {
  constructor(private readonly baseUrl: string) {}

  async verify(input: {
    commandId: string;
    deviceId: string;
    organizationId: string;
    authorization: string;
  }) {
    const response = await fetch(
      `${this.baseUrl}/commands/${input.commandId}`,
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
