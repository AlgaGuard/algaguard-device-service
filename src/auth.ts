import { createRemoteJWKSet, jwtVerify } from "jose";

export interface Principal {
  subjectId: string;
  email?: string;
  service: boolean;
}
export type Authenticator = (
  authorization: string | undefined,
) => Promise<Principal>;
export class AuthenticationError extends Error {}

export function createAuthenticator(
  environment: NodeJS.ProcessEnv = process.env,
): Authenticator {
  const issuer =
    environment.KEYCLOAK_ISSUER ?? "http://keycloak:8080/realms/algaguard";
  const audience = environment.KEYCLOAK_AUDIENCE ?? "algaguard-api";
  const serviceClients = new Set(
    (
      environment.SERVICE_CLIENT_IDS ??
      "algaguard-access-service,algaguard-mqtt-ingestion-service,algaguard-telemetry-service"
    )
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
  const jwksUrl =
    environment.KEYCLOAK_JWKS_URL ?? `${issuer}/protocol/openid-connect/certs`;
  const jwks = createRemoteJWKSet(new URL(jwksUrl));
  return async (authorization) => {
    const match = /^Bearer ([^ ]+)$/.exec(authorization ?? "");
    if (!match?.[1]) throw new AuthenticationError("Bearer token required");
    const result = await jwtVerify(match[1], jwks, { issuer, audience });
    if (!result.payload.sub)
      throw new AuthenticationError("Token subject is required");
    const clientId =
      typeof result.payload.azp === "string"
        ? result.payload.azp
        : typeof result.payload.client_id === "string"
          ? result.payload.client_id
          : undefined;
    return {
      subjectId: result.payload.sub,
      ...(typeof result.payload.email === "string"
        ? { email: result.payload.email }
        : {}),
      service: Boolean(clientId && serviceClients.has(clientId)),
    };
  };
}

export interface AccessAuthorizer {
  authorize(input: {
    subjectId: string;
    action: string;
    resourceType: "organization" | "device";
    resourceId: string;
    organizationId?: string;
    correlationId?: string;
  }): Promise<boolean>;
  registerDevice(
    deviceUuid: string,
    organizationId: string,
    correlationId?: string,
  ): Promise<void>;
}

export class OidcAccessAuthorizer implements AccessAuthorizer {
  private token?: { value: string; expiresAt: number };
  constructor(
    private readonly environment: NodeJS.ProcessEnv = process.env,
    private readonly fetcher: typeof fetch = fetch,
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
    const clientId =
      this.environment.SERVICE_CLIENT_ID ?? "algaguard-device-service";
    const clientSecret = this.environment.SERVICE_CLIENT_SECRET;
    if (!clientSecret)
      throw new AuthenticationError("SERVICE_CLIENT_SECRET is required");
    const response = await this.fetcher(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (!response.ok)
      throw new AuthenticationError("Service authentication failed");
    const value = (await response.json()) as {
      access_token?: string;
      expires_in?: number;
    };
    if (!value.access_token)
      throw new AuthenticationError("Service token response was invalid");
    this.token = {
      value: value.access_token,
      expiresAt: Date.now() + Math.max(value.expires_in ?? 30, 1) * 1000,
    };
    return this.token.value;
  }

  async authorize(input: {
    subjectId: string;
    action: string;
    resourceType: "organization" | "device";
    resourceId: string;
    organizationId?: string;
    correlationId?: string;
  }) {
    const response = await this.fetcher(
      `${this.environment.ACCESS_SERVICE_URL ?? "http://access-service:3000"}/v1/internal/authorizations/decide`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${await this.serviceToken()}`,
          ...(input.correlationId
            ? { "x-correlation-id": input.correlationId }
            : {}),
        },
        body: JSON.stringify({
          subjectId: input.subjectId,
          action: input.action,
          resourceType: input.resourceType,
          resourceId: input.resourceId,
          ...(input.organizationId
            ? { organizationId: input.organizationId }
            : {}),
        }),
      },
    );
    if (!response.ok) return false;
    return Boolean(((await response.json()) as { allowed?: boolean }).allowed);
  }

  async registerDevice(
    deviceUuid: string,
    organizationId: string,
    correlationId?: string,
  ) {
    const response = await this.fetcher(
      `${this.environment.ACCESS_SERVICE_URL ?? "http://access-service:3000"}/v1/internal/resources/device/${encodeURIComponent(deviceUuid)}`,
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${await this.serviceToken()}`,
          ...(correlationId ? { "x-correlation-id": correlationId } : {}),
        },
        body: JSON.stringify({ organizationId }),
      },
    );
    if (!response.ok)
      throw new Error(
        `Access resource registration failed with ${response.status}`,
      );
  }
}
