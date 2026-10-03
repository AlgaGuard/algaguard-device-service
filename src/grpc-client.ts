import * as grpc from "@grpc/grpc-js";

// Shared by every outbound gRPC client this service builds (access-service,
// realtime-service, command-service): obtains an OIDC client-credentials
// token the same way the HTTP fetch() clients it replaces did, and attaches
// it as "authorization: Bearer <token>" gRPC call metadata so the callee's
// existing HTTP Authenticator-based auth works unchanged over gRPC too.
export function createServiceTokenProvider(
  environment: NodeJS.ProcessEnv = process.env,
) {
  let cached: { value: string; expiresAt: number } | undefined;
  return async function serviceToken() {
    if (cached && cached.expiresAt > Date.now() + 10_000) return cached.value;
    const issuer =
      environment.KEYCLOAK_ISSUER ?? "http://keycloak:8080/realms/algaguard";
    const tokenUrl =
      environment.KEYCLOAK_TOKEN_URL ??
      `${issuer}/protocol/openid-connect/token`;
    const clientId =
      environment.SERVICE_CLIENT_ID ?? "algaguard-device-service";
    const clientSecret = environment.SERVICE_CLIENT_SECRET;
    if (!clientSecret) throw new Error("SERVICE_CLIENT_SECRET is required");
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (!response.ok) throw new Error("Service authentication failed");
    const value = (await response.json()) as {
      access_token?: string;
      expires_in?: number;
    };
    if (!value.access_token)
      throw new Error("Service authentication response was invalid");
    cached = {
      value: value.access_token,
      expiresAt: Date.now() + Math.max(value.expires_in ?? 30, 1) * 1000,
    };
    return cached.value;
  };
}

// grpc-js refuses to compose call credentials (the metadata-generator
// pattern) with *insecure* channel credentials, specifically to stop a
// bearer token being silently sent over plaintext. Internal traffic here
// stays plaintext within the Docker network -- same as the HTTP calls this
// replaces -- so the bearer token is attached as plain per-call metadata
// instead of formal call credentials; callers build it fresh per RPC via
// metadataWithServiceToken() rather than baking it into the channel.
export async function metadataWithServiceToken(
  serviceToken: () => Promise<string>,
  extra?: Record<string, string>,
) {
  const metadata = new grpc.Metadata();
  metadata.set("authorization", `Bearer ${await serviceToken()}`);
  for (const [key, value] of Object.entries(extra ?? {}))
    metadata.set(key, value);
  return metadata;
}
