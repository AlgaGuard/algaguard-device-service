import assert from "node:assert/strict";
import test from "node:test";
import { OidcAccessAuthorizer } from "../src/auth.js";

test("uses the private token endpoint while retaining the public issuer configuration", async () => {
  const issuer = "https://dev.algaguard.example/auth/realms/algaguard";
  const tokenUrl =
    "http://keycloak:8080/realms/algaguard/protocol/openid-connect/token";
  const calls: string[] = [];
  const authorizer = new OidcAccessAuthorizer(
    {
      KEYCLOAK_ISSUER: issuer,
      KEYCLOAK_TOKEN_URL: tokenUrl,
      SERVICE_CLIENT_ID: "algaguard-device-service",
      SERVICE_CLIENT_SECRET: "test-only-secret",
      ACCESS_SERVICE_URL: "http://access-service:3000",
    },
    async (input) => {
      const url = String(input);
      calls.push(url);
      if (url === tokenUrl)
        return new Response(
          JSON.stringify({ access_token: "service-token", expires_in: 60 }),
          { status: 200 },
        );
      if (
        url === "http://access-service:3000/v1/internal/authorizations/decide"
      )
        return new Response(JSON.stringify({ allowed: true }), { status: 200 });
      throw new Error(`Unexpected request: ${url}`);
    },
  );

  assert.equal(
    await authorizer.authorize({
      subjectId: "demo-user",
      action: "device.manage",
      resourceType: "organization",
      resourceId: "00000000-0000-4000-8000-000000000001",
    }),
    true,
  );
  assert.deepEqual(calls, [
    tokenUrl,
    "http://access-service:3000/v1/internal/authorizations/decide",
  ]);
});
