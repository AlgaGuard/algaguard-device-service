import assert from "node:assert/strict";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { GrpcAccessAuthorizer } from "../src/auth.js";
import {
  GrpcPhysicalUnpairCommandVerifier,
  GrpcPhysicalUnpairNotifier,
} from "../src/physical-unpair.js";

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

// A fake Keycloak token endpoint so the clients under test can obtain a
// service token without a real Keycloak instance.
function withFakeTokenEndpoint(
  testFn: (environment: NodeJS.ProcessEnv) => Promise<void>,
) {
  return async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: any) => {
      if (String(input).includes("/protocol/openid-connect/token"))
        return new Response(
          JSON.stringify({ access_token: "fake-token", expires_in: 300 }),
          { status: 200 },
        );
      return originalFetch(input);
    }) as typeof fetch;
    try {
      await testFn({
        SERVICE_CLIENT_SECRET: "test-secret",
        SERVICE_CLIENT_ID: "algaguard-device-service",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  };
}

test(
  "GrpcAccessAuthorizer calls Decide and RegisterResource with a bearer token",
  withFakeTokenEndpoint(async (environment) => {
    const proto = loadProto("access_service.proto");
    const received: { authorization?: string }[] = [];
    const server = new grpc.Server();
    server.addService(proto.algaguard.access.v1.AuthorizationService.service, {
      decide(
        call: grpc.ServerUnaryCall<any, any>,
        callback: grpc.sendUnaryData<any>,
      ) {
        received.push({
          authorization: call.metadata.get("authorization")[0] as string,
        });
        callback(null, {
          allowed: true,
          reason: "",
          decidedAt: new Date().toISOString(),
          ttlSeconds: 5,
        });
      },
    });
    server.addService(
      proto.algaguard.access.v1.ResourceRegistryService.service,
      {
        registerResource(
          _call: grpc.ServerUnaryCall<any, any>,
          callback: grpc.sendUnaryData<any>,
        ) {
          callback(null, {});
        },
      },
    );
    const port = await new Promise<number>((resolve, reject) => {
      server.bindAsync(
        "127.0.0.1:0",
        grpc.ServerCredentials.createInsecure(),
        (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
      );
    });
    try {
      const authorizer = new GrpcAccessAuthorizer(
        `127.0.0.1:${port}`,
        environment,
      );
      const allowed = await authorizer.authorize({
        subjectId: "owner",
        action: "device.read",
        resourceType: "device",
        resourceId: randomUUID(),
      });
      assert.equal(allowed, true);
      assert.equal(received[0]?.authorization, "Bearer fake-token");

      await assert.doesNotReject(() =>
        authorizer.registerDevice(randomUUID(), randomUUID()),
      );
    } finally {
      await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
    }
  }),
);

test(
  "GrpcPhysicalUnpairNotifier calls DeviceUnpaired",
  withFakeTokenEndpoint(async (environment) => {
    const proto = loadProto("realtime_service.proto");
    const received: unknown[] = [];
    const server = new grpc.Server();
    server.addService(
      proto.algaguard.realtime.v1.DeviceNotificationService.service,
      {
        deviceUnpaired(
          call: grpc.ServerUnaryCall<any, any>,
          callback: grpc.sendUnaryData<any>,
        ) {
          received.push(call.request);
          callback(null, {});
        },
      },
    );
    const port = await new Promise<number>((resolve, reject) => {
      server.bindAsync(
        "127.0.0.1:0",
        grpc.ServerCredentials.createInsecure(),
        (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
      );
    });
    try {
      const notifier = new GrpcPhysicalUnpairNotifier(
        `127.0.0.1:${port}`,
        environment,
      );
      const organizationId = randomUUID();
      const commandId = randomUUID();
      await notifier.notify({ organizationId, commandId });
      assert.deepEqual(received[0], {
        organizationId,
        eventId: commandId,
      });
    } finally {
      await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
    }
  }),
);

test(
  "GrpcPhysicalUnpairCommandVerifier forwards the caller's authorization and validates binding",
  withFakeTokenEndpoint(async (environment) => {
    const proto = loadProto("command_service.proto");
    const deviceId = "AG-000001";
    const organizationId = randomUUID();
    const commandId = randomUUID();
    const server = new grpc.Server();
    server.addService(proto.algaguard.command.v1.CommandLookupService.service, {
      getCommand(
        call: grpc.ServerUnaryCall<any, any>,
        callback: grpc.sendUnaryData<any>,
      ) {
        assert.equal(
          call.metadata.get("authorization")[0],
          "Bearer caller-token",
        );
        callback(null, {
          commandId: call.request.commandId,
          deviceId,
          organizationId,
          commandType: "REQUEST_PHYSICAL_UNPAIR",
          parametersJson: "{}",
          status: "SUCCEEDED",
          createdAt: new Date().toISOString(),
          expiresAt: new Date().toISOString(),
          createdBy: "owner",
          correlationId: "",
          reportedAt: "",
        });
      },
    });
    const port = await new Promise<number>((resolve, reject) => {
      server.bindAsync(
        "127.0.0.1:0",
        grpc.ServerCredentials.createInsecure(),
        (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
      );
    });
    try {
      const verifier = new GrpcPhysicalUnpairCommandVerifier(
        `127.0.0.1:${port}`,
      );
      const result = await verifier.verify({
        commandId,
        deviceId,
        organizationId,
        authorization: "Bearer caller-token",
      });
      assert.equal(result.physicallyConfirmed, true);
      assert.equal(result.deviceId, deviceId);
    } finally {
      await new Promise<void>((resolve) => server.tryShutdown(() => resolve()));
    }
  }),
);
