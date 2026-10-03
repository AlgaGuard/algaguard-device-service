import path from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { z } from "zod";
import {
  createAuthenticator,
  OidcAccessAuthorizer,
  type AccessAuthorizer,
  type Authenticator,
} from "./auth.js";
import {
  DomainError,
  resolveDeviceContext,
  type DeviceRepository,
} from "./domain.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(here, "..", "proto", "device_service.proto");

const DEVICE_STATUS_NUMBER: Record<string, number> = {
  UNCLAIMED: 1,
  CLAIMED: 2,
  PROVISIONING: 3,
  PROVISIONED: 4,
  ACTIVE: 5,
  INACTIVE: 6,
  REVOKED: 7,
};

async function requireServicePrincipal(
  authenticate: Authenticator,
  metadata: grpc.Metadata,
) {
  const [authorization] = metadata.get("authorization");
  const actor = await authenticate(
    typeof authorization === "string" ? authorization : undefined,
  );
  if (!actor.service)
    throw new DomainError(
      "SERVICE_TOKEN_REQUIRED",
      403,
      "Service token required",
    );
}

// grpc-js only serializes `code`, `details`, and `metadata` across the
// wire -- a server-side Error's own `.name`/custom properties never reach
// the client. Callers that branch on the exact DomainError code (e.g.
// mqtt-ingestion-service distinguishing DEVICE_REVOKED from
// DEVICE_UNCLAIMED for its metrics) need that code carried explicitly in
// a metadata trailer.
function grpcErrorFor(error: unknown): grpc.ServiceError {
  const [code, domainCode, message] =
    error instanceof DomainError
      ? ([
          error.status === 403
            ? grpc.status.PERMISSION_DENIED
            : error.status === 404
              ? grpc.status.NOT_FOUND
              : error.status >= 500
                ? grpc.status.INTERNAL
                : grpc.status.FAILED_PRECONDITION,
          error.code,
          error.message,
        ] as const)
      : ([grpc.status.INTERNAL, "INTERNAL", "Internal error"] as const);
  const metadata = new grpc.Metadata();
  metadata.set("x-domain-error-code", domainCode);
  return Object.assign(new Error(message), {
    code,
    name: domainCode,
    details: message,
    metadata,
  });
}

export interface GrpcServerDependencies {
  repository: DeviceRepository;
  authenticate?: Authenticator;
  authorize?: AccessAuthorizer;
}

export function buildGrpcServer(dependencies: GrpcServerDependencies) {
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(PROTO_PATH)],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as any;
  const authenticate = dependencies.authenticate ?? createAuthenticator();
  const authorize = dependencies.authorize ?? new OidcAccessAuthorizer();
  const { repository } = dependencies;

  const server = new grpc.Server();

  function contextMessage(context: ReturnType<typeof resolveDeviceContext>) {
    return {
      deviceUuid: context.deviceUuid,
      deviceId: context.deviceId,
      organizationId: context.organizationId,
      status: DEVICE_STATUS_NUMBER[context.status],
      ownershipVersion: context.ownershipVersion,
      resolvedAt: context.resolvedAt,
      tankId: context.tankId ?? "",
      contextVersion: context.contextVersion,
    };
  }

  server.addService(proto.algaguard.device.v1.DeviceLookupService.service, {
    async getContext(
      call: grpc.ServerUnaryCall<any, any>,
      callback: grpc.sendUnaryData<any>,
    ) {
      try {
        await requireServicePrincipal(authenticate, call.metadata);
        const deviceUuid = z.string().uuid().parse(call.request.deviceUuid);
        const context = resolveDeviceContext(
          await repository.getDevice(deviceUuid),
        );
        callback(null, contextMessage(context));
      } catch (error) {
        callback(grpcErrorFor(error));
      }
    },

    async getContextByDeviceId(
      call: grpc.ServerUnaryCall<any, any>,
      callback: grpc.sendUnaryData<any>,
    ) {
      try {
        await requireServicePrincipal(authenticate, call.metadata);
        const deviceId = z
          .string()
          .regex(/^AG-[0-9]{6}$/)
          .parse(call.request.deviceId);
        const context = resolveDeviceContext(
          await repository.getDeviceById(deviceId),
        );
        callback(null, contextMessage(context));
      } catch (error) {
        callback(grpcErrorFor(error));
      }
    },

    async getDevice(
      call: grpc.ServerUnaryCall<any, any>,
      callback: grpc.sendUnaryData<any>,
    ) {
      try {
        // Unlike GetContext/GetContextByDeviceId, the HTTP route this
        // replaces (GET /v1/devices/:deviceUuid) is not service-token-only
        // -- it authorizes the ORIGINAL caller's own device.read
        // permission via requireAccess(). The gRPC caller (ota-service)
        // forwards that caller's own bearer token rather than its own
        // service token, so this mirrors that exactly.
        const [authorization] = call.metadata.get("authorization");
        const actor = await authenticate(
          typeof authorization === "string" ? authorization : undefined,
        );
        const deviceUuid = z.string().uuid().parse(call.request.deviceUuid);
        const [correlationId] = call.metadata.get("x-correlation-id");
        const allowed = await authorize.authorize({
          subjectId: actor.subjectId,
          action: "device.read",
          resourceType: "device",
          resourceId: deviceUuid,
          ...(typeof correlationId === "string" ? { correlationId } : {}),
        });
        if (!allowed)
          throw new DomainError(
            "FORBIDDEN",
            403,
            "Operation is not authorized",
          );
        const device = await repository.getDevice(deviceUuid);
        if (!device)
          throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
        callback(null, {
          deviceUuid: device.deviceUuid,
          deviceId: device.deviceId,
          displayName: device.displayName ?? "",
          organizationId: device.organizationId,
          tankId: device.tankId ?? "",
          hardwareModel: device.hardwareModel,
          firmwareVersion: device.firmwareVersion,
          lifecycle: device.lifecycle,
          ownershipVersion: device.ownershipVersion,
          createdAt: device.createdAt,
          updatedAt: device.updatedAt,
        });
      } catch (error) {
        callback(grpcErrorFor(error));
      }
    },
  });

  return server;
}
