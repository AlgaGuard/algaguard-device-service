import { Router, type Request } from "express";
import { z } from "zod";
import {
  createAuthenticator,
  OidcAccessAuthorizer,
  type AccessAuthorizer,
  type Authenticator,
} from "./auth.js";
import {
  DevelopmentCredentialProvider,
  DomainError,
  resolveDeviceContext,
  type DeviceCredentialProvider,
  type DeviceRepository,
} from "./domain.js";

export interface RouteDependencies {
  repository: DeviceRepository;
  authenticate?: Authenticator;
  authorize?: AccessAuthorizer;
  credentials?: DeviceCredentialProvider;
}

function correlationId(request: Request) {
  return request.header("x-correlation-id");
}

export function createRouter(dependencies: RouteDependencies) {
  const router = Router();
  const authenticate = dependencies.authenticate ?? createAuthenticator();
  const authorize = dependencies.authorize ?? new OidcAccessAuthorizer();
  const credentials =
    dependencies.credentials ?? new DevelopmentCredentialProvider();
  const { repository } = dependencies;

  async function requireAccess(
    request: Request,
    action: string,
    resourceType: "organization" | "device",
    resourceId: string,
    organizationId?: string,
  ) {
    const actor = await authenticate(request.header("authorization"));
    const requestCorrelationId = correlationId(request);
    const allowed = await authorize.authorize({
      subjectId: actor.subjectId,
      action,
      resourceType,
      resourceId,
      ...(organizationId ? { organizationId } : {}),
      ...(requestCorrelationId ? { correlationId: requestCorrelationId } : {}),
    });
    if (!allowed)
      throw new DomainError("FORBIDDEN", 403, "Operation is not authorized");
    return actor;
  }

  router.post("/devices", async (request, response) => {
    const input = z
      .object({
        organizationId: z.string().uuid(),
        tankId: z.string().uuid().optional(),
        hardwareModel: z
          .string()
          .min(2)
          .max(64)
          .default("ESP32-S3-DEVKITC-1-N16R8"),
      })
      .parse(request.body);
    await requireAccess(
      request,
      "device.manage",
      "organization",
      input.organizationId,
    );
    const created = await repository.createDevice({
      organizationId: input.organizationId,
      hardwareModel: input.hardwareModel,
      ...(input.tankId ? { tankId: input.tankId } : {}),
    });
    const requestCorrelationId = correlationId(request);
    await authorize.registerDevice(
      created.deviceUuid,
      created.organizationId,
      requestCorrelationId,
    );
    response.status(201).json(created);
  });

  router.get("/devices", async (request, response) => {
    const organizationId = z
      .string()
      .uuid()
      .parse(request.query.organizationId);
    await requireAccess(request, "device.read", "organization", organizationId);
    response.json({ items: await repository.listDevices(organizationId) });
  });

  router.get("/devices/:id", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    await requireAccess(request, "device.read", "device", deviceUuid);
    const value = await repository.getDevice(deviceUuid);
    response
      .status(value ? 200 : 404)
      .json(value ?? { code: "DEVICE_NOT_FOUND" });
  });

  router.put("/devices/:id/tank-association", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    const actor = await requireAccess(
      request,
      "device.manage",
      "device",
      deviceUuid,
    );
    const input = z
      .object({ tankId: z.string().uuid().nullable() })
      .parse(request.body);
    response.json(
      await repository.assignTank(
        deviceUuid,
        input.tankId ?? undefined,
        actor.subjectId,
      ),
    );
  });

  router.post("/devices/:id/setup", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    const actor = await requireAccess(
      request,
      "device.manage",
      "device",
      deviceUuid,
    );
    const input = z
      .object({
        expiresInSeconds: z.number().int().min(60).max(3600).default(600),
      })
      .parse(request.body);
    const device = await repository.getDevice(deviceUuid);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    response
      .status(201)
      .json(
        await repository.createClaim(
          device.deviceId,
          input.expiresInSeconds * 1000,
          actor.subjectId,
        ),
      );
  });

  router.post("/devices/:id/ownership-transfer", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    const current = await repository.getDevice(deviceUuid);
    if (!current)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    const actor = await requireAccess(
      request,
      "device.manage",
      "device",
      deviceUuid,
      current.organizationId,
    );
    const input = z
      .object({ organizationId: z.string().uuid() })
      .strict()
      .parse(request.body);
    await requireAccess(
      request,
      "device.manage",
      "organization",
      input.organizationId,
    );
    const transferred = await repository.transferOwnership(
      deviceUuid,
      input.organizationId,
      actor.subjectId,
    );
    const requestCorrelationId = correlationId(request);
    await authorize.registerDevice(
      transferred.device.deviceUuid,
      transferred.device.organizationId,
      requestCorrelationId,
    );
    response.json(transferred);
  });

  router.post("/claims/consume", async (request, response) => {
    const input = z
      .object({
        organizationId: z.string().uuid(),
        deviceId: z
          .string()
          .regex(/^AG-[0-9]{6}$/)
          .optional(),
        claimCode: z.string().min(8).max(96).optional(),
        qr: z
          .object({
            v: z.literal(1),
            d: z.string().regex(/^AG-[0-9]{6}$/),
            c: z.string().regex(/^[A-Za-z0-9_-]{32,64}$/),
            e: z.string().datetime(),
            f: z.string().regex(/^[A-HJ-NP-Z2-9]{8,12}$/),
          })
          .strict()
          .optional(),
      })
      .refine(
        (value) => Boolean(value.qr || (value.deviceId && value.claimCode)),
        {
          message: "qr or deviceId plus claimCode is required",
        },
      )
      .parse(request.body);
    if (input.qr && Date.parse(input.qr.e) <= Date.now())
      throw new DomainError("CLAIM_EXPIRED", 410, "Claim QR expired");
    const deviceId = input.qr?.d ?? input.deviceId!;
    const secret = input.qr?.c ?? input.claimCode!;
    const actor = await requireAccess(
      request,
      "device.claim",
      "organization",
      input.organizationId,
    );
    response.json(
      await repository.consumeClaim({
        deviceId,
        secret,
        organizationId: input.organizationId,
        subjectId: actor.subjectId,
      }),
    );
  });

  router.post("/devices/:id/bootstrap", async (request, response) => {
    const input = z
      .object({ sessionToken: z.string().regex(/^[A-Za-z0-9_-]{32,96}$/) })
      .parse(request.body);
    await repository.consumeBootstrap(request.params.id, input.sessionToken);
    response.json({
      ...(await credentials.issue(request.params.id)),
      developmentOnly: true,
    });
  });

  router.get("/devices/:id/status", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    await requireAccess(request, "device.read", "device", deviceUuid);
    const device = await repository.getDevice(deviceUuid);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    const value = await repository.latestStatus(device.deviceId);
    response
      .status(value ? 200 : 404)
      .json(value ?? { code: "STATUS_NOT_FOUND" });
  });

  router.get("/devices/:id/health", async (request, response) => {
    const deviceUuid = z.string().uuid().parse(request.params.id);
    await requireAccess(request, "device.read", "device", deviceUuid);
    const device = await repository.getDevice(deviceUuid);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    const value = await repository.latestHealth(device.deviceId);
    response
      .status(value ? 200 : 404)
      .json(value ?? { code: "HEALTH_NOT_FOUND" });
  });

  router.get(
    "/internal/devices/:deviceUuid/context",
    async (request, response) => {
      const actor = await authenticate(request.header("authorization"));
      if (!actor.service)
        throw new DomainError(
          "SERVICE_TOKEN_REQUIRED",
          403,
          "Service token required",
        );
      const deviceUuid = z.string().uuid().parse(request.params.deviceUuid);
      response.json(
        resolveDeviceContext(await repository.getDevice(deviceUuid)),
      );
    },
  );

  router.get(
    "/internal/devices/by-device-id/:deviceId/context",
    async (request, response) => {
      const actor = await authenticate(request.header("authorization"));
      if (!actor.service)
        throw new DomainError(
          "SERVICE_TOKEN_REQUIRED",
          403,
          "Service token required",
        );
      const deviceId = z
        .string()
        .regex(/^AG-[0-9]{6}$/)
        .parse(request.params.deviceId);
      response.json(
        resolveDeviceContext(await repository.getDeviceById(deviceId)),
      );
    },
  );

  router.put("/internal/devices/:id/status", async (request, response) => {
    const actor = await authenticate(request.header("authorization"));
    if (!actor.service)
      throw new DomainError(
        "SERVICE_TOKEN_REQUIRED",
        403,
        "Service token required",
      );
    const input = z
      .object({
        observedAt: z.string().datetime(),
        status: z.record(z.string(), z.unknown()),
      })
      .parse(request.body);
    await repository.updateStatus(
      request.params.id,
      input.status,
      new Date(input.observedAt),
    );
    response.status(204).end();
  });

  router.put("/internal/devices/:id/health", async (request, response) => {
    const actor = await authenticate(request.header("authorization"));
    if (!actor.service)
      throw new DomainError(
        "SERVICE_TOKEN_REQUIRED",
        403,
        "Service token required",
      );
    const input = z
      .object({
        observedAt: z.string().datetime(),
        health: z.record(z.string(), z.unknown()),
      })
      .parse(request.body);
    await repository.updateHealth(
      request.params.id,
      input.health,
      new Date(input.observedAt),
    );
    response.status(204).end();
  });

  return router;
}
