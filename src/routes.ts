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
import { DeviceCredentialService } from "./credential-service.js";

export interface RouteDependencies {
  repository: DeviceRepository;
  authenticate?: Authenticator;
  authorize?: AccessAuthorizer;
  credentials?: DeviceCredentialProvider;
  credentialLifecycle?: DeviceCredentialService;
  authenticateBroker?: (authorization: string | undefined) => void;
  httpBodyLimit?: string;
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
    const device = await repository.getDevice(deviceUuid);
    if (!device)
      throw new DomainError("DEVICE_NOT_FOUND", 404, "Device not found");
    const actor = await requireAccess(
      request,
      "device.manage",
      "organization",
      device.organizationId,
    );
    const input = z
      .object({
        expiresInSeconds: z.number().int().min(60).max(3600).default(600),
      })
      .parse(request.body);
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
    response.setHeader("Deprecation", "true");
    response.setHeader(
      "Warning",
      '299 - "Development-only bootstrap; migrate to exchange plus CSR issue"',
    );
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

  if (dependencies.credentialLifecycle) {
    const lifecycle = dependencies.credentialLifecycle;

    router.post(
      "/device-credential-bootstrap/exchange",
      async (request, response) => {
        const input = z
          .object({
            schema: z
              .literal(
                "urn:algaguard:schema:onboarding:bootstrap-token-exchange-request:v1",
              )
              .optional(),
            schemaVersion: z.literal("1.0.0").optional(),
            sessionToken: z.string().regex(/^[A-Za-z0-9_-]{32,96}$/),
            deviceId: z
              .string()
              .regex(/^AG-[0-9]{6}$/)
              .optional(),
          })
          .strict()
          .parse(request.body);
        response.status(201).json(
          await lifecycle.exchangeBootstrapSession({
            sessionToken: input.sessionToken,
            ...(input.deviceId ? { deviceId: input.deviceId } : {}),
          }),
        );
      },
    );

    router.post(
      "/devices/:id/credential-bootstrap",
      async (request, response) => {
        const deviceUuid = z.string().uuid().parse(request.params.id);
        const actor = await requireAccess(
          request,
          "device.credentials.bootstrap",
          "device",
          deviceUuid,
        );
        response
          .status(201)
          .json(await lifecycle.createBootstrap(deviceUuid, actor.subjectId));
      },
    );

    router.post(
      "/device-credential-bootstrap/issue",
      async (request, response) => {
        const token = request
          .header("authorization")
          ?.match(/^Bearer (.+)$/)?.[1];
        if (!token)
          throw new DomainError(
            "BOOTSTRAP_TOKEN_REQUIRED",
            401,
            "Bootstrap bearer token required",
          );
        const input = z
          .object({
            schema: z
              .literal(
                "urn:algaguard:schema:onboarding:credential-csr-submission:v1",
              )
              .optional(),
            schemaVersion: z.literal("1.0.0").optional(),
            deviceUuid: z.string().uuid(),
            deviceId: z.string().regex(/^AG-[0-9]{6}$/),
            purpose: z.literal("INITIAL"),
            rotationId: z.null(),
            idempotencyKey: z.string().uuid(),
            keyAlgorithm: z.enum(["EC_P256", "RSA_3072"]),
            csrPem: z
              .string()
              .min(128)
              .max(16_384)
              .startsWith("-----BEGIN CERTIFICATE REQUEST-----"),
          })
          .strict()
          .parse(request.body);
        response.status(201).json(
          await lifecycle.issueInitial({
            token,
            deviceUuid: input.deviceUuid,
            deviceId: input.deviceId,
            idempotencyKey: input.idempotencyKey,
            keyAlgorithm: input.keyAlgorithm,
            csrPem: input.csrPem,
          }),
        );
      },
    );

    router.get("/devices/:id/credentials", async (request, response) => {
      const deviceUuid = z.string().uuid().parse(request.params.id);
      await requireAccess(
        request,
        "device.credentials.view",
        "device",
        deviceUuid,
      );
      response.json({ items: await lifecycle.listCredentials(deviceUuid) });
    });

    router.get("/devices/:id/credential-status", async (request, response) => {
      const deviceUuid = z.string().uuid().parse(request.params.id);
      await requireAccess(
        request,
        "device.credentials.view",
        "device",
        deviceUuid,
      );
      response.json(await lifecycle.credentialStatus(deviceUuid));
    });

    router.get("/devices/:id/credential-audit", async (request, response) => {
      const deviceUuid = z.string().uuid().parse(request.params.id);
      await requireAccess(
        request,
        "device.credentials.audit",
        "device",
        deviceUuid,
      );
      response.json({ items: await lifecycle.listAudit(deviceUuid) });
    });

    router.post(
      "/devices/:id/credential-rotations",
      async (request, response) => {
        const deviceUuid = z.string().uuid().parse(request.params.id);
        const input = z
          .object({
            idempotencyKey: z.string().uuid(),
            reason: z
              .enum(["SCHEDULED", "EXPIRING", "ADMIN_REQUESTED", "RECOVERY"])
              .default("ADMIN_REQUESTED"),
            overlapSeconds: z.number().int().min(30).max(86_400).optional(),
          })
          .strict()
          .parse(request.body);
        const actor = await requireAccess(
          request,
          input.reason === "RECOVERY"
            ? "device.credentials.recover"
            : "device.credentials.rotate",
          "device",
          deviceUuid,
        );
        response.status(202).json(
          await lifecycle.beginRotation({
            deviceUuid,
            actorId: actor.subjectId,
            requestKey: input.idempotencyKey,
            reason: input.reason,
            ...(input.overlapSeconds
              ? { overlapSeconds: input.overlapSeconds }
              : {}),
          }),
        );
      },
    );

    router.post(
      "/internal/device-credential-rotations/:rotationId/issue",
      async (request, response) => {
        const actor = await authenticate(request.header("authorization"));
        if (!actor.service)
          throw new DomainError(
            "SERVICE_TOKEN_REQUIRED",
            403,
            "Trusted mTLS proxy service token required",
          );
        const rotationId = z.string().uuid().parse(request.params.rotationId);
        const input = z
          .object({
            currentCertificatePem: z.string().min(128).max(16_384),
            idempotencyKey: z.string().uuid(),
            keyAlgorithm: z.enum(["EC_P256", "RSA_3072"]),
            csrPem: z.string().min(128).max(16_384),
          })
          .strict()
          .parse(request.body);
        response
          .status(201)
          .json(await lifecycle.issueRotation({ rotationId, ...input }));
      },
    );

    router.post(
      "/internal/device-credential-rotations/:rotationId/acknowledgement",
      async (request, response) => {
        const actor = await authenticate(request.header("authorization"));
        if (!actor.service)
          throw new DomainError(
            "SERVICE_TOKEN_REQUIRED",
            403,
            "Trusted device proxy service token required",
          );
        const rotationId = z.string().uuid().parse(request.params.rotationId);
        const input = z
          .object({
            newCredentialId: z.string().uuid(),
            result: z.enum(["CONNECTED", "FAILED"]),
            failureCode: z
              .enum([
                "TLS_REJECTED",
                "BROKER_UNREACHABLE",
                "STORAGE_FAILURE",
                "TIME_UNSYNCHRONIZED",
                "UNKNOWN",
              ])
              .optional(),
          })
          .strict()
          .parse(request.body);
        response.json(
          await lifecycle.acknowledgeRotation({
            rotationId,
            newCredentialId: input.newCredentialId,
            result: input.result,
            ...(input.failureCode ? { failureCode: input.failureCode } : {}),
          }),
        );
      },
    );

    router.post(
      "/devices/:deviceUuid/credentials/:credentialId/revocation",
      async (request, response) => {
        const deviceUuid = z.string().uuid().parse(request.params.deviceUuid);
        const credentialId = z
          .string()
          .uuid()
          .parse(request.params.credentialId);
        const input = z
          .object({
            reason: z.enum([
              "COMPROMISED",
              "ADMIN_REVOKED",
              "DEVICE_RETIRED",
              "RECOVERY_REPLACED",
            ]),
          })
          .strict()
          .parse(request.body);
        const actor = await requireAccess(
          request,
          input.reason === "COMPROMISED"
            ? "device.credentials.compromise"
            : "device.credentials.revoke",
          "device",
          deviceUuid,
        );
        response.json(
          await lifecycle.revoke({
            deviceUuid,
            credentialId,
            reason: input.reason,
            actorId: actor.subjectId,
          }),
        );
      },
    );

    router.post(
      "/internal/device-credentials/authenticate",
      async (request, response) => {
        dependencies.authenticateBroker?.(request.header("authorization"));
        if (!dependencies.authenticateBroker)
          throw new DomainError(
            "BROKER_AUTHENTICATION_DISABLED",
            503,
            "Broker authentication integration is disabled",
          );
        const input = z
          .object({
            clientId: z.string().regex(/^AG-[0-9]{6}$/),
            certificatePem: z.string().min(128).max(16_384),
          })
          .strict()
          .parse(request.body);
        response.json(await lifecycle.authenticateBroker(input));
      },
    );

    router.get(
      "/internal/device-credentials/metrics",
      async (request, response) => {
        const actor = await authenticate(request.header("authorization"));
        if (!actor.service)
          throw new DomainError(
            "SERVICE_TOKEN_REQUIRED",
            403,
            "Service token required",
          );
        response.json(lifecycle.getMetrics());
      },
    );
  }

  return router;
}
