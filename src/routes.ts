import { randomBytes } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { ClaimStore, DevelopmentCredentialProvider } from "./domain.js";

interface DeviceRecord {
  id: string;
  organizationId: string;
  tankId?: string;
  hardwareModel: string;
  status: "UNPROVISIONED" | "PROVISIONED";
}

export const router = Router();
const claims = new ClaimStore();
const devices = new Map<string, DeviceRecord>();
const bootstrap = new Map<string, { deviceId: string; expiresAt: number }>();
let nextDevice = 1;

async function authorize(subjectId: string, organizationId: string) {
  const response = await fetch(
    `${process.env.ACCESS_SERVICE_URL ?? "http://access-service:3000"}/v1/authorizations/subscriptions`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectId,
        resourceType: "organization",
        resourceId: organizationId,
      }),
    },
  );
  return (
    response.ok &&
    Boolean(((await response.json()) as { allowed?: boolean }).allowed)
  );
}

router.post("/devices", (request, response) => {
  const input = z
    .object({
      organizationId: z.string().uuid(),
      tankId: z.string().uuid().optional(),
      hardwareModel: z.string().default("ESP32-S3-DEVKITC-1-N16R8"),
    })
    .parse(request.body);
  const id = `AG-${String(nextDevice++).padStart(6, "0")}`;
  const record: DeviceRecord = {
    id,
    organizationId: input.organizationId,
    hardwareModel: input.hardwareModel,
    status: "UNPROVISIONED",
    ...(input.tankId ? { tankId: input.tankId } : {}),
  };
  devices.set(id, record);
  response.status(201).json(record);
});

router.post("/devices/:id/setup", (request, response) => {
  if (!devices.has(request.params.id))
    return response.status(404).json({ status: 404 });
  const input = z
    .object({ bootstrapUrl: z.string().url(), environment: z.string().min(1) })
    .parse(request.body);
  return response
    .status(201)
    .json(
      claims.create(request.params.id, input.bootstrapUrl, input.environment),
    );
});

router.post("/claims/consume", async (request, response) => {
  const input = z
    .object({
      claimCode: z.string().min(1),
      subjectId: z.string().min(1),
      organizationId: z.string().uuid(),
    })
    .parse(request.body);
  const candidate = claims.peek(input.claimCode);
  const device = candidate ? devices.get(candidate) : undefined;
  if (!device || device.organizationId !== input.organizationId) {
    return response
      .status(410)
      .json({ title: "Claim expired or consumed", status: 410 });
  }
  if (!(await authorize(input.subjectId, input.organizationId))) {
    return response
      .status(403)
      .json({ title: "Device claim is not authorized", status: 403 });
  }
  const deviceId = claims.consume(input.claimCode);
  if (!deviceId)
    return response
      .status(410)
      .json({ title: "Claim expired or consumed", status: 410 });
  const bootstrapToken = randomBytes(24).toString("base64url");
  bootstrap.set(bootstrapToken, {
    deviceId,
    expiresAt: Date.now() + 5 * 60_000,
  });
  return response.json({
    deviceId,
    consumed: true,
    bootstrapToken,
    expiresInSeconds: 300,
  });
});

router.post("/devices/:id/bootstrap", async (request, response) => {
  const input = z
    .object({ bootstrapToken: z.string().min(1) })
    .parse(request.body);
  const value = bootstrap.get(input.bootstrapToken);
  bootstrap.delete(input.bootstrapToken);
  if (
    !value ||
    value.deviceId !== request.params.id ||
    value.expiresAt <= Date.now()
  ) {
    return response
      .status(410)
      .json({ title: "Bootstrap credential expired or consumed", status: 410 });
  }
  const credentials = await new DevelopmentCredentialProvider().issue(
    request.params.id,
  );
  const device = devices.get(request.params.id);
  if (device) device.status = "PROVISIONED";
  return response.json({
    ...credentials,
    expiresInSeconds: 900,
    developmentOnly: true,
  });
});

router.get("/devices/:id", (request, response) => {
  const device = devices.get(request.params.id);
  response.status(device ? 200 : 404).json(device ?? { status: 404 });
});
