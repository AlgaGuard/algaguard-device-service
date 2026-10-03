import assert from "node:assert/strict";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import test from "node:test";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { buildGrpcServer } from "../src/grpc-server.js";
import type { Authenticator } from "../src/auth.js";
import type { DeviceRecord, DeviceRepository } from "../src/domain.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(here, "..", "proto", "device_service.proto");

const authenticate: Authenticator = async (authorization) => {
  const subjectId = authorization?.replace("Bearer ", "") || "anonymous";
  return { subjectId, service: subjectId === "service" };
};

class FakeDeviceRepository implements Partial<DeviceRepository> {
  constructor(private readonly devices: Map<string, DeviceRecord>) {}
  async getDevice(deviceUuid: string) {
    return this.devices.get(deviceUuid);
  }
  async getDeviceById() {
    return undefined;
  }
}

function activeDevice(): DeviceRecord {
  return {
    deviceUuid: randomUUID(),
    deviceId: "AG-000001",
    organizationId: randomUUID(),
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
    firmwareVersion: "1.0.0",
    lifecycle: "ACTIVE",
    ownershipVersion: "1",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

async function startServer(devices: Map<string, DeviceRecord>) {
  const repository = new FakeDeviceRepository(
    devices,
  ) as unknown as DeviceRepository;
  const server = buildGrpcServer({ repository, authenticate });
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      grpc.ServerCredentials.createInsecure(),
      (error, boundPort) => (error ? reject(error) : resolve(boundPort)),
    );
  });
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    includeDirs: [path.dirname(PROTO_PATH)],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as any;
  const client = new proto.algaguard.device.v1.DeviceLookupService(
    `127.0.0.1:${port}`,
    grpc.credentials.createInsecure(),
  );
  return {
    client,
    stop: () =>
      new Promise<void>((resolve) => server.tryShutdown(() => resolve())),
  };
}

function metadataFor(bearer: string) {
  const metadata = new grpc.Metadata();
  metadata.set("authorization", `Bearer ${bearer}`);
  return metadata;
}

test("GetContext requires a service principal", async () => {
  const { client, stop } = await startServer(new Map());
  try {
    await assert.rejects(
      () =>
        new Promise((resolve, reject) => {
          client.getContext(
            { deviceUuid: randomUUID() },
            metadataFor("owner"),
            (error: grpc.ServiceError, response: unknown) =>
              error ? reject(error) : resolve(response),
          );
        }),
      (error: grpc.ServiceError) => {
        assert.equal(error.code, grpc.status.PERMISSION_DENIED);
        return true;
      },
    );
  } finally {
    await stop();
  }
});

test("GetContext resolves an active device's context", async () => {
  const device = activeDevice();
  const { client, stop } = await startServer(
    new Map([[device.deviceUuid, device]]),
  );
  try {
    const response = await new Promise<any>((resolve, reject) => {
      client.getContext(
        { deviceUuid: device.deviceUuid },
        metadataFor("service"),
        (error: grpc.ServiceError, value: unknown) =>
          error ? reject(error) : resolve(value),
      );
    });
    assert.equal(response.deviceUuid, device.deviceUuid);
    assert.equal(response.deviceId, device.deviceId);
    assert.equal(response.organizationId, device.organizationId);
    assert.equal(response.status, 5); // ACTIVE
    assert.equal(response.ownershipVersion, "1");
  } finally {
    await stop();
  }
});

test("GetContext reports NOT_FOUND for an unknown device", async () => {
  const { client, stop } = await startServer(new Map());
  try {
    await assert.rejects(
      () =>
        new Promise((resolve, reject) => {
          client.getContext(
            { deviceUuid: randomUUID() },
            metadataFor("service"),
            (error: grpc.ServiceError, response: unknown) =>
              error ? reject(error) : resolve(response),
          );
        }),
      (error: grpc.ServiceError) => {
        assert.equal(error.code, grpc.status.NOT_FOUND);
        return true;
      },
    );
  } finally {
    await stop();
  }
});

test("GetDevice returns the full device record for a service caller", async () => {
  const device = activeDevice();
  const { client, stop } = await startServer(
    new Map([[device.deviceUuid, device]]),
  );
  try {
    const response = await new Promise<any>((resolve, reject) => {
      client.getDevice(
        { deviceUuid: device.deviceUuid },
        metadataFor("service"),
        (error: grpc.ServiceError, value: unknown) =>
          error ? reject(error) : resolve(value),
      );
    });
    assert.equal(response.deviceUuid, device.deviceUuid);
    assert.equal(response.hardwareModel, device.hardwareModel);
    assert.equal(response.lifecycle, "ACTIVE");
  } finally {
    await stop();
  }
});
