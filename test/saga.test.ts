import assert from "node:assert/strict";
import test from "node:test";
import {
  DeviceOwnershipSagaWorker,
  MAX_ATTEMPTS_BEFORE_COMPENSATION,
  MemoryDeviceOwnershipSagaRepository,
  type SagaCompensation,
  type SagaNotifyUnpair,
  type SagaRegisterDevice,
} from "../src/saga.js";

function compensationRecorder() {
  const reverted: Array<{ deviceUuid: string; toOrganizationId: string }> = [];
  const retired: string[] = [];
  const compensation: SagaCompensation = {
    async revertOwnership(deviceUuid, toOrganizationId) {
      reverted.push({ deviceUuid, toOrganizationId });
    },
    async retireDevice(deviceUuid) {
      retired.push(deviceUuid);
    },
  };
  return { compensation, reverted, retired };
}

test("a saga that succeeds on the first attempt completes without compensating", async () => {
  const repository = new MemoryDeviceOwnershipSagaRepository();
  const calls: Array<{ deviceUuid: string; organizationId: string }> = [];
  const registerDevice: SagaRegisterDevice = {
    async registerDevice(deviceUuid, organizationId) {
      calls.push({ deviceUuid, organizationId });
    },
  };
  const { compensation, reverted, retired } = compensationRecorder();
  const worker = new DeviceOwnershipSagaWorker(
    repository,
    registerDevice,
    compensation,
  );
  const sagaId = await repository.record({
    deviceUuid: "device-1",
    sagaType: "DEVICE_CREATION",
    toOrganizationId: "org-1",
  });
  const claimed = await worker.runOnce();
  assert.equal(claimed, true);
  assert.deepEqual(calls, [
    { deviceUuid: "device-1", organizationId: "org-1" },
  ]);
  assert.equal(repository.stateOf(sagaId), "COMPLETED");
  assert.equal(reverted.length, 0);
  assert.equal(retired.length, 0);
});

test("a saga that fails transiently retries instead of compensating immediately", async () => {
  const repository = new MemoryDeviceOwnershipSagaRepository();
  let attempt = 0;
  const registerDevice: SagaRegisterDevice = {
    async registerDevice() {
      attempt += 1;
      if (attempt < 3) throw new Error("transient access-service failure");
    },
  };
  const { compensation, reverted, retired } = compensationRecorder();
  const worker = new DeviceOwnershipSagaWorker(
    repository,
    registerDevice,
    compensation,
  );
  const sagaId = await repository.record({
    deviceUuid: "device-1",
    sagaType: "OWNERSHIP_TRANSFER",
    toOrganizationId: "org-2",
    fromOrganizationId: "org-1",
  });
  // First two attempts fail and go back to PENDING with a retry delay, so
  // claim() won't pick them up again until that delay elapses -- force the
  // clock forward each time, same as a real poll loop would observe.
  await worker.runOnce(new Date(0));
  assert.equal(repository.stateOf(sagaId), "PENDING");
  await worker.runOnce(new Date(Date.now() + 60_000));
  assert.equal(repository.stateOf(sagaId), "PENDING");
  const succeeded = await worker.runOnce(new Date(Date.now() + 120_000));
  assert.equal(succeeded, true);
  assert.equal(repository.stateOf(sagaId), "COMPLETED");
  assert.equal(attempt, 3);
  assert.equal(reverted.length, 0);
  assert.equal(retired.length, 0);
});

test("OWNERSHIP_TRANSFER compensates by reverting ownership after exhausting retries", async () => {
  const repository = new MemoryDeviceOwnershipSagaRepository();
  const registerDevice: SagaRegisterDevice = {
    async registerDevice() {
      throw new Error("access-service is down");
    },
  };
  const { compensation, reverted, retired } = compensationRecorder();
  const worker = new DeviceOwnershipSagaWorker(
    repository,
    registerDevice,
    compensation,
  );
  const sagaId = await repository.record({
    deviceUuid: "device-1",
    sagaType: "OWNERSHIP_TRANSFER",
    toOrganizationId: "org-2",
    fromOrganizationId: "org-1",
  });
  let now = 0;
  for (let i = 0; i < MAX_ATTEMPTS_BEFORE_COMPENSATION; i += 1) {
    await worker.runOnce(new Date(now));
    now += 60_000;
  }
  assert.equal(repository.stateOf(sagaId), "COMPENSATED");
  assert.deepEqual(reverted, [
    { deviceUuid: "device-1", toOrganizationId: "org-1" },
  ]);
  assert.equal(retired.length, 0);
});

test("DEVICE_CREATION and CLAIM_CONSUMPTION compensate by retiring the device, not reverting ownership", async () => {
  for (const sagaType of ["DEVICE_CREATION", "CLAIM_CONSUMPTION"] as const) {
    const repository = new MemoryDeviceOwnershipSagaRepository();
    const registerDevice: SagaRegisterDevice = {
      async registerDevice() {
        throw new Error("access-service is down");
      },
    };
    const { compensation, reverted, retired } = compensationRecorder();
    const worker = new DeviceOwnershipSagaWorker(
      repository,
      registerDevice,
      compensation,
    );
    const sagaId = await repository.record({
      deviceUuid: "device-1",
      sagaType,
      toOrganizationId: "org-1",
    });
    let now = 0;
    for (let i = 0; i < MAX_ATTEMPTS_BEFORE_COMPENSATION; i += 1) {
      await worker.runOnce(new Date(now));
      now += 60_000;
    }
    assert.equal(repository.stateOf(sagaId), "COMPENSATED");
    assert.deepEqual(retired, ["device-1"]);
    assert.equal(reverted.length, 0);
  }
});

test("PHYSICAL_UNPAIR_NOTIFY retries indefinitely and never compensates", async () => {
  const repository = new MemoryDeviceOwnershipSagaRepository();
  const registerDevice: SagaRegisterDevice = {
    async registerDevice() {
      throw new Error("should never be called for this saga type");
    },
  };
  const { compensation, reverted, retired } = compensationRecorder();
  const notified: Array<{ organizationId: string; commandId: string }> = [];
  let failUntilAttempt = MAX_ATTEMPTS_BEFORE_COMPENSATION + 3;
  const notifyUnpair: SagaNotifyUnpair = {
    async notify(input) {
      failUntilAttempt -= 1;
      if (failUntilAttempt > 0) throw new Error("realtime-service unreachable");
      notified.push(input);
    },
  };
  const worker = new DeviceOwnershipSagaWorker(
    repository,
    registerDevice,
    compensation,
    notifyUnpair,
  );
  const sagaId = await repository.record({
    deviceUuid: "device-1",
    sagaType: "PHYSICAL_UNPAIR_NOTIFY",
    toOrganizationId: "org-1",
    eventId: "11111111-1111-4111-8111-111111111111",
  });
  let now = 0;
  for (let i = 0; i < MAX_ATTEMPTS_BEFORE_COMPENSATION + 3; i += 1) {
    await worker.runOnce(new Date(now));
    now += 60_000;
  }
  // Retried past MAX_ATTEMPTS_BEFORE_COMPENSATION without ever compensating
  // -- a physical unpair already happened on the device; there is nothing
  // to revert, only a notification to keep retrying until it's delivered.
  assert.equal(repository.stateOf(sagaId), "COMPLETED");
  assert.equal(reverted.length, 0);
  assert.equal(retired.length, 0);
  assert.deepEqual(notified, [
    {
      organizationId: "org-1",
      commandId: "11111111-1111-4111-8111-111111111111",
    },
  ]);
});

test("runOnce returns false when there is nothing pending", async () => {
  const repository = new MemoryDeviceOwnershipSagaRepository();
  const registerDevice: SagaRegisterDevice = {
    async registerDevice() {},
  };
  const { compensation } = compensationRecorder();
  const worker = new DeviceOwnershipSagaWorker(
    repository,
    registerDevice,
    compensation,
  );
  assert.equal(await worker.runOnce(), false);
});
