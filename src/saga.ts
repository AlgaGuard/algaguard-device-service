import { randomUUID } from "node:crypto";

export type SagaType =
  | "DEVICE_CREATION"
  | "CLAIM_CONSUMPTION"
  | "OWNERSHIP_TRANSFER"
  | "PHYSICAL_UNPAIR_NOTIFY";

export type SagaState =
  "PENDING" | "IN_FLIGHT" | "COMPLETED" | "COMPENSATING" | "COMPENSATED";

export interface NewSaga {
  deviceUuid: string;
  sagaType: SagaType;
  toOrganizationId: string;
  fromOrganizationId?: string;
  eventId?: string;
}

export interface SagaClaim {
  sagaId: string;
  deviceUuid: string;
  sagaType: SagaType;
  toOrganizationId: string;
  fromOrganizationId?: string;
  eventId?: string;
  attempts: number;
}

export interface DeviceOwnershipSagaRepository {
  claim(now?: Date): Promise<SagaClaim | undefined>;
  complete(sagaId: string): Promise<void>;
  retry(sagaId: string, reason: string, retryAt: Date): Promise<void>;
  startCompensating(sagaId: string): Promise<void>;
  markCompensated(sagaId: string): Promise<void>;
}

// Step 1 (RegisterResource with access-service) is retried with capped
// exponential backoff up to this many attempts before the saga gives up and
// compensates -- roughly a few minutes of retrying, matching
// command-service's outbox tolerance for a transient access-service outage
// without leaving a device claimed-but-unusable indefinitely.
export const MAX_ATTEMPTS_BEFORE_COMPENSATION = 8;

export function backoffMs(attempts: number) {
  return Math.min(30_000, 250 * 2 ** Math.min(attempts, 7));
}

export interface SagaRegisterDevice {
  registerDevice(
    deviceUuid: string,
    organizationId: string,
    correlationId?: string,
  ): Promise<void>;
}

export interface SagaNotifyUnpair {
  notify(input: { organizationId: string; commandId: string }): Promise<void>;
}

export interface SagaCompensation {
  // OWNERSHIP_TRANSFER: revert devices.organization_id back to
  // fromOrganizationId without recording a new saga (this IS the
  // compensation, not a fresh user-initiated transfer).
  revertOwnership(deviceUuid: string, toOrganizationId: string): Promise<void>;
  // DEVICE_CREATION / CLAIM_CONSUMPTION: the device was never successfully
  // registered with access-service, so no permission check will ever
  // resolve it as owned by anyone -- revoke it rather than leaving an
  // orphaned, unusable claimed/active device behind.
  retireDevice(deviceUuid: string, actorSubjectId: string): Promise<void>;
}

export class DeviceOwnershipSagaWorker {
  constructor(
    private readonly repository: DeviceOwnershipSagaRepository,
    private readonly registerDevice: SagaRegisterDevice,
    private readonly compensation: SagaCompensation,
    private readonly notifyUnpair?: SagaNotifyUnpair,
  ) {}

  async runOnce(now = new Date()): Promise<boolean> {
    const item = await this.repository.claim(now);
    if (!item) return false;
    try {
      await this.execute(item);
      await this.repository.complete(item.sagaId);
      return true;
    } catch (error) {
      const message =
        error instanceof Error ? error.message.slice(0, 256) : "saga failed";
      const canCompensate = item.sagaType !== "PHYSICAL_UNPAIR_NOTIFY";
      if (canCompensate && item.attempts >= MAX_ATTEMPTS_BEFORE_COMPENSATION) {
        await this.compensate(item);
        return false;
      }
      await this.repository.retry(
        item.sagaId,
        message,
        new Date(now.getTime() + backoffMs(item.attempts)),
      );
      return false;
    }
  }

  private async execute(item: SagaClaim) {
    switch (item.sagaType) {
      case "DEVICE_CREATION":
      case "CLAIM_CONSUMPTION":
      case "OWNERSHIP_TRANSFER":
        await this.registerDevice.registerDevice(
          item.deviceUuid,
          item.toOrganizationId,
        );
        return;
      case "PHYSICAL_UNPAIR_NOTIFY":
        if (!this.notifyUnpair || !item.eventId) return;
        await this.notifyUnpair.notify({
          organizationId: item.toOrganizationId,
          commandId: item.eventId,
        });
        return;
    }
  }

  private async compensate(item: SagaClaim) {
    await this.repository.startCompensating(item.sagaId);
    if (item.sagaType === "OWNERSHIP_TRANSFER" && item.fromOrganizationId) {
      await this.compensation.revertOwnership(
        item.deviceUuid,
        item.fromOrganizationId,
      );
    } else {
      await this.compensation.retireDevice(item.deviceUuid, "saga-worker");
    }
    await this.repository.markCompensated(item.sagaId);
  }
}

interface MemorySagaRow extends SagaClaim {
  state: SagaState;
  nextAttemptAt: number;
  lockedUntil?: number;
}

export class MemoryDeviceOwnershipSagaRepository implements DeviceOwnershipSagaRepository {
  private readonly sagas = new Map<string, MemorySagaRow>();

  async record(input: NewSaga) {
    const sagaId = randomUUID();
    this.sagas.set(sagaId, {
      sagaId,
      deviceUuid: input.deviceUuid,
      sagaType: input.sagaType,
      toOrganizationId: input.toOrganizationId,
      ...(input.fromOrganizationId
        ? { fromOrganizationId: input.fromOrganizationId }
        : {}),
      ...(input.eventId ? { eventId: input.eventId } : {}),
      attempts: 0,
      state: "PENDING",
      nextAttemptAt: 0,
    });
    return sagaId;
  }

  async claim(now = new Date()) {
    const nowMs = now.getTime();
    for (const row of this.sagas.values()) {
      if (row.state !== "PENDING" || row.nextAttemptAt > nowMs) continue;
      row.state = "IN_FLIGHT";
      row.attempts += 1;
      row.lockedUntil = nowMs + 30_000;
      return { ...row };
    }
    return undefined;
  }

  async complete(sagaId: string) {
    const row = this.sagas.get(sagaId);
    if (row) row.state = "COMPLETED";
  }

  async retry(sagaId: string, _reason: string, retryAt: Date) {
    const row = this.sagas.get(sagaId);
    if (!row) return;
    row.state = "PENDING";
    row.nextAttemptAt = retryAt.getTime();
    delete row.lockedUntil;
  }

  async startCompensating(sagaId: string) {
    const row = this.sagas.get(sagaId);
    if (row) row.state = "COMPENSATING";
  }

  async markCompensated(sagaId: string) {
    const row = this.sagas.get(sagaId);
    if (row) row.state = "COMPENSATED";
  }

  stateOf(sagaId: string) {
    return this.sagas.get(sagaId)?.state;
  }
}
