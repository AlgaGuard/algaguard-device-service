import { randomUUID } from "node:crypto";

export const DEMO_SOURCE = "SIMULATED_DEMO" as const;
export const DEMO_PROFILE_VERSION = "1.0.0" as const;
export const DEMO_PROFILE_ID = "d3000000-0000-4000-8000-000000000001";

export interface DemoDeviceContext {
  deviceUuid: string;
  deviceId: string;
  organizationId: string;
  ownershipVersion: string;
}

export interface DemoValues {
  temperatureC: number;
  ph: number;
  lightLux: number;
  nutrientPercent: number;
}

export interface DemoSample {
  sequence: string;
  observedAt: string;
  timestampQuality: "NTP_SYNCED";
  uptimeMs: string;
  values: DemoValues;
  qualityFlags: ["SIMULATED"];
  simulationScenario: "simulated-demo";
  extensions: {
    "algaguard.demo.source": typeof DEMO_SOURCE;
    "algaguard.demo.generated-at": string;
    "algaguard.demo.profile-version": typeof DEMO_PROFILE_VERSION;
  };
}

function rounded(value: number, decimals: number) {
  const scale = 10 ** decimals;
  return Math.round(value * scale) / scale;
}

export class DemoTelemetryGenerator {
  constructor(private readonly seed = 37) {}

  sample(sequence: bigint, generatedAt: Date, startedAt: Date): DemoSample {
    const step = Number((sequence + BigInt(this.seed)) % 10_000n);
    const slow = Math.sin(step / 17);
    const slower = Math.sin(step / 43 + this.seed);
    const values: DemoValues = {
      temperatureC: rounded(24 + slow * 0.8 + slower * 0.2, 2),
      ph: rounded(7.1 + slow * 0.12, 2),
      lightLux: rounded(900 + slow * 110 + slower * 35, 0),
      nutrientPercent: rounded(
        Math.min(100, Math.max(0, 60 + slow * 12 + slower * 4)),
        1,
      ),
    };
    return {
      sequence: sequence.toString(),
      observedAt: generatedAt.toISOString(),
      timestampQuality: "NTP_SYNCED",
      uptimeMs: Math.max(
        0,
        generatedAt.getTime() - startedAt.getTime(),
      ).toString(),
      values,
      qualityFlags: ["SIMULATED"],
      simulationScenario: "simulated-demo",
      extensions: {
        "algaguard.demo.source": DEMO_SOURCE,
        "algaguard.demo.generated-at": generatedAt.toISOString(),
        "algaguard.demo.profile-version": DEMO_PROFILE_VERSION,
      },
    };
  }
}

export function createDemoBatch(
  context: DemoDeviceContext,
  samples: DemoSample[],
) {
  if (samples.length === 0 || samples.length > 120)
    throw new Error("demo batch must contain between 1 and 120 samples");
  return {
    batchId: randomUUID(),
    deviceUuid: context.deviceUuid,
    deviceId: context.deviceId,
    organizationId: context.organizationId,
    ownershipVersion: context.ownershipVersion,
    correlationId: randomUUID(),
    activeProfile: {
      profileId: DEMO_PROFILE_ID,
      profileVersion: DEMO_PROFILE_VERSION,
    },
    samples,
  };
}

export class DemoSampleBuffer {
  private readonly pending: DemoSample[] = [];
  add(sample: DemoSample) {
    if (this.pending.length >= 5) return false;
    this.pending.push(sample);
    return true;
  }
  ready() {
    return this.pending.length === 5;
  }
  take() {
    if (!this.ready()) return [];
    return this.pending.splice(0, this.pending.length);
  }
  clear() {
    this.pending.splice(0, this.pending.length);
  }
  get size() {
    return this.pending.length;
  }
}
