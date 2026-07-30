import pg from "pg";
import { loadConfig } from "./config.js";
import {
  createDemoBatch,
  DemoSampleBuffer,
  DemoTelemetryGenerator,
  type DemoDeviceContext,
} from "./demo-telemetry-simulator.js";

const config = loadConfig();
if (config.ALGAGUARD_ENABLE_DEMO_TELEMETRY_SIMULATOR !== "1") {
  process.stdout.write("DEMO_SIMULATOR_DISABLED\n");
  process.exit(0);
}

const pool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 2 });
const lockClient = await pool.connect();
let timer: NodeJS.Timeout | undefined;
let stopping = false;
const startedAt = new Date();

async function selectTarget(): Promise<DemoDeviceContext> {
  const result = await lockClient.query(
    `SELECT device_uuid::text AS "deviceUuid", device_id AS "deviceId",
            organization_id::text AS "organizationId",
            ownership_version::text AS "ownershipVersion"
       FROM devices
      WHERE lifecycle = 'CLAIMED' AND organization_id IS NOT NULL
      ORDER BY device_id LIMIT 2`,
  );
  if (result.rowCount !== 1)
    throw new Error("exactly one claimed development device is required");
  return result.rows[0] as DemoDeviceContext;
}

async function acquireLock(context: DemoDeviceContext) {
  const result = await lockClient.query<{ locked: boolean }>(
    "SELECT pg_try_advisory_lock(hashtext($1)) AS locked",
    [`algaguard-demo-simulator:${context.deviceUuid}`],
  );
  if (!result.rows[0]?.locked)
    throw new Error("a demo simulator is already active for the target device");
}

async function nextSequence(context: DemoDeviceContext) {
  const result = await lockClient.query<{ maximum: string | null }>(
    `SELECT max(sequence)::text AS maximum
       FROM telemetry_samples WHERE device_uuid = $1`,
    [context.deviceUuid],
  );
  return BigInt(result.rows[0]?.maximum ?? "0") + 1n;
}

async function serviceToken() {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.SERVICE_CLIENT_ID!,
    client_secret: config.SERVICE_CLIENT_SECRET!,
  });
  const response = await fetch(config.KEYCLOAK_TOKEN_URL!, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) throw new Error("service authentication failed");
  const value = (await response.json()) as { access_token?: unknown };
  if (typeof value.access_token !== "string" || value.access_token.length < 32)
    throw new Error("service authentication response was invalid");
  return value.access_token;
}

async function publish(
  context: DemoDeviceContext,
  samples: ReturnType<DemoTelemetryGenerator["sample"]>[],
) {
  let token = await serviceToken();
  try {
    const response = await fetch(
      `${config.TELEMETRY_SERVICE_URL}/v1/ingestion/batches`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(createDemoBatch(context, samples)),
      },
    );
    if (response.status !== 202)
      throw new Error("telemetry ingestion rejected the demo batch");
  } finally {
    token = "";
  }
}

async function shutdown() {
  if (stopping) return;
  stopping = true;
  if (timer) clearInterval(timer);
  await lockClient
    .query("SELECT pg_advisory_unlock_all()")
    .catch(() => undefined);
  lockClient.release();
  await pool.end();
  process.stdout.write("DEMO_SIMULATOR_STOPPED\n");
}

try {
  const context = await selectTarget();
  await acquireLock(context);
  let sequence = await nextSequence(context);
  const generator = new DemoTelemetryGenerator();
  const buffer = new DemoSampleBuffer();
  let running = false;
  timer = setInterval(() => {
    if (running || stopping) return;
    running = true;
    void (async () => {
      const sample = generator.sample(sequence++, new Date(), startedAt);
      buffer.add(sample);
      if (buffer.ready()) await publish(context, buffer.take());
    })()
      .catch(() => {
        buffer.clear();
        process.stderr.write("DEMO_SIMULATOR_FAILED\n");
      })
      .finally(() => {
        running = false;
      });
  }, 1000);
  process.stdout.write("DEMO_SIMULATOR_RUNNING\n");
} catch {
  process.stderr.write("DEMO_SIMULATOR_FAILED\n");
  await shutdown();
  process.exit(1);
}

process.on("SIGTERM", () => void shutdown().then(() => process.exit(0)));
process.on("SIGINT", () => void shutdown().then(() => process.exit(0)));
