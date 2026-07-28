import fs from "node:fs";
import path from "node:path";
const contractRoot = path.resolve(
  process.env.CONTRACTS_DIR ?? "../algaguard-contracts",
);
const required = [
  "schemas/common/event-envelope-v1.schema.json",
  "schemas/websocket/realtime-envelope-v1.schema.json",
  "asyncapi/algaguard-mqtt-v1.yaml",
  "asyncapi/algaguard-websocket-v1.yaml",
  "schemas/onboarding/claim-qr-v1.schema.json",
  "schemas/onboarding/bootstrap-session-v1.schema.json",
  "schemas/onboarding/bootstrap-token-exchange-request-v1.schema.json",
  "schemas/onboarding/bootstrap-token-exchange-response-v1.schema.json",
  "schemas/onboarding/ble-provisioning-request-v1.schema.json",
  "schemas/onboarding/ble-provisioning-result-v1.schema.json",
  "schemas/onboarding/physical-session-handoff-start-request-v1.schema.json",
  "schemas/onboarding/physical-session-handoff-start-response-v1.schema.json",
  "schemas/onboarding/physical-session-handoff-approve-request-v1.schema.json",
  "schemas/onboarding/physical-session-handoff-redeem-request-v1.schema.json",
  "schemas/onboarding/physical-session-handoff-redeem-response-v1.schema.json",
  "schemas/common/device-identity-v1.schema.json",
  "schemas/internal/device-context-v1.schema.json",
];
const missing = required.filter(
  (file) => !fs.existsSync(path.join(contractRoot, file)),
);
if (missing.length > 0)
  throw new Error(`Missing algaguard-contracts files: ${missing.join(", ")}`);
process.stdout.write(
  `Validated ${required.length} required files from algaguard-contracts.\n`,
);
