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
];
const missing = required.filter(
  (file) => !fs.existsSync(path.join(contractRoot, file)),
);
if (missing.length > 0)
  throw new Error(`Missing algaguard-contracts files: ${missing.join(", ")}`);
process.stdout.write(
  `Validated ${required.length} required files from algaguard-contracts.\n`,
);
