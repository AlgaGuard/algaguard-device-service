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
  "schemas/onboarding/owned-device-bootstrap-reissue-request-v1.schema.json",
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

// gRPC .proto files are loaded at container runtime (@grpc/proto-loader
// reads real files from disk, unlike the JSON schemas above which are only
// checked at CI time), so the Docker image can't rely on a sibling
// algaguard-contracts checkout -- this service vendors its own copy under
// proto/. This check keeps that copy from silently drifting from the
// source of truth.
const vendoredProtos = [
  "common.proto",
  "device_service.proto",
  "access_service.proto",
  "realtime_service.proto",
  "command_service.proto",
];
const protoMismatches = vendoredProtos.filter((file) => {
  const vendored = path.resolve("proto", file);
  const source = path.join(contractRoot, "proto", file);
  if (!fs.existsSync(source)) return true;
  return fs.readFileSync(vendored, "utf8") !== fs.readFileSync(source, "utf8");
});
if (protoMismatches.length > 0)
  throw new Error(
    `Vendored proto/ files differ from algaguard-contracts: ${protoMismatches.join(", ")}`,
  );
process.stdout.write(
  `Validated ${vendoredProtos.length} vendored proto files match algaguard-contracts.\n`,
);
