import { createPostgresPool } from "./adapters.js";
import { buildApp } from "./app.js";
import { createAuthenticator, OidcAccessAuthorizer } from "./auth.js";
import { loadConfig } from "./config.js";
import { DevelopmentCredentialProvider } from "./domain.js";
import { PostgresDeviceRepository } from "./repository.js";

const config = loadConfig();
const repository = new PostgresDeviceRepository(createPostgresPool(config));
const server = buildApp({
  repository,
  authenticate: createAuthenticator(),
  authorize: new OidcAccessAuthorizer(),
  credentials: new DevelopmentCredentialProvider(),
}).listen(config.PORT, () => {
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-device-service", message: "listening", port: config.PORT })}\n`,
  );
});

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-device-service", message: "shutdown", signal })}\n`,
  );
  const deadline = setTimeout(() => process.exit(1), 10_000);
  deadline.unref();
  server.close(async (error) => {
    try {
      await repository.close();
      clearTimeout(deadline);
      process.exit(error ? 1 : 0);
    } catch {
      process.exit(1);
    }
  });
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
