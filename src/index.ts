import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
const config = loadConfig();
const server = buildApp().listen(config.PORT, () => {
  process.stdout.write(
    JSON.stringify({
      level: "info",
      service: "algaguard-device-service",
      message: "listening",
      port: config.PORT,
    }) + "\n",
  );
});
async function shutdown(signal: string) {
  process.stdout.write(
    JSON.stringify({
      level: "info",
      service: "algaguard-device-service",
      message: "shutdown",
      signal,
    }) + "\n",
  );
  server.close((error) => process.exit(error ? 1 : 0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
