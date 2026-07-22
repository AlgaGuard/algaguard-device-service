import { randomUUID } from "node:crypto";
import express, {
  type ErrorRequestHandler,
  type RequestHandler,
} from "express";
import { trace } from "@opentelemetry/api";
import pino from "pino";
import { router } from "./routes.js";

const logger = pino({ level: process.env.LOG_LEVEL ?? "info" });
const requestContext: RequestHandler = (request, response, next) => {
  const supplied = request.header("x-correlation-id");
  const correlationId =
    supplied && supplied.length <= 128 ? supplied : randomUUID();
  response.setHeader("x-correlation-id", correlationId);
  const span = trace
    .getTracer("algaguard-device-service")
    .startSpan(`${request.method} ${request.path}`);
  const startedAt = Date.now();
  response.on("finish", () => {
    logger.info(
      {
        correlationId,
        method: request.method,
        path: request.path,
        status: response.statusCode,
        durationMs: Date.now() - startedAt,
      },
      "request completed",
    );
    span.end();
  });
  next();
};

export function buildApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "256kb" }));
  app.use(requestContext);
  app.get("/health/live", (_request, response) =>
    response.json({ status: "UP", service: "algaguard-device-service" }),
  );
  app.get("/health/ready", (_request, response) =>
    response.json({
      status: "READY",
      service: "algaguard-device-service",
      dependencies: "configured",
    }),
  );
  app.use("/v1", router);
  app.use((_request, response) =>
    response
      .status(404)
      .type("application/problem+json")
      .json({ type: "about:blank", title: "Not Found", status: 404 }),
  );
  const errors: ErrorRequestHandler = (error, _request, response, _next) => {
    logger.error({ err: error }, "request failed");
    response.status(500).type("application/problem+json").json({
      type: "about:blank",
      title: "Internal Server Error",
      status: 500,
    });
  };
  app.use(errors);
  return app;
}
