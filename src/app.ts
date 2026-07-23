import { randomUUID } from "node:crypto";
import { trace } from "@opentelemetry/api";
import express, {
  type ErrorRequestHandler,
  type RequestHandler,
} from "express";
import pino from "pino";
import { ZodError } from "zod";
import { AuthenticationError } from "./auth.js";
import { DomainError } from "./domain.js";
import { createRouter, type RouteDependencies } from "./routes.js";

const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: [
    "req.headers.authorization",
    "claimCode",
    "sessionToken",
    "password",
    "token",
    "bootstrapToken",
    "csrPem",
    "currentCertificatePem",
    "certificatePem",
    "privateKey",
    "privateKeyPem",
  ],
});

const requestContext: RequestHandler = (request, response, next) => {
  const supplied = request.header("x-correlation-id");
  const correlationId =
    supplied && supplied.length <= 128 ? supplied : randomUUID();
  request.headers["x-correlation-id"] = correlationId;
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

export function buildApp(dependencies: RouteDependencies) {
  const app = express();
  app.disable("x-powered-by");
  app.use(
    express.json({
      limit:
        dependencies.httpBodyLimit ?? process.env.HTTP_BODY_LIMIT ?? "256kb",
    }),
  );
  app.use(requestContext);
  app.get("/health/live", (_request, response) =>
    response.json({ status: "UP", service: "algaguard-device-service" }),
  );
  app.get("/health/ready", async (_request, response) => {
    try {
      await dependencies.repository.health();
      response.json({
        status: "READY",
        service: "algaguard-device-service",
        dependencies: { postgres: "UP" },
      });
    } catch {
      response.status(503).json({
        status: "NOT_READY",
        service: "algaguard-device-service",
        dependencies: { postgres: "DOWN" },
      });
    }
  });
  app.use("/v1", createRouter(dependencies));
  app.use((_request, response) =>
    response.status(404).type("application/problem+json").json({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      code: "NOT_FOUND",
    }),
  );
  const errors: ErrorRequestHandler = (error, _request, response, _next) => {
    const status =
      error instanceof DomainError
        ? error.status
        : error instanceof AuthenticationError
          ? 401
          : error instanceof ZodError
            ? 400
            : 500;
    const code =
      error instanceof DomainError
        ? error.code
        : error instanceof AuthenticationError
          ? "UNAUTHENTICATED"
          : error instanceof ZodError
            ? "VALIDATION_ERROR"
            : "INTERNAL_ERROR";
    const requestCorrelationId =
      response.getHeader("x-correlation-id")?.toString() ?? randomUUID();
    if (status >= 500)
      logger.error(
        {
          errorName: error instanceof Error ? error.name : "Unknown",
          correlationId: requestCorrelationId,
        },
        "request failed",
      );
    response
      .status(status)
      .type("application/problem+json")
      .json({
        type: "about:blank",
        title:
          status === 500
            ? "Internal Server Error"
            : error instanceof Error
              ? error.message
              : "Request failed",
        status,
        code,
        correlationId: requestCorrelationId,
      });
  };
  app.use(errors);
  return app;
}
