# Development demo telemetry worker

`ALGAGUARD_ENABLE_DEMO_TELEMETRY_SIMULATOR` defaults to `0`. The dedicated
worker refuses to start outside development/test or without its private service
configuration. It discovers exactly one claimed development device, acquires a
PostgreSQL advisory lock for that device, generates a sample each second, and
submits one five-sample batch every five seconds through the existing telemetry
ingestion service. It does not expose an HTTP endpoint or use MQTT/device
credentials.

Samples use the released telemetry contract and carry `qualityFlags:
["SIMULATED"]`, `simulationScenario: "simulated-demo"`, and extension metadata
for `SIMULATED_DEMO`, generation time, and demo profile version. Values are
bounded presentation data, not physical sensor readings or scientifically
validated cultivation ranges. Shutdown clears the timer and releases the lock.
