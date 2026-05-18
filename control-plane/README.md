# control-plane

The Quarkus app (the **control plane**) that loads `tokens.yaml`, observes sidecar lifecycle via gRPC, writes the audit log, and exposes a healthcheck. No request-data ever flows through here.

Per Constitution Principle II, the **data plane keeps routing even if this process is down**, so failure modes here are bounded to admin/config concerns. `ui/` is an empty stub in v1 — admin UI lands in a later feature.
