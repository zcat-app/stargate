# data-plane

The Go binary (the **data plane**) that listens on `127.0.0.1:8881` and forwards bytes to a privacy sidecar (Tor in v1).

Per Constitution Principle I, this is a **dumb router**: no payload parsing, no TLS termination, no local DNS resolution, no header inspection, no per-request logs, no cover traffic. The browser extension decides routing; this code just forwards bytes for the port it received them on.

Per Constitution Principle II, this code must **keep routing if `control-plane/` is unreachable**.
