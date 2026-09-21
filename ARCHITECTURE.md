# Stargate architecture

The detailed design is [specs/000-architecture/spec.md](specs/000-architecture/spec.md).
It is subordinate to the [constitution](.specify/memory/constitution.md). Concrete build/runtime
pins remain binding in that design and the reviewed build inputs; this entry point does not
duplicate them or claim every planned component is implemented.

The two primary services are the Go data plane and Java/Quarkus control plane, communicating
through authenticated versioned gRPC over Unix sockets. The browser extension selects each route;
sidecars supply the underlying network protocols. Proxy listeners, sidecar capabilities, auth
recovery and retained data must meet the constitution's explicit boundaries.

For the current Tor slice, use the [foundation contract](specs/001-tor-route/contracts/foundation-boundaries.md),
[Constitution Check](specs/001-tor-route/plan.md#constitution-check--t156-target-implementation-not-yet-compliant)
and [implementation queue](specs/001-tor-route/remaining-implementation-plan.md).
The September audit found unresolved deployment, isolation, authentication and evidence gaps.
For Tor port 8881, the reviewed T172 target supports authenticated SOCKS5 only. HTTP
CONNECT first byte `C` closes with no response, auth evaluation, counter or upstream dial;
T173 must still replace the current conflicting code and measure the deployed result.
Older sketches are not proof that the current stack meets the target design. Foundation repair
and T155 precede further feature implementation; T078/T079 remain final cumulative reviews.
