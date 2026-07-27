---
id: 20260727-009-maven-wrapper-no-checksum
status: open
severity: major
principle: [IV, VI]
threat-model: n/a — build-integrity surface
location: control-plane/.mvn/wrapper/maven-wrapper.properties
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# Maven wrapper downloads the Maven distribution with no checksum pin

## What the code does

```properties
distributionType=only-script
distributionUrl=https://repo.maven.apache.org/maven2/.../apache-maven-3.9.14-bin.zip
```

```
$ grep -i sha256 control-plane/.mvn/wrapper/maven-wrapper.properties
(no match)
```

`mvnw` **supports and validates** `distributionSha256Sum` — its own script does the check at
`control-plane/mvnw:225-247`. The properties file simply does not set it. So every `./mvnw`
invocation — including the `control-plane` gate in `scripts/verify.sh` and any release build
— fetches a Maven 3.9.14 zip over the network and executes it with zero integrity
verification.

## Why it leaks

A registry compromise, CDN cache poisoning, or MITM on the download yields a trojaned Maven
that builds the control plane, including its eventual native image. That is arbitrary code
execution inside the build TCB, on a component the project otherwise pins carefully
(Quarkus `3.33.1`, JDK `25`, and all plugin versions *are* pinned in the poms — the gap is
specifically the wrapper distribution).

Constitution Principle IV (pinned, verified external components) and Principle VI
(reproducible, auditable builds).

## Suggested fix

Add both checksums to `control-plane/.mvn/wrapper/maven-wrapper.properties`:

```properties
distributionSha256Sum=<sha256 of apache-maven-3.9.14-bin.zip>
wrapperSha256Sum=<sha256 of the wrapper script>
```

Have `scripts/ground-check.sh` assert both keys are present and non-empty, so a future
wrapper upgrade cannot drop them silently.

## Regression test

A contract assertion in `ground-check.sh` (which already grounds external pins) that
`maven-wrapper.properties` contains `distributionSha256Sum` and `wrapperSha256Sum`.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S8).
- Same Principle IV root cause as 20260727-005, 20260727-006, 20260727-002.
