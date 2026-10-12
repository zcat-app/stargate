# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# control-plane/Dockerfile — Stargate Quarkus control-plane container.
#
# Multi-stage build:
#   1. builder stage uses maven:3.9-eclipse-temurin-25 (Maven 3.9.x
#      bundled with Eclipse Temurin 25 LTS — research.md §1,
#      constitution v1.1.0) to run `mvn -B -DskipTests package` against
#      the multi-module reactor from T003. Quarkus 3.40 emits the
#      fast-jar layout at runtime/target/quarkus-app/.
#   2. runtime stage is eclipse-temurin:25-jre-noble — official
#      Temurin 25 LTS JRE on Ubuntu Noble. The runtime user
#      `stargate-cp` (UID 5101) is created via shadow-utils with the
#      supplementary group `stargate-ipc` (GID 5100), matching T015's
#      compose `user:` directive and contracts/control-grpc.md
#      §"Socket topology".
#
# Base images are digest-pinned per Principle IV (constitution §IV);
# digests below are the OCI multi-arch indices so amd64 and arm64
# hosts both resolve to the exact tested bytes for their platform.
#
# The T003a task description references `./mvnw -B -DskipTests
# package`. We invoke `mvn` directly instead because (a) T003 does
# not lay down the maven-wrapper files (mvnw, .mvn/wrapper/), and
# (b) pinning the maven:3.9-eclipse-temurin-25 image digest gives us
# Maven + JDK pinned together at the OCI layer rather than via a
# wrapper that downloads Maven at build time.
#
# No EXPOSE or health-probe history (T152 / Constitution III). Current
# health is an authenticated observation, not a Docker probe journal.
# No host port mapping is introduced for the CP (Principle II).
#
# Mandrel 25 is a completed-v1 native-build input; the 001 feature-preview
# uses this JVM runtime and still requires JDK/Quarkus compatibility evidence.
#
# Contract status: `docker build` against this file will fail until
# T040 lands Java sources and activates the quarkus-maven-plugin in
# runtime/. The output digest belongs in T081's separate signed release
# data and derived digest-pinned Compose, never source local Compose.

FROM maven:3.9-eclipse-temurin-25@sha256:1c3a703ab39fee7ac0880f46e6ccd22c0d701f17f0616e6e66a258ddc1c637d2 AS builder

WORKDIR /src

# Dependency lock (T185, Principle IV). The image pin covers Maven and the JDK,
# not what Maven downloads. .mvn/maven.config turns on --strict-checksums and the
# Maven Resolver "trusted checksums" check. Every artifact the build resolves
# (dependency, plugin, annotation processor, build extension, POM, Quarkus
# deployment jar) must match its SHA-256 in .mvn/checksums/checksums.sha256
# before it is used. An unlisted artifact fails the build too (failIfMissing).
# mvn reads .mvn/ from /src, so this COPY must precede every RUN mvn. The same
# file applies to ./mvnw in scripts/verify.sh. Remote SNAPSHOTs are not
# checked; only the release-only Central repository is configured.
# tests/contract/workflow/maven_dependency_lock_test.sh gates this.
#
# Refreshing the lock is a reviewed change, never automatic. Run it after any
# change to a dependency, plugin or the Maven version (wrapper or this image):
#   1. cd control-plane && : > .mvn/checksums/checksums.sha256
#      (start empty so no stale entry survives; record mode only adds lines)
#   2. R=$(mktemp -d); ./mvnw -B -Dmaven.repo.local="$R" \
#        -Daether.artifactResolver.postProcessor.trustedChecksums.record=true \
#        -Dmaven.test.failure.ignore=true clean verify
#      Run this twice. The first pass downloads from Central under strict
#      checksums. Tests that start a child Maven fail on that pass because the
#      lock is only written at the end of the session.
#   2b. Record the arm64 closure too: the base images are multi-arch, and
#      some natives are chosen by the build host's arch (brotli4j via a Maven
#      <os> profile). Run step 2 once more with MAVEN_OPTS=-Dos.arch=aarch64
#      and -Dquarkus.grpc.protoc-os-classifier=linux-x86_64. The second flag
#      keeps an amd64 host able to execute protoc; every protoc classifier is
#      already locked. No amd64 gate resolves the resulting arm64-only
#      entries, so copy their new digests into ARM64_ONLY in
#      tests/contract/workflow/maven_dependency_lock_test.sh. Where an arm64
#      builder or emulator exists, also run step 4 with --platform linux/arm64.
#   3. ./mvnw -B -Dmaven.repo.local="$R" clean verify   (enforcing; must pass)
#   4. docker build -f control-plane/Dockerfile . (from the repo root; this
#      image's own Maven version must pass against the lock too)
#   5. Review the lock diff: each added or changed line is a new executable
#      input and needs a justification in the PR.
COPY control-plane/.mvn ./.mvn

# Pom-first layer: rebuilds only when reactor wiring changes, not when
# Java source changes. Quarkus's quarkus-maven-plugin resolves some
# artefacts at package time (extension processors), so a separate
# `dependency:go-offline` step is best-effort at best and we skip it
# (the lock above still checks those package-time artefacts);
# the structured COPY still gives Docker a stable cache key for the
# poms-only layer. COPY paths are repo-root relative: the build context
# is the REPO ROOT (T122) because the codegen reads the repo-top proto/
# module — WORKDIR /src keeps the in-image layout identical to the old
# ../control-plane context.
COPY control-plane/pom.xml             ./pom.xml
COPY control-plane/api/pom.xml         ./api/pom.xml
COPY control-plane/core/pom.xml        ./core/pom.xml
COPY control-plane/persistence/pom.xml ./persistence/pom.xml
COPY control-plane/runtime/pom.xml     ./runtime/pom.xml
COPY control-plane/ui/pom.xml          ./ui/pom.xml

# Source layer; rebuilds only when Java source actually changes. proto/
# lands at /proto: the api pom's Quarkus gRPC codegen reads
# ${project.basedir}/../../proto/stargate/v1, which from /src/api
# resolves to /proto (T122).
COPY control-plane/api/src         ./api/src
COPY control-plane/core/src        ./core/src
COPY control-plane/persistence/src ./persistence/src
COPY control-plane/runtime/src     ./runtime/src
COPY control-plane/ui/src          ./ui/src
COPY proto/                        /proto/

# JVM-mode package. Byte-reproducibility is the POM's responsibility
# (reproducible-build-maven-plugin, arch §12.2); no Dockerfile flags
# are needed for byte-stable bytecode.
RUN mvn -B -DskipTests -Dmaven.repo.local=/src/.m2 package

# -----------------------------------------------------------------------------

FROM eclipse-temurin:25-jre-noble@sha256:b27ca47660a8fa837e47a8533b9b1a3a430295cf29ca28d91af4fd121572dc29

# stargate-cp (UID 5101) joins the supplementary group stargate-ipc
# (GID 5100). Numerics match T015's compose `user:` directive and
# contracts/control-grpc.md §"Socket topology" exactly. Noble ships
# shadow-utils so the conventional groupadd/useradd pattern works
# without the synth-passwd trick the data-plane (FROM scratch)
# Dockerfile uses.
RUN groupadd --gid 5100 stargate-ipc \
 && useradd  --uid 5101 --gid stargate-ipc \
             --home-dir /opt/stargate \
             --shell /sbin/nologin \
             --no-create-home \
             stargate-cp

# Quarkus 3.40 fast-jar layout: quarkus-run.jar is a thin launcher
# that resolves app/, lib/, and quarkus/ as siblings, so the entire
# quarkus-app/ directory must travel together.
COPY --from=builder --chown=stargate-cp:stargate-ipc \
     /src/runtime/target/quarkus-app/ /opt/stargate/

USER stargate-cp
WORKDIR /opt/stargate
COPY --chmod=0555 control-plane/entrypoint.sh /opt/stargate/entrypoint.sh
ENTRYPOINT ["/opt/stargate/entrypoint.sh"]
