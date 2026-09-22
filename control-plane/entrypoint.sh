#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# Constitution III: establish the boundary before the JVM/framework can log.
exec >/dev/null 2>&1
ulimit -c 0
unset JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS JAVA_OPTS
exec java -XX:-CreateCoredumpOnCrash -XX:ErrorFile=/dev/null -XX:-HeapDumpOnOutOfMemoryError -jar /opt/stargate/quarkus-run.jar
