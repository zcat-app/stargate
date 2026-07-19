# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

# Makefile for the Stargate data plane (Go).
#
# All build targets MUST produce byte-reproducible output (arch §12.1):
# the same source tree compiled with the same toolchain (go1.26.3, pinned
# in go.mod per research.md §1) MUST yield the same binary bytes
# regardless of build host, build directory, build time, or VCS state.
# The flags below are what enforces that:
#
#   -trimpath            strip the build's filesystem paths from the
#                        binary (otherwise the absolute path of the
#                        source tree is embedded and differs per host).
#   -buildvcs=false      do not embed VCS information (commit SHA, dirty
#                        flag) into the binary; reproducibility must not
#                        depend on git state.
#   -ldflags=-buildid=   zero out the build-id symbol that Go embeds by
#                        default (varies across otherwise-identical
#                        builds).
#   CGO_ENABLED=0        disable cgo so the binary is statically linked
#                        and does not depend on the host libc's ABI
#                        (Principle IV — pinned toolchain implies pinned
#                        output).
#
# Verified by tests/reproducibility/data_plane_test.sh (T075): build twice
# into separate directories and `cmp` the two binaries byte-for-byte.

GO            ?= go
BIN_DIR       := bin
BINARY        := $(BIN_DIR)/stargate-proxy
MAIN_PACKAGE  := ./cmd/stargate-proxy

BUILD_FLAGS   := -trimpath -buildvcs=false
LDFLAGS       := -ldflags=-buildid=

export CGO_ENABLED := 0

.PHONY: all build clean test vet tidy verify

all: build

build: | $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BINARY) $(MAIN_PACKAGE)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)

test:
	$(GO) test $(BUILD_FLAGS) ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

verify:
	$(GO) mod verify
