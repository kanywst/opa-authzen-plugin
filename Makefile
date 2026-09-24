GO := go
PKG := github.com/kanywst/opa-authzen-plugin

BIN := opa-authzen-plugin

.PHONY: all
all: build

.PHONY: build
build:
	$(GO) build -o $(BIN) ./cmd/opa-authzen-plugin

.PHONY: test
test:
	$(GO) test -v ./...

# The release matrix, the asset names, the checksums, the SBOM and the
# signature all live in .goreleaser.yaml. This target runs the same pipeline
# locally in snapshot mode so a release can be inspected before it is tagged;
# signing is skipped because keyless signing needs a CI OIDC token.
.PHONY: release
release:
	$(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean --skip=sign

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -rf dist .authzen-spec

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

# Tool versions. These are deliberately not tracked in go.mod: golangci-lint and
# go-licenses are programs, not importable packages, so a require directive only
# bloats the dependency graph of anyone importing ./plugin.
GOLANGCI_LINT_VERSION ?= v2.12.2
GO_LICENSES_VERSION ?= v1.6.0
GORELEASER_VERSION ?= v2.18.0

.PHONY: print-golangci-lint-version
print-golangci-lint-version:
	@echo $(GOLANGCI_LINT_VERSION)

.PHONY: print-goreleaser-version
print-goreleaser-version:
	@echo $(GORELEASER_VERSION)

.PHONY: lint
lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

.PHONY: licenses
licenses:
	$(GO) run github.com/google/go-licenses@$(GO_LICENSES_VERSION) check ./...

IMAGE := ghcr.io/kanywst/opa-authzen-plugin
DOCKER_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE):$(DOCKER_VERSION) .

# --addr is not optional here: OPA binds localhost by default, which a published
# port cannot reach from outside the container.
.PHONY: docker-run
docker-run:
	docker run --rm -p 8181:8181 \
		-v $(PWD)/example:/example:ro \
		$(IMAGE):$(DOCKER_VERSION) \
		run --server --addr 0.0.0.0:8181 --config-file /example/config.yaml /example/policy.rego

# Conformance against the AuthZEN working group's own artifacts, fetched at a
# pinned commit because openid/authzen carries no license to vendor under.
# Bump the ref deliberately and re-run the target when you do.
AUTHZEN_SPEC_REF ?= 6ed00bad5daa8f6eef6f2aef1f124442beeb8382
AUTHZEN_SPEC_DIR := .authzen-spec

.PHONY: authzen-spec
authzen-spec:
	@build/fetch-sparse.sh https://github.com/openid/authzen.git $(AUTHZEN_SPEC_REF) $(AUTHZEN_SPEC_DIR) \
		/api/schemas/ /interop/authzen-todo-backend/

# Checks requests and responses against the published evaluation JSON Schemas.
.PHONY: test-contract
test-contract: authzen-spec
	AUTHZEN_SPEC_DIR=$(abspath $(AUTHZEN_SPEC_DIR)) $(GO) test -v -run 'TestSpecSchema' ./internal/

.PHONY: test-interop
test-interop: docker-build
	@echo "==> Running opa-authzen-interop E2E tests"
	@rm -rf .interop-test
	@git clone --depth 1 https://github.com/kanywst/opa-authzen-interop.git .interop-test
	@$(MAKE) -C .interop-test integration-test PDP_IMAGE=$(IMAGE) PDP_VERSION=$(DOCKER_VERSION)
	@rm -rf .interop-test
