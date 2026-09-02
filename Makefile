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
	rm -rf dist

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

.PHONY: test-interop
test-interop: docker-build
	@echo "==> Running opa-authzen-interop E2E tests"
	@rm -rf .interop-test
	@git clone --depth 1 https://github.com/kanywst/opa-authzen-interop.git .interop-test
	@$(MAKE) -C .interop-test integration-test PDP_IMAGE=$(IMAGE) PDP_VERSION=$(DOCKER_VERSION)
	@rm -rf .interop-test
