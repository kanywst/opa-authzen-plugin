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

VERSION ?= $(shell ./build/get-opa-version.sh)$(shell ./build/get-plugin-rev.sh)
RELEASE_DIR ?= _release/$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: release
release:
	@mkdir -p $(RELEASE_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -o $(RELEASE_DIR)/opa_authzen_$${os}_$${arch}$${ext} ./cmd/opa-authzen-plugin; \
	done

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -rf _release

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

IMAGE := ghcr.io/kanywst/opa-authzen-plugin
DOCKER_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE):$(DOCKER_VERSION) .

.PHONY: docker-run
docker-run:
	docker run --rm -p 8181:8181 \
		-v $(PWD)/example:/example:ro \
		$(IMAGE):$(DOCKER_VERSION) \
		run --server --config-file /example/config.yaml /example/policy.rego

.PHONY: test-interop
test-interop: docker-build
	@echo "==> Running opa-authzen-interop E2E tests"
	@rm -rf .interop-test
	@git clone --depth 1 https://github.com/kanywst/opa-authzen-interop.git .interop-test
	@$(MAKE) -C .interop-test integration-test PDP_IMAGE=$(IMAGE) PDP_VERSION=$(DOCKER_VERSION)
	@rm -rf .interop-test
