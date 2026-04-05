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

.PHONY: clean
clean:
	rm -f $(BIN)

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

IMAGE := ghcr.io/kanywst/opa-authzen-plugin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE):$(VERSION) .

.PHONY: docker-run
docker-run:
	docker run --rm -p 8181:8181 \
		-v $(PWD)/example:/example:ro \
		$(IMAGE):$(VERSION) \
		run --server --config-file /example/config.yaml /example/policy.rego
