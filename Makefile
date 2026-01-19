# Project variables
PROJECT_NAME := conf-inferencing
GO := go
GOFLAGS := -v
BUILD_DIR := bin

# Binary names
KUBLET_PROXY := kublet-proxy

# Build flags
LDFLAGS := -ldflags "-s -w"

.PHONY: all build clean kublet-proxy help

## all: Build all binaries
all: build

## build: Build all binaries
build: kublet-proxy

## kublet-proxy: Build the kublet-proxy binary
kublet-proxy:
	@echo "Building kublet-proxy..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(KUBLET_PROXY) ./cmd/kublet-proxy

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

## test: Run tests
test:
	$(GO) test -v ./...

## fmt: Format Go code
fmt:
	$(GO) fmt ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
