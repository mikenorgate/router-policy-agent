GO ?= go
VERSION ?= dev
LDFLAGS = -X github.com/mikenorgate/router-policy-agent/internal/cli.Version=$(VERSION)

.PHONY: build test integration vet fmt fuzz lint security check help

## build: Build available command-line tools
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

## test: Run unit tests, race detection and coverage
test:
	$(GO) test -race -coverprofile=coverage.out ./...

## integration: Run native Linux IPC tests (cross-UID case requires isolated root)
integration:
	$(GO) test -race -shuffle=on -count=1 -tags integration -coverprofile=coverage.out ./...

## vet: Run Go static checks
vet:
	$(GO) vet ./...

## fmt: Format Go source
fmt:
	gofmt -w cmd internal

## fuzz: Exercise policy, protocol and durable-state fuzz properties
fuzz:
	$(GO) test ./internal/strictjson -run '^$$' -fuzz FuzzDecode -fuzztime 10s
	$(GO) test ./internal/policy -run '^$$' -fuzz FuzzParseGroup -fuzztime 10s
	$(GO) test ./internal/policy -run '^$$' -fuzz FuzzResolve -fuzztime 10s
	$(GO) test ./internal/state -run '^$$' -fuzz FuzzDecode -fuzztime 10s
	$(GO) test ./internal/ipc -run '^$$' -fuzz FuzzRequest -fuzztime 10s
	$(GO) test ./internal/ipc -run '^$$' -fuzz FuzzFrame -fuzztime 10s

## check: Run tests and static checks
check: test vet

## lint: Run the pinned golangci-lint tool (install instructions in CI workflow)
lint:
	golangci-lint run --build-tags integration ./...

## security: Scan reachable dependencies (install instructions in CI workflow)
security:
	govulncheck ./...

## help: List targets
help:
	@sed -n 's/^## //p' Makefile
