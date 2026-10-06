GO ?= go
CONTAINER ?= docker
KERNEL_TEST_IMAGE ?= router-policy-agent-kernel-test:local
VERSION ?= dev
LDFLAGS = -X github.com/mikenorgate/router-policy-agent/internal/cli.Version=$(VERSION)

.PHONY: build test integration kernel vet fmt fuzz lint security check help

## build: Build available command-line tools
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

## test: Run unit tests, race detection and coverage
test:
	$(GO) test -race -coverprofile=coverage.out ./...

## integration: Run native Linux IPC tests (cross-UID case requires isolated root)
integration:
	$(GO) test -race -shuffle=on -count=1 -tags integration -coverprofile=coverage.out ./...

## kernel: Qualify nftables updates in an isolated disposable container (never host networking)
kernel:
	$(CONTAINER) build --file packaging/Containerfile.kernel --tag $(KERNEL_TEST_IMAGE) packaging
	$(CONTAINER) run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
		--security-opt no-new-privileges \
		--env ROUTER_POLICY_KERNEL_TEST=isolated \
		--mount type=bind,src="$(CURDIR)",dst=/workspace,readonly \
		--workdir /workspace $(KERNEL_TEST_IMAGE) \
		go test -race -shuffle=on -count=1 -tags integration,kernel ./internal/firewall

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
	$(GO) test ./internal/firewall -run '^$$' -fuzz FuzzBatch -fuzztime 10s
	$(GO) test ./internal/firewall -run '^$$' -fuzz FuzzInventory -fuzztime 10s

## check: Run tests and static checks
check: test vet

## lint: Run the pinned golangci-lint tool (install instructions in CI workflow)
lint:
	golangci-lint run --build-tags integration,kernel ./...

## security: Scan reachable dependencies (install instructions in CI workflow)
security:
	govulncheck ./...

## help: List targets
help:
	@sed -n 's/^## //p' Makefile
