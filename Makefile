GO ?= go
BINARY := nx

.PHONY: all build frontend test verify clean cross
all: build
frontend:
	cd web && npm ci --no-audit --no-fund && npm run build
build: frontend
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/nx
test:
	$(GO) test ./...
verify:
	test -z "$$($(GO)fmt -l .)"
	$(GO) vet ./...
	$(GO) build ./...
	$(GO) test ./...
cross: frontend
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o nx-linux-amd64 ./cmd/nx
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o nx-linux-arm64 ./cmd/nx
clean:
	rm -f nx nx-linux-amd64 nx-linux-arm64 hydra-backup-*.tar.gz
