# Sikur Atlas build entrypoints. Development targets assume Linux (or any
# OS with clang for `bpf`); the agent itself always targets Linux.

GO         ?= go
BPF_CC     ?= clang
# zig users: make bpf BPF_CC="zig cc" BPF_TARGET="-target bpfel-freestanding"
BPF_TARGET ?= --target=bpfel
BPF_CFLAGS  = -g -O2 -D__TARGET_ARCH_x86 -Ibpf/include
BPF_OBJ     = internal/ebpf/obj/atlas.bpf.o

.PHONY: build bpf agent web test lint verify e2e demo-up demo-down clean

build: bpf web agent

## bpf: compile the eBPF object (requires clang or zig)
bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/atlas.bpf.c $(wildcard bpf/include/*.h)
	$(BPF_CC) $(BPF_TARGET) $(BPF_CFLAGS) -c bpf/atlas.bpf.c -o $@

## agent: build the atlas binary with whatever UI/bpf artifacts exist
agent:
	$(GO) build -o bin/atlas ./cmd/atlas

## web: build the UI and stage it for embedding
web:
	cd web && npm run build
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -R web/dist/. internal/webui/dist/

test: bpf
	$(GO) test ./...
	cd web && npm run test -- --run

lint:
	$(GO) vet ./...
	golangci-lint run
	cd web && npm run typecheck && npm run lint

## verify: the full deterministic build+lint+test gate CI runs
verify: bpf
	$(GO) vet ./...
	golangci-lint run
	$(GO) test ./...
	cd web && npm ci --no-audit --no-fund
	cd web && npm run typecheck
	cd web && npm run lint
	cd web && npm run test -- --run
	cd web && npm run build
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -R web/dist/. internal/webui/dist/
	$(GO) build -o bin/atlas ./cmd/atlas
	@echo "verify: OK"

## e2e: run the demo workload against a live agent and assert the graph
e2e:
	./scripts/e2e.sh

demo-up:
	docker compose -f demo/docker-compose.yml up -d

demo-down:
	docker compose -f demo/docker-compose.yml down -v

clean:
	rm -rf bin web/dist
	rm -f $(BPF_OBJ)
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
