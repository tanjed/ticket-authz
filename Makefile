OPA_IMAGE := openpolicyagent/opa:1.21.0
BIN := $(CURDIR)/bin

# Pinned code generation tools, installed into ./bin by `make tools`.
BUF_VERSION := v1.73.0
PROTOC_GEN_GO_VERSION := v1.36.12
CONNECT_VERSION := v1.21.0
GRPC_GATEWAY_VERSION := v2.31.0 # protoc-gen-openapiv2 only (a generator, not a runtime dependency)

.PHONY: help
help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

.PHONY: tools
tools: ## install buf and the protoc plugins (pinned) into ./bin
	@GOBIN="$(BIN)" go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	@GOBIN="$(BIN)" go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@GOBIN="$(BIN)" go install connectrpc.com/connect/cmd/protoc-gen-connect-go@$(CONNECT_VERSION)
	@GOBIN="$(BIN)" go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@$(GRPC_GATEWAY_VERSION)

.PHONY: generate
generate: tools ## regenerate api/gen and api/openapi from proto/ (commit the result)
	@rm -rf api/gen api/openapi
	@"$(BIN)/buf" lint
	@"$(BIN)/buf" generate

.PHONY: build
build: ## build bin/authz
	@go build -o bin/authz ./cmd/authz

.PHONY: test
test: ## Go tests (the rbac tests start a Postgres container: needs Docker)
	@go test -race ./...

.PHONY: test-policy
test-policy: ## opa test for the gateway policy (in the OPA container)
	@docker run --rm -v "$(CURDIR)/policy:/policy:ro" $(OPA_IMAGE) test /policy -v

.PHONY: lint
lint: ## go vet, buf lint, opa check, helm lint against every helmvars file
	@go vet ./...
	@"$(BIN)/buf" lint
	@docker run --rm -v "$(CURDIR)/policy:/policy:ro" $(OPA_IMAGE) check --strict /policy
	@for f in helmvars/*.yaml; do helm lint chart -f $$f || exit 1; done

.PHONY: template
template: ## helm template against every helmvars file, output discarded (render-only check)
	@for f in helmvars/*.yaml; do helm template authz chart -f $$f > /dev/null || exit 1; done

.PHONY: check-generated
check-generated: generate ## fail if the committed generated code is stale
	@git diff --exit-code -- api/ || (echo "api/ is stale: run make generate and commit" && exit 1)

.PHONY: verify
verify: lint test test-policy template ## everything CI runs

.PHONY: seed
seed: ## seed a manifest into the local Authz: make seed SERVICE=order FILE=path/to/manifest.json
	@curl -sf -X PUT "http://127.0.0.1:8091/internal/v1/manifests/$(SERVICE)" -H 'content-type: application/json' --data @$(FILE); echo
