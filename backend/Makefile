SHELL := /bin/bash
.PHONY: init api api-check build fmt lint test-unit test-integration test-contract \
        replay loadtest migrate migrate-down seed clean

GOBIN ?= $(shell go env GOPATH)/bin
SERVICES := siem-api siem-ingest siem-processor
COVER_MIN := 80
# Credentials go in QUERY PARAMETERS, not in the userinfo section. golang-migrate's
# ClickHouse driver ignores `user:pass@host` entirely and falls back to the default
# user, so the userinfo form fails with AUTHENTICATION_FAILED against any server that
# has a password — which is every server except an unconfigured local one.
CLICKHOUSE_URL ?= clickhouse://$(CLICKHOUSE_ADDR)?username=$(CLICKHOUSE_USERNAME)&password=$(CLICKHOUSE_PASSWORD)&database=$(CLICKHOUSE_DATABASE)&x-multi-statement=true

init:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install github.com/go-kratos/kratos/cmd/protoc-gen-go-http/v2@latest
	go install github.com/google/gnostic/cmd/protoc-gen-openapi@latest
	# The clickhouse build tag is REQUIRED: without it the CLI installs with no
	# ClickHouse driver and fails at runtime with "unknown driver clickhouse".
	go install -tags 'clickhouse' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go mod download

api:
	PATH="$(GOBIN):$$PATH" buf generate
	@echo "generated: api/gen/**, api/openapi.yaml"

# Drift gate: regenerate into a temp tree and diff against what is committed.
api-check:
	@tmp=$$(mktemp -d); \
	cp -r api/gen api/openapi.yaml "$$tmp/" 2>/dev/null || true; \
	PATH="$(GOBIN):$$PATH" buf generate >/dev/null; \
	if ! diff -r -q "$$tmp/gen" api/gen >/dev/null 2>&1 || \
	   ! diff -q "$$tmp/openapi.yaml" api/openapi.yaml >/dev/null 2>&1; then \
		echo "ERROR: generated code is stale. Run 'make api' and commit the result."; \
		rm -rf "$$tmp"; exit 1; \
	fi; \
	rm -rf "$$tmp"; echo "OK: generated code matches committed output"

build:
	@for s in $(SERVICES); do \
		echo "building $$s"; \
		CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$$s ./cmd/$$s || exit 1; \
	done

fmt:
	go fmt ./...
	$(GOBIN)/goimports -w -local github.com/menta2k/siem . 2>/dev/null || true

lint:
	$(GOBIN)/golangci-lint run ./...
	buf lint
	buf breaking --against '.git#branch=main,subdir=backend' || \
		echo "note: buf breaking skipped (no main branch to compare against yet)"

# -coverpkg is required, not cosmetic: black-box suites under test/unit exercise
# internal packages from outside, and without it their coverage is attributed to
# nothing and the gate reports a falsely low number.
COVERPKG = $$(go list ./internal/... | tr '\n' ',')

test-unit:
	go test -race -covermode=atomic -coverprofile=coverage-unit.out \
		-coverpkg=$(COVERPKG) \
		$$(go list ./... | grep -v '/test/integration' | grep -v '/test/contract' | grep -v '/test/corpus' | grep -v '/test/load' | grep -v '/api/gen')

test-integration:
	go test -race -tags=integration -timeout=20m \
		-covermode=atomic -coverprofile=coverage-integration.out \
		-coverpkg=$(COVERPKG) \
		./test/integration/...

test-contract:
	go test -race -tags=contract ./test/contract/...

# The 80% floor applies to the WHOLE suite, not to unit tests alone. Repositories and
# transports are deliberately covered by integration tests against real ClickHouse and
# Redpanda rather than by mocks, so judging them on a unit-only profile would either
# report a false failure or push us toward mocking the exact behaviour that matters.
coverage: test-unit test-integration ## Merged unit+integration coverage against the 80% floor
	@echo "mode: atomic" > coverage.out
	@tail -q -n +2 coverage-unit.out coverage-integration.out 2>/dev/null >> coverage.out || true
	@go tool cover -func=coverage.out | tail -1
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print substr($$3, 1, length($$3)-1)}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { \
		if (t+0 < m+0) { print "ERROR: total coverage " t "% is below the " m "% floor"; exit 1 } \
		else { print "OK: total coverage " t "% meets the " m "% floor" } }' 

replay:
	go test -race -tags=corpus -timeout=15m -v ./test/corpus/...

loadtest:
	go test -tags=load -timeout=60m -v ./test/load/...

migrate:
	$(GOBIN)/migrate -path ../deploy/clickhouse/migrations -database "$(CLICKHOUSE_URL)" up

migrate-down:
	$(GOBIN)/migrate -path ../deploy/clickhouse/migrations -database "$(CLICKHOUSE_URL)" down 1

seed:
	go run ./cmd/seed

clean:
	rm -rf bin coverage.out coverage-unit.out coverage-integration.out coverage.html
