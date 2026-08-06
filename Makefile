SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help init api api-check build lint test test-unit test-integration test-contract \
        replay loadtest e2e up down down-v logs migrate migrate-down seed fmt clean \
        dist package images

BACKEND := backend
FRONTEND := frontend
COMPOSE := docker compose

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## ---------------------------------------------------------------- toolchain

init: ## Install Go plugins and frontend dependencies
	$(MAKE) -C $(BACKEND) init
	cd $(FRONTEND) && npm ci

## ---------------------------------------------------------------- contract

api: ## Regenerate protos -> Go stubs + openapi.yaml + frontend TS client
	$(MAKE) -C $(BACKEND) api
	cd $(FRONTEND) && npm run gen:api

api-check: ## Fail if generated output differs from what is committed (CI drift gate)
	$(MAKE) -C $(BACKEND) api-check
# Compared against a saved copy rather than via `git diff`, matching the backend half.
# Outside a working tree `git diff` exits non-zero because it cannot run at all, which
# the old check read as "the file is stale" — a gate that reports a specific failure it
# has not actually detected is worse than no gate.
	@cd $(FRONTEND) && tmp=$$(mktemp -d) && \
		cp src/api/schema.d.ts "$$tmp/schema.d.ts" && \
		npm run gen:api >/dev/null 2>&1; \
		status=0; \
		if ! diff -q "$$tmp/schema.d.ts" src/api/schema.d.ts >/dev/null 2>&1; then \
			echo "ERROR: frontend/src/api/schema.d.ts is stale. Run 'make api' and commit."; \
			status=1; \
		fi; \
		rm -rf "$$tmp"; exit $$status
	@echo "OK: generated artifacts match committed output"

## ---------------------------------------------------------------- build

build: ## Build all backend binaries and the frontend bundle
	$(MAKE) -C $(BACKEND) build
	cd $(FRONTEND) && npm run build

fmt: ## Format Go and frontend sources
	$(MAKE) -C $(BACKEND) fmt
	cd $(FRONTEND) && npm run format

lint: ## golangci-lint + buf lint/breaking + eslint + vue-tsc
	$(MAKE) -C $(BACKEND) lint
	cd $(FRONTEND) && npm run lint
# eslint does not type-check. Without this, a component referencing a schema type that
# the generator no longer emits lints clean and only fails later, in `make build`.
	cd $(FRONTEND) && npm run typecheck

## ---------------------------------------------------------------- test

test: coverage test-contract ## Full suite with the 80% coverage gate
	cd $(FRONTEND) && npm run test

test-unit: ## Backend unit tests
	$(MAKE) -C $(BACKEND) test-unit

test-integration: ## Backend integration tests (testcontainers)
	$(MAKE) -C $(BACKEND) test-integration

test-contract: ## Handlers vs openapi.yaml
	$(MAKE) -C $(BACKEND) test-contract

coverage: ## Merged unit+integration coverage against the 80% floor
	$(MAKE) -C $(BACKEND) coverage

replay: ## Correlation accuracy against the labelled corpus (SC-004)
	$(MAKE) -C $(BACKEND) replay

loadtest: ## 5k EPS sustained / 15k peak (SC-002, SC-003)
	$(MAKE) -C $(BACKEND) loadtest

e2e: ## Playwright suite against the Compose stack
	cd $(FRONTEND) && npm run e2e

## ---------------------------------------------------------------- packaging

# VERSION is the release version WITHOUT a leading v, matching what CI derives from the
# git tag. Overridable so a local package can be built without tagging anything.
VERSION ?= 0.0.0-dev
ARCH    ?= amd64
GOARCH  ?= $(ARCH)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
VERPKG  := github.com/menta2k/siem/internal/version

dist: ## Build release binaries and the web bundle into dist/
	@mkdir -p dist
	cd $(FRONTEND) && npm run build
	@for s in siem-api siem-ingest siem-processor; do \
		echo "building $$s ($(GOARCH))"; \
		cd $(BACKEND) && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath \
			-ldflags "-s -w -X $(VERPKG).Version=$(VERSION) -X $(VERPKG).Commit=$(COMMIT) -X $(VERPKG).Date=$(DATE)" \
			-o ../dist/$$s ./cmd/$$s || exit 1; cd ..; \
	done
	cd $(BACKEND) && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath \
		-ldflags "-s -w" -o ../dist/siem-seed ./cmd/seed
# A -X against a symbol that no longer exists is silently ignored by the linker, so an
# unstamped binary is indistinguishable from a good one until someone asks it for its
# version in production. Checking here is what keeps the ldflags path honest.
	@grep -qa "$(VERSION)" dist/siem-api \
		|| { echo "ERROR: version $(VERSION) not stamped into dist/siem-api"; exit 1; }

package: dist ## Build the .deb and .rpm from dist/ (needs nfpm)
	VERSION=$(VERSION) ARCH=$(ARCH) envsubst < nfpm.yaml > dist/nfpm.rendered.yaml
	nfpm package -f dist/nfpm.rendered.yaml -p deb -t dist/
	nfpm package -f dist/nfpm.rendered.yaml -p rpm -t dist/
	@ls -1 dist/*.deb dist/*.rpm

images: ## Build the container images locally
	@for s in siem-api siem-ingest siem-processor; do \
		echo "building image $$s"; \
		docker build -f deploy/Dockerfile.backend --build-arg SERVICE=$$s \
			--build-arg APP_VERSION=$(VERSION) --build-arg APP_COMMIT=$(COMMIT) \
			--build-arg APP_DATE=$(DATE) -t siem/$$s:$(VERSION) . || exit 1; \
	done
	docker build -f deploy/Dockerfile.frontend -t siem/siem-frontend:$(VERSION) .

## ---------------------------------------------------------------- runtime

env: ## Create .env with generated local secrets, if it does not exist
# .env.example deliberately ships every secret BLANK, so a copy of it will not start.
# Generating them here rather than telling a developer to invent their own is the
# point: someone asked to produce a 48-character signing key types "changeme", and
# that value then follows the project into places it should never reach.
	@if [ -f .env ] && grep -q '^JWT_SIGNING_KEY=.\+' .env; then \
		echo ".env already has secrets; leaving it alone"; \
	else \
		cp -n .env.example .env 2>/dev/null || true; \
		tmp=$$(mktemp); \
		sed -e "s|^CLICKHOUSE_PASSWORD=.*|CLICKHOUSE_PASSWORD=$$(openssl rand -hex 16)|" \
		    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$$(openssl rand -hex 16)|" \
		    -e "s|^JWT_SIGNING_KEY=.*|JWT_SIGNING_KEY=$$(openssl rand -hex 32)|" \
		    .env > $$tmp && mv $$tmp .env; \
		echo "generated local secrets in .env — development only, never deploy this file"; \
	fi

up: env ## Start the full local stack
	$(COMPOSE) up -d --build
	@echo "console  http://localhost:5173"
	@echo "api      http://localhost:8000/api/v1"
	@echo "openapi  http://localhost:8000/q/openapi.yaml"

down: ## Stop the stack, keep volumes
	$(COMPOSE) down

down-v: ## Stop the stack and drop volumes
	$(COMPOSE) down -v

logs: ## Tail service logs
	$(COMPOSE) logs -f siem-api siem-ingest siem-processor

migrate: ## Apply ClickHouse migrations
	$(MAKE) -C $(BACKEND) migrate

migrate-down: ## Roll back the last ClickHouse migration
	$(MAKE) -C $(BACKEND) migrate-down

seed: ## Create the demo tenant, admin user, and one feed per vendor
	$(MAKE) -C $(BACKEND) seed

clean: ## Remove build artifacts
	$(MAKE) -C $(BACKEND) clean
	rm -rf $(FRONTEND)/dist $(FRONTEND)/coverage dist
