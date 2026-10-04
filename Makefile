.PHONY: test test-go test-bats test-integration test-e2e test-diff test-pyyaml build \
	coverage lint lint-sh lint-go lint-private hooks clean bootstrap

BATS := tests/bats/bats-core/bin/bats
BATS_FLAGS ?= --print-output-on-failure
SHELLCHECK ?= shellcheck

# --- bats --jobs: test files run in parallel, the tests of one file in order ---
# Needs GNU parallel; without it bats runs serially (and says why below).
# BATS_JOBS=1 forces a serial run.
BATS_JOBS ?= $(shell nproc 2> /dev/null || echo 1)
ifneq ($(BATS_JOBS),1)
ifneq ($(shell command -v parallel 2> /dev/null),)
BATS_JOBS_FLAGS := --jobs $(BATS_JOBS) --no-parallelize-within-files
endif
endif

# bats_run <files or dirs> [extra flags]
define bats_run
	@if [ "$(BATS_JOBS)" != 1 ] && [ -z "$(BATS_JOBS_FLAGS)" ]; then \
		echo "make: GNU parallel not found, running bats serially (apt install parallel; BATS_JOBS=1 silences this)"; fi
	$(BATS) $(BATS_FLAGS) $(BATS_JOBS_FLAGS) $(2) $(1)
endef

# --- Go ---
GO ?= /usr/local/go/bin/go
GOFMT ?= $(dir $(GO))gofmt
# golangci-lint is pinned; 'make lint' never installs it (see lint-go).
GOLANGCI_LINT_VERSION := v2.14.0
GOLANGCI_LINT ?= $(firstword $(shell command -v golangci-lint 2> /dev/null) \
	$(wildcard $(HOME)/go/bin/golangci-lint $(HOME)/.local/bin/golangci-lint) golangci-lint)
GOLANGCI_LINT_INSTALL := GOBIN=$$HOME/.local/bin $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
# The Go build cache: the toolchain's default, unless that directory is not
# writable for the caller (a 'sudo go build' with the caller's HOME leaves it
# root-owned), then one of tacctl's own.
ifeq ($(origin GOCACHE),undefined)
GO_DEFAULT_CACHE := $(shell $(GO) env GOCACHE 2> /dev/null)
ifneq ($(GO_DEFAULT_CACHE),)
ifneq ($(shell mkdir -p "$(GO_DEFAULT_CACHE)" 2> /dev/null; [ -w "$(GO_DEFAULT_CACHE)" ] && echo ok),ok)
export GOCACHE := $(HOME)/.cache/tacctl/go-build
endif
endif
endif

# Default: the Go tests, then the bats suite against dist/tacctl.
test: test-go test-bats

# The bats suite (integration, then e2e) against the binary 'make build'
# writes.
test-bats: build
	$(call bats_run,tests/integration tests/e2e)

test-integration: build
	$(call bats_run,tests/integration)

test-e2e: build
	$(call bats_run,tests/e2e)

# Go unit tests (-race needs cgo).
test-go:
	CGO_ENABLED=1 $(GO) test -race ./...
	CGO_ENABLED=1 $(GO) test -race -tags testknobs ./...

# internal/yamlpy's PyYAML corpus (docs/plans/go-rewrite.md 3.3): regenerate
# the expected files with PyYAML and compare with the committed ones. Without
# python3 or python3-yaml it says so and passes.
test-pyyaml:
	@if command -v python3 > /dev/null 2>&1; then python3 tests/tools/pyyaml-corpus.py --check && \
		python3 tests/tools/pyyaml-corpus.py --check internal/conf/testdata/pyyaml; \
	else echo "make: python3 not found; the PyYAML corpus was not checked"; fi

# The differential runner (docs/plans/go-rewrite.md 2.5): make test-diff CORPUS=users
test-diff: build
	@[ -x tests/diff/run.sh ] || { echo "make: tests/diff/run.sh does not exist yet"; exit 1; }
	tests/diff/run.sh $(CORPUS)

# dist/tacctl for the harness: the deploy recipe (bin/tacctl.sh --build) with
# the test knobs compiled in.
build:
	bin/tacctl.sh --build dist/tacctl --tags testknobs

# Statement coverage of the Go tests (with the test knobs, which the bats
# suite's binary has too): coverage/go.out, a per-function summary and
# coverage/index.html.
coverage:
	mkdir -p coverage
	PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 $(GO) test -tags testknobs -coverprofile=coverage/go.out ./...
	$(GO) tool cover -func=coverage/go.out | tail -1
	$(GO) tool cover -html=coverage/go.out -o coverage/index.html
	@echo "Report: coverage/index.html"

# Static analysis: the shell that remains (the bootstrap shim, the Linux
# client scripts, the test helpers and tools), then all Go, then no private
# names (the repo is public; see tests/tools/no-private.sh).
lint: lint-sh lint-go lint-private

lint-private:
	tests/tools/no-private.sh

# Run the same check on every push (local hook; not versioned by git).
hooks:
	ln -sf ../../tests/tools/pre-push .git/hooks/pre-push

lint-sh:
	$(SHELLCHECK) bin/tacctl.sh config/linux/*.sh
	$(SHELLCHECK) tests/helpers/*.bash tests/tools/*.sh tests/tools/pre-push tests/diff/*.sh
	$(SHELLCHECK) tests/containers/crossover/*.sh tests/containers/fresh/*.sh

lint-go:
	@out=$$($(GOFMT) -l cmd internal); if [ -n "$$out" ]; then echo "gofmt -l: not formatted:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	$(GO) vet -tags testknobs ./...
	@if ! command -v $(GOLANGCI_LINT) > /dev/null 2>&1; then \
		echo "make: golangci-lint $(GOLANGCI_LINT_VERSION) not found. Install it for your user (no root):"; \
		echo "    $(GOLANGCI_LINT_INSTALL)"; exit 1; fi
	@v=$$($(GOLANGCI_LINT) version --short 2> /dev/null); if [ "v$${v#v}" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "make: $(GOLANGCI_LINT) is version '$$v'; this tree pins $(GOLANGCI_LINT_VERSION):"; \
		echo "    $(GOLANGCI_LINT_INSTALL)"; exit 1; fi
	PATH="$(dir $(GO)):$$PATH" $(GOLANGCI_LINT) run ./...
	PATH="$(dir $(GO)):$$PATH" $(GOLANGCI_LINT) run --build-tags testknobs ./...

# First-time setup: ensure bats submodules are populated.
bootstrap:
	git submodule update --init --recursive

clean:
	rm -rf coverage dist
