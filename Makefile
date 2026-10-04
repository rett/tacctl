.PHONY: test test-unit test-integration test-e2e test-blackbox test-go test-diff test-pyyaml build \
	coverage lint lint-sh lint-go clean bootstrap

BATS := tests/bats/bats-core/bin/bats
BATS_FLAGS ?= --print-output-on-failure
KCOV ?= kcov
SHELLCHECK ?= shellcheck

# --- Which implementation the bats suite drives (tests/helpers/setup.bash) ---
# bash: bin/tacctl.sh. go: dist/tacctl (built first), which hands what it
# does not implement yet to bin/tacctl.sh. Until the Go rewrite's Phase 4 only
# the files in tests/blackbox.list run against go (make test-blackbox).
TACCTL_IMPL ?= bash
export TACCTL_IMPL

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

# Default: run all tests (unit → integration → e2e).
test: test-unit test-integration test-e2e

test-unit test-integration test-e2e: impl-check
test-unit:
	$(call bats_run,tests/unit)

test-integration:
	$(call bats_run,tests/integration)

test-e2e:
	$(call bats_run,tests/e2e)

.PHONY: impl-check
impl-check:
	@if [ "$(TACCTL_IMPL)" = go ]; then \
		echo "make: TACCTL_IMPL=go runs the whole suite only from Phase 4 of the Go rewrite; use make test-blackbox"; exit 1; fi

# The black-box files (tests/blackbox.list) against TACCTL_IMPL. With go, the
# binary is built first, list entries marked '# go-after: <package>' are
# skipped, and so are tests tagged bash-only (they run a copy of the bash
# script from another directory, or similar). An entry marked
# '# go-tags: <tag> [<tag>...]' runs in full with bash, and with go only its
# tests carrying one of those tags (the cut-over tags of
# characterisation.bats), in a bats run of its own.
test-blackbox: $(if $(filter go,$(TACCTL_IMPL)),build)
	$(call bats_run,$$(awk -v impl="$(TACCTL_IMPL)" '/^[[:space:]]*(#|$$)/ { next } impl == "go" && /#[[:space:]]*go-(after|tags):/ { next } { print $$1 }' tests/blackbox.list),$(if $(filter go,$(TACCTL_IMPL)),--filter-tags '!bash-only'))
	@if [ "$(TACCTL_IMPL)" = go ]; then \
		awk '/^[[:space:]]*#/ { next } /#[[:space:]]*go-tags:/ { f = $$1; sub(/.*go-tags:[[:space:]]*/, ""); print f, $$0 }' tests/blackbox.list | \
		while read -r file tags; do \
			set --; for t in $$tags; do set -- "$$@" --filter-tags "$$t,!bash-only"; done; \
			echo "$(BATS) $(BATS_FLAGS) $$* $$file"; \
			$(BATS) $(BATS_FLAGS) "$$@" "$$file" || exit 1; \
		done; \
	fi

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

# Line coverage via kcov. Requires kcov installed (apt install kcov).
coverage:
	@command -v $(KCOV) >/dev/null || { echo "kcov not found. apt install kcov"; exit 1; }
	rm -rf coverage
	$(KCOV) --include-path=bin,lib,tests/helpers --bash-dont-parse-binary-dir \
		coverage $(BATS) tests/unit tests/integration tests/e2e
	@echo "Report: coverage/index.html"

# Static analysis: all bash, then all Go.
lint: lint-sh lint-go

lint-sh:
	$(SHELLCHECK) bin/tacctl.sh lib/*.sh lib/backends/*.sh
	$(SHELLCHECK) bin/tacctl.sh.new tests/containers/crossover/*.sh
	$(SHELLCHECK) tests/helpers/*.bash tests/tools/*.sh tests/diff/*.sh
	$(SHELLCHECK) config/linux/*.sh

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
