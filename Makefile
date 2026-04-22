.PHONY: test test-unit test-integration test-e2e coverage lint clean bootstrap

BATS := tests/bats/bats-core/bin/bats
BATS_FLAGS ?= --print-output-on-failure
KCOV ?= kcov
SHELLCHECK ?= shellcheck

# Default: run all tests (unit → integration → e2e).
test: test-unit test-integration test-e2e

test-unit:
	$(BATS) $(BATS_FLAGS) tests/unit

test-integration:
	$(BATS) $(BATS_FLAGS) tests/integration

test-e2e:
	$(BATS) $(BATS_FLAGS) tests/e2e

# Line coverage via kcov. Requires kcov installed (apt install kcov).
coverage:
	@command -v $(KCOV) >/dev/null || { echo "kcov not found. apt install kcov"; exit 1; }
	rm -rf coverage
	$(KCOV) --include-path=bin,tests/helpers --bash-dont-parse-binary-dir \
		coverage $(BATS) tests/unit tests/integration tests/e2e
	@echo "Report: coverage/index.html"

# Static analysis for all bash in the repo.
lint:
	$(SHELLCHECK) bin/tacctl.sh
	$(SHELLCHECK) tests/helpers/*.bash

# First-time setup: ensure bats submodules are populated.
bootstrap:
	git submodule update --init --recursive

clean:
	rm -rf coverage
