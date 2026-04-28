# ©AngelaMos | 2026
# Makefile

.PHONY: build build-dev test test-unit test-integration lint format format-check demo demo-full demo-full-down check ci clean

CRYSTAL ?= crystal
SHARDS ?= shards

build:
	$(SHARDS) build cre --release --no-debug

build-dev:
	$(SHARDS) build cre

test:
	$(CRYSTAL) spec --order=random

test-unit:
	$(CRYSTAL) spec spec/unit --order=random

test-integration:
	$(CRYSTAL) spec spec/integration --order=random

lint:
	@if [ -x ./bin/ameba ]; then \
		./bin/ameba; \
	else \
		echo "ameba not installed (requires libpcre3-dev on Debian 13+); skipping lint"; \
	fi

format:
	$(CRYSTAL) tool format

format-check:
	$(CRYSTAL) tool format --check

demo:
	$(SHARDS) build cre && ./bin/cre demo

demo-full:
	docker compose -f docker/docker-compose.yml up -d
	@echo "Waiting for services..."
	@sleep 8
	$(SHARDS) build cre && ./bin/cre run --config=config/demo-full.cr

demo-full-down:
	docker compose -f docker/docker-compose.yml down -v

check:
	$(MAKE) format-check
	$(MAKE) lint
	$(MAKE) test

ci: check

clean:
	rm -rf bin lib .shards .crystal coverage tmp
