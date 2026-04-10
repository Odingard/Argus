.PHONY: help install dev lint format test test-v build clean docker docker-test run status corpus

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install ARGUS
	pip install -e .

dev: ## Install ARGUS with dev dependencies
	pip install -e ".[dev]"

lint: ## Run linter
	ruff check src/ tests/

format: ## Format code
	ruff format src/ tests/

test: ## Run tests
	pytest tests/ -v --tb=short

test-v: ## Run tests with verbose output
	pytest tests/ -v -s

build: ## Build distribution package
	python -m build

clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker: ## Build Docker image
	docker compose build argus

docker-test: ## Run tests in Docker
	docker compose run --rm argus-dev

run: ## Run ARGUS status check
	argus status

status: ## Show ARGUS system status
	argus status

corpus: ## Show attack corpus stats
	argus corpus

scan: ## Run a scan (usage: make scan TARGET="name" MCP_URL="url")
	argus scan "$(TARGET)" --mcp-url "$(MCP_URL)"
