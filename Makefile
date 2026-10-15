# SentinelSwitch — Evidence-Driven Network Security & Response Lab
# Every target works from a fresh clone on macOS / Linux with Python 3.11+ and Node 20+.

PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
PYTHON  := $(BIN)/python
NPM     ?= npm
PORT    ?= 8000

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip -q

setup: $(BIN)/python ## Create the virtualenv, install Python + Node dependencies and headless Chromium
	$(BIN)/pip install -q -r requirements.txt
	$(BIN)/pip install -q -e .
	$(PYTHON) -m playwright install chromium
	cd frontend && $(NPM) install --no-audit --no-fund
	@echo "setup complete — next: make seed && make dev"

generate: ## Regenerate the synthetic dataset from the canonical fixtures
	$(PYTHON) -m sentinelswitch generate

seed: ## Generate the dataset and load it into SQLite (baseline state, runs the validation harness)
	$(PYTHON) -m sentinelswitch seed --regenerate

reset: ## Restore the deterministic baseline (removes the flagship evidence bundle)
	$(PYTHON) -m sentinelswitch reset

demo: ## Replay the flagship incident INC-2026-0042 end to end in the terminal
	$(PYTHON) -m sentinelswitch demo --reset

demo-2: ## SentinelSwitch 2.0 workflow: assess → incident → authorize → contain → verify → remediate → recover → export
	$(PYTHON) -m sentinelswitch demo2

assess: ## Run the control assessment engine against the current twin state
	$(PYTHON) -m sentinelswitch assess

findings: ## List open findings
	$(PYTHON) -m sentinelswitch findings

remediate: ## Request, execute and verify remediation for every open finding with an executable action
	$(PYTHON) -m sentinelswitch remediate --all

report: ## Export the posture + incident report (JSON, HTML, PDF when Chromium is available)
	$(PYTHON) -m sentinelswitch report

validate-security: ## Run the security validation harness (9 scenarios, MTTD/MTTA/MTTC)
	$(PYTHON) -m sentinelswitch validate

drift: ## Report configuration drift between desired intent and the observed twin
	$(PYTHON) -m sentinelswitch drift

build: ## Build the React dashboard into frontend/dist
	cd frontend && $(NPM) run build

dev: build ## Serve API + built dashboard on http://127.0.0.1:$(PORT)
	$(PYTHON) -m sentinelswitch serve --port $(PORT)

dev-frontend: ## Vite dev server with hot reload (expects the API on :8000)
	cd frontend && $(NPM) run dev

serve: ## Serve without rebuilding the frontend
	$(PYTHON) -m sentinelswitch serve --port $(PORT)

test: ## Backend tests (pytest) + frontend type-check
	$(PYTHON) -m pytest -q
	cd frontend && npx tsc -b

lint: ## ruff (backend, simulator, scripts) + oxlint (frontend)
	$(BIN)/ruff check backend simulator scripts diagrams/source
	$(BIN)/ruff format --check backend simulator scripts diagrams/source
	cd frontend && $(NPM) run lint

format: ## Auto-format Python
	$(BIN)/ruff format backend simulator scripts diagrams/source
	$(BIN)/ruff check --fix backend simulator scripts diagrams/source

diagrams: ## Render SVG + Mermaid + PNG diagrams into diagrams/
	$(PYTHON) scripts/diagrams.py --allow-missing-png

screenshots: build diagrams ## Regenerate every screenshot, LinkedIn card, GitHub image, branding PNG and the 2.0 artifact screenshots
	$(PYTHON) scripts/screenshots.py

screenshots-2: build ## Only the SentinelSwitch 2.0 artifact screenshots (artifacts/sentinelswitch-2.0/screenshots)
	$(PYTHON) scripts/screenshots.py --only-2

media: screenshots ## Alias for screenshots

docker-up: ## Build and run the stack with docker compose
	docker compose up --build

clean: ## Remove build artifacts and the local database (keeps the committed dataset)
	rm -rf frontend/dist data/generated/sentinelswitch.db* .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

.PHONY: help setup generate seed reset demo demo-2 assess findings remediate report validate-security drift build dev dev-frontend serve test lint format diagrams screenshots screenshots-2 media docker-up clean
