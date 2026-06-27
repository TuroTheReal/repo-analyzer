# repo-analyzer
#
# Your default `python3` may be a uv-managed standalone build that cannot serve
# as a base for the stdlib `venv` module (it fails with "No module named
# 'encodings'"). PYTHON auto-selects a Homebrew framework python instead.
# Override with: make install PYTHON=/path/to/python3   (or use: make install-uv)

VENV := .venv
BIN := $(VENV)/bin
PYTHON ?= $(shell ls /opt/homebrew/bin/python3.1[0-9] 2>/dev/null | sort -V | tail -1 || command -v python3)

.PHONY: install install-uv test scan self clean

install:  ## Create the venv and install the package + dev deps
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev]"

install-uv:  ## Alternative install using uv (if uv is on PATH)
	uv venv $(VENV)
	uv pip install -e ".[dev]"

test:  ## Run the test suite
	$(BIN)/pytest

scan:  ## Scan a path: make scan TARGET=/path/to/repo
	$(BIN)/repo-analyzer $(TARGET)

self:  ## Scan this repository (dogfood)
	$(BIN)/repo-analyzer .

clean:  ## Remove venv, caches and generated reports
	rm -rf $(VENV) repo-analyzer-report .pytest_cache *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
