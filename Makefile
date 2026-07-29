.PHONY: help dev test coverage lint dist release clean

PYTHON ?= python3

help:
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z_-]+:.*## / {printf "%-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

dev: .venv/.installed-dev ## Create a development environment

.venv/bin/python:
	$(PYTHON) -m venv .venv

.venv/.installed-dev: pyproject.toml .venv/bin/python
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -e '.[dev]'
	touch $@

test: .venv/.installed-dev ## Run tests
	.venv/bin/python -m pytest

coverage: .venv/.installed-dev ## Run tests with branch coverage
	.venv/bin/python -m pytest --cov=xfh --cov-branch --cov-report=term-missing

lint: .venv/.installed-dev ## Check formatting and lint
	.venv/bin/python -m ruff check .
	.venv/bin/python -m ruff format --check .

dist: .venv/.installed-dev ## Build wheel and source archive
	.venv/bin/python -m build --no-isolation
	.venv/bin/python -m twine check dist/*

release: scripts/release.sh ## Publish the prebuilt tagged version to PyPI
	scripts/release.sh xfh

clean: ## Remove generated local files
	rm -rf .coverage .pytest_cache .ruff_cache build dist htmlcov site src/xfh.egg-info
