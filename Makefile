.PHONY: install dev test lint typecheck check build clean

install:
	pipx install --force .

dev:
	pip install -e ".[dev]"

test:
	python -m pytest -q

lint:
	python -m ruff check .

typecheck:
	python -m mypy spiderforge

check: lint typecheck test

build:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache