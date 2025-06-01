.PHONY: setup install test lint format clean build run security

setup:
	python -m pip install --upgrade pip
	pip install ruff pytest pytest-cov pytest-asyncio pdm bandit

install:
	pdm install

install-dev: install
	pdm install -G test
	pip install bandit

test:
	pytest

coverage:
	pytest --cov=zcap --cov-report=xml --cov-report=term

lint:
	ruff check .

format:
	ruff format .

security:
	bandit -r zcap

clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type d -name "*.pytest_cache" -exec rm -rf {} +
	find . -type d -name "*.coverage" -delete
	find . -type d -name "htmlcov" -exec rm -rf {} +

build:
	pdm build

run:
	python -m zcap 