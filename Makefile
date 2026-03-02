.PHONY: help install test lint typecheck run docker-build docker-run clean

help:
	@echo "SecureAccess — Available commands:"
	@echo "  make install      Install dependencies"
	@echo "  make test         Run tests"
	@echo "  make lint         Run ruff linter"
	@echo "  make typecheck    Run mypy type checker"
	@echo "  make run          Launch the application"
	@echo "  make build        Build standalone executable"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-run   Run in Docker"
	@echo "  make clean        Remove build artifacts"

install:
	pip install -r requirements.txt
	pip install pytest pytest-cov ruff mypy pytest-mock

test:
	pytest tests/ -v --cov=src --cov=database --cov=connectors --cov-report=term-missing

lint:
	ruff check src/ tests/ database.py connectors.py --ignore E501

typecheck:
	mypy src/ --ignore-missing-imports

run:
	python app.py

build:
	python build.py

docker-build:
	docker build -t secureaccess:latest .

docker-run:
	docker-compose up

clean:
	rm -rf build/ dist/ *.spec __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
