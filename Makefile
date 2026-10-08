.PHONY: install test lint demo train run-api clean

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check src tests

demo:
	bash scripts/simulate_attacks.sh
	python scripts/generate_normal_traffic.py
	cypher replay data/raw/auth_attack_demo.log --source-type auth_log
	cypher replay data/raw/auth_normal.log --source-type auth_log
	cypher status

train:
	cypher train

run-api:
	uvicorn cypher.api.app:create_app --factory --reload

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache
