PY ?= python3

.PHONY: install data test demo clean

install:
	$(PY) -m pip install --break-system-packages -r requirements.txt

data:
	$(PY) scripts/generate_sample_data.py

test:
	$(PY) -m pytest -q

demo: ## run every subcommand against the synthetic data
	$(PY) -m soctk triage data/alerts.json --top 5
	$(PY) -m soctk phish data/samples/eml --out-dir output/phish
	$(PY) -m soctk ioc data/samples/analyst_notes.txt --csv output/iocs.csv --stix output/iocs_stix.json
	$(PY) -m soctk timeline data/logs --pivot WS-FIN-017 --out output/timeline_ws-fin-017.md
	$(PY) -m soctk report data/cases/INC-2026-0142.yaml --out output/INC-2026-0142.md

clean:
	rm -rf output/* .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
