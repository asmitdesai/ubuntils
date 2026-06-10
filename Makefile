.PHONY: install scan scan-json test clean

install:
	pip install -e '.[dev]'

# Run the interactive TUI scan (handles sudo automatically via cli.py)
scan:
	ubuntils scan

# Output scan results as JSON
scan-json:
	ubuntils scan --json

test:
	pytest

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null; \
	find . -name "*.pyc" -delete 2>/dev/null; \
	rm -rf .coverage htmlcov/
