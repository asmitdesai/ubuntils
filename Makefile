.PHONY: install scan scan-json test lock lock-dev clean

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

# Regenerate requirements.lock (hash-pinned runtime + build deps). Run with
# Python 3.10, the oldest Python on a supported Ubuntu (22.04), so the pins
# install on every later one; then `pip-audit --require-hashes --disable-pip
# -r requirements.lock`.
lock:
	pip-compile --generate-hashes --allow-unsafe --no-strip-extras --build-deps-for wheel \
		--output-file requirements.lock pyproject.toml

# Regenerate requirements-dev.lock: test dependencies, constrained to the
# runtime pins in requirements.lock, so CI tests what users install.
lock-dev:
	uv pip compile pyproject.toml requirements-dev.in --python-version 3.10 \
		--generate-hashes --no-strip-extras --universal --output-file requirements-dev.lock

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null; \
	find . -name "*.pyc" -delete 2>/dev/null; \
	rm -rf .coverage htmlcov/
