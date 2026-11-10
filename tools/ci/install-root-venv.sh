#!/usr/bin/env bash
# Install this checkout into a root-owned venv at /opt/ubuntils, through the
# hash-pinned lock: the install the README recommends. CI runners only.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo "refusing: CI runners only" >&2; exit 2; }
sudo apt-get install -yqq python3-venv >/dev/null 2>&1 || true
sudo python3 -m venv /opt/ubuntils
sudo /opt/ubuntils/bin/pip install -q --disable-pip-version-check --require-hashes -r requirements.lock
sudo cp -r . /tmp/ubuntils-src
sudo /opt/ubuntils/bin/pip install -q --disable-pip-version-check --no-deps --no-build-isolation /tmp/ubuntils-src
/opt/ubuntils/bin/ubuntils version
