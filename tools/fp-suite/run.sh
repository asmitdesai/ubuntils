#!/usr/bin/env bash
# run.sh IMAGE OUT.json: scan a stock container image with ubuntils and write
# the JSON report. The image gets only what ubuntils needs: the distribution's
# python3 and python3-venv. ubuntils is installed from this checkout, through
# the hash-pinned lock, into a root-owned venv, the way the README says.
#
# UBUNTILS_FP_DOCKER_ARGS  extra `docker run` arguments (e.g. a CA bundle mount)
# UBUNTILS_FP_SETUP        shell run in the container before apt (e.g. proxy config)
set -euo pipefail
image=${1:?usage: run.sh IMAGE OUT.json}
out=${2:?usage: run.sh IMAGE OUT.json}
repo=$(cd "$(dirname "$0")/../.." && pwd)
outdir=$(cd "$(dirname "$out")" && pwd)
name=$(basename "$out")

# shellcheck disable=SC2086
docker run --rm ${UBUNTILS_FP_DOCKER_ARGS:-} \
    -e UBUNTILS_FP_SETUP="${UBUNTILS_FP_SETUP:-}" \
    -v "$repo":/src:ro -v "$outdir":/out "$image" bash -euc '
    umask 022
    eval "$UBUNTILS_FP_SETUP"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -yqq python3 python3-venv >/dev/null
    python3 -m venv /opt/ubuntils
    /opt/ubuntils/bin/pip install -q --disable-pip-version-check --require-hashes \
        -r /src/requirements.lock
    cp -r /src /tmp/ubuntils-src
    /opt/ubuntils/bin/pip install -q --disable-pip-version-check --no-deps \
        --no-build-isolation /tmp/ubuntils-src
    cd /root
    /opt/ubuntils/bin/ubuntils scan --json --no-wazuh > /out/'"$name"'
'
echo "report: $out"
