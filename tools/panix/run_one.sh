#!/usr/bin/env bash
# run_one.sh TECHNIQUE OUTDIR — on a disposable CI runner only, as root.
# Scans the clean runner, plants one PANIX technique, scans again. compare.py
# decides caught/missed from the two reports. Never run this on a real host.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]] || { echo "refusing: CI runners only" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
tech=${1:?technique}; out=${2:?outdir}
here=$(cd "$(dirname "$0")" && pwd)
panix=${PANIX_DIR:?set PANIX_DIR to the pinned PANIX checkout}
ubuntils=${UBUNTILS_BIN:-/opt/ubuntils/bin/ubuntils}
IP=192.0.2.1; PORT=4444
mkdir -p "$out"
line=$(awk -F'\t' -v t="$tech" '$1==t {print; exit}' "$here/techniques.tsv")
[[ -n $line ]] || { echo "unknown technique $tech" >&2; exit 2; }
attack=$(cut -f2 <<<"$line"); args=$(cut -f3 <<<"$line")
ssh-keygen -q -t ed25519 -N '' -C panix-ci -f "$out/key" <<<y >/dev/null
PUBKEY=$(cat "$out/key.pub"); rm -f "$out/key"
args=${args//\{IP\}/$IP}; args=${args//\{PORT\}/$PORT}; args=${args//\{PUBKEY\}/$PUBKEY}

"$ubuntils" scan --json --no-wazuh --output "$out/before.json" || true
cd "$panix"
set +e
eval "bash ./panix.sh -q $args" > "$out/plant.log" 2>&1
rc=$?
set -e
echo "$rc" > "$out/plant.rc"
sleep 3   # let backgrounded listeners and shells start
"$ubuntils" scan --json --no-wazuh --output "$out/after.json" || true
printf '{"technique": "%s", "attack": "%s", "panix_commit": "%s", "plant_rc": %s}\n' \
    "$tech" "$attack" "$(cat "$here/PANIX_COMMIT")" "$rc" > "$out/meta.json"
