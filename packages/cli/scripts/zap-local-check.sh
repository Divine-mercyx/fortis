#!/usr/bin/env bash
# Downloads a real ZAP and runs `fortis test` with it against the sample API, without Docker.
# Run from the repository root, after `pnpm --filter fortis-watchdog build`. Needs Java 17 or newer.
set -euo pipefail

ZAP_VERSION=2.17.0
ZAP_SHA256=94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0
PORT=3999

work="${RUNNER_TEMP:-$(mktemp -d)}/zap-local"
mkdir -p "$work"

curl -fsSL --retry 3 -o "$work/zap.zip" "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip"
actual=$(node -e "process.stdout.write(require('crypto').createHash('sha256').update(require('fs').readFileSync(process.argv[1])).digest('hex'))" "$work/zap.zip")
[ "$actual" = "$ZAP_SHA256" ] || { echo "FAILED: ZAP download checksum is $actual"; exit 1; }
unzip -q "$work/zap.zip" -d "$work"

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) zap=$(cygpath -w "$work/ZAP_${ZAP_VERSION}/zap.bat") ;;
  *) zap="$work/ZAP_${ZAP_VERSION}/zap.sh" ;;
esac

node packages/cli/node_modules/tsx/dist/cli.mjs packages/cli/tests/sample-api/vulnerable-api.ts "$PORT" &
api=$!
trap 'kill "$api" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -fs "http://127.0.0.1:$PORT/" > /dev/null && break
  sleep 1
done

# Exit 1 only means findings met the threshold. Anything else is a failure to run.
set +e
FORTIS_ZAP_PATH="$zap" node packages/cli/dist/fortis.js test --target "http://127.0.0.1:$PORT" --local --minutes 1 --json > "$work/result.json"
code=$?
set -e
if [ "$code" != 0 ] && [ "$code" != 1 ]; then
  echo "FAILED: fortis test exited with $code"
  cat "$work/result.json"
  exit 1
fi

# The sample API sets no security headers, so a working passive scan always reports alerts.
node -e "
const r = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
const zap = r.findings.filter((f) => f.ruleId.startsWith('ZAP-'));
console.log('ZAP findings:', zap.map((f) => f.ruleId).join(', '));
if (!zap.length) { console.error('FAILED: ZAP ran but reported nothing'); process.exit(1); }
" "$work/result.json"
