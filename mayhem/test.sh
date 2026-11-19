#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# kore ships no test suite of its own; build.sh builds mayhem/out/kore_selftest (normal flags,
# no sanitizers), which drives real connections through kore's HTTP / WebSocket / filemap
# request path and checks known requests against known responses, plus known-answer checks of
# the JSON API and string decoders. Each check prints PASS/FAIL; the counts come from those lines.
BIN="$SRC/mayhem/out/kore_selftest"
if [ ! -x "$BIN" ]; then
  echo "kore_selftest missing: $BIN (mayhem/build.sh should have built it)" >&2
  emit_ctrf "kore-selftest" 0 1 0
  exit 1
fi
EXPECTED=35   # number of checks in mayhem/harnesses/selftest.c
log="$(mktemp)"
rc=0; "$BIN" >"$log" 2>&1 || rc=$?
cat "$log"
passed=$(grep -c '^PASS ' "$log" || true)
failed=$(grep -c '^FAIL ' "$log" || true)
seen=$(( passed + failed ))
if ! grep -q "^SUMMARY passed=$passed failed=$failed\$" "$log"; then
  echo "kore_selftest did not finish (no matching SUMMARY line, exit $rc)" >&2
  failed=$(( failed + 1 ))
fi
if [ "$seen" -lt "$EXPECTED" ]; then
  echo "kore_selftest ran $seen of $EXPECTED checks" >&2
  failed=$(( failed + EXPECTED - seen ))
fi
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
rm -f "$log"
emit_ctrf "kore-selftest" "$passed" "$failed" 0
