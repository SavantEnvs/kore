#!/usr/bin/env bash
#
# mayhem/build.sh — build kore's fuzz targets and its functional self-test.
#
# kore's own Makefile only links the `kore` server binary (main() included, -Werror,
# OpenSSL by default), so this compiles the same source list the Makefile uses for
# TLS_BACKEND=none on Linux, three times, into gitignored directories under mayhem/:
#   mayhem/build/fuzz  sanitized + SanCov objects for the libFuzzer harnesses
#   mayhem/build/afl   sanitized afl-clang-fast objects for the config-file target
#   mayhem/build/test  normal-flag objects for the self-test (the test.sh oracle)
# kore.c is compiled with -Dmain=kore_main: it holds globals the rest of kore needs,
# and its main() would clash with the harness entry points.
# Outputs land in mayhem/out/. Re-runnable, offline, no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${AFL_CC:=afl-clang-fast}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

B=mayhem/build
OUT=mayhem/out
H=mayhem/harnesses
mkdir -p "$B/gen" "$OUT"

# Generated headers, as the Makefile's $(PLATFORM) and $(VERSION).c rules make them.
misc/linux-platform.sh > "$B/gen/platform.h.new"
mv -f "$B/gen/platform.h.new" "$B/gen/platform.h"
cat > "$B/gen/version.c" <<'EOF'
const char *kore_version = "mayhem";
const char *kore_build_date = "1970-01-01";
EOF

SRCS="kore buf config connection domain filemap fileref json log mem msg module net
      pool runtime sha1 sha2 timer utils worker tls_none auth accesslog http route
      validator websocket linux seccomp"
KORE_CFLAGS="-std=c99 -D_GNU_SOURCE=1 -DPREFIX=\"/usr/local\" -Iinclude/kore -I$B/gen -fno-common -Wno-everything"

# compile_kore <dir> <cc> <flags...>: every kore source (plus version.c) into <dir>.
compile_kore() {
  local dir="$1" cc="$2"; shift 2
  mkdir -p "$dir"
  local f
  for f in $SRCS; do
    local extra=""
    [ "$f" = kore ] && extra="-Dmain=kore_main"
    printf '%s\0' "$cc $KORE_CFLAGS $* $extra -c src/$f.c -o $dir/$f.o"
  done | xargs -0 -P "$MAYHEM_JOBS" -n 1 bash -c 'eval "$0"'
  $cc $KORE_CFLAGS "$@" -c "$B/gen/version.c" -o "$dir/version.o"
}
kore_objs() { local f; for f in $SRCS version; do printf '%s/%s.o ' "$1" "$f"; done; }

# 1) libFuzzer targets: kore itself sanitized + coverage-instrumented.
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
compile_kore "$B/fuzz" "$CC" $FUZZ_FLAGS
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
FUZZ_OBJS="$(kore_objs "$B/fuzz") $B/fuzz/lsan_off.o"
LINK="-rdynamic -ldl -lm"

build_target() {   # build_target <name> <harness.c> [defines...]
  local name="$1" src="$2"; shift 2
  $CC $KORE_CFLAGS $FUZZ_FLAGS "$@" -c "$src" -o "$B/fuzz/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" $FUZZ_OBJS $LINK -o "$OUT/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/standalone_main.o" "$B/fuzz/$name.o" $FUZZ_OBJS $LINK -o "$OUT/$name-standalone"
}
build_target fuzz_http      "$H/fuzz_conn.c" -DFUZZ_HTTP
build_target fuzz_websocket "$H/fuzz_conn.c" -DFUZZ_WEBSOCKET
build_target fuzz_filemap   "$H/fuzz_conn.c" -DFUZZ_FILEMAP
build_target fuzz_json      "$H/fuzz_json.c"
build_target fuzz_utils     "$H/fuzz_utils.c"

# 2) AFL file-input target for the config parser (it exit()s on every bad line).
AFL_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
export AFL_QUIET=1
compile_kore "$B/afl" "$AFL_CC" $AFL_FLAGS
$AFL_CC $KORE_CFLAGS $AFL_FLAGS -c "$H/fuzz_config.c" -o "$B/afl/fuzz_config.o"
${AFL_CXX:-afl-clang-fast++} $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/afl/lsan_off.o"
$AFL_CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/afl/fuzz_config.o" $(kore_objs "$B/afl") "$B/afl/lsan_off.o" $LINK -o "$OUT/fuzz_config"

# 3) The functional self-test, with kore's normal flags (no sanitizers): drives real
#    connections through kore and asserts the responses (run by mayhem/test.sh).
TEST_FLAGS="-O2 $COVERAGE_FLAGS"
compile_kore "$B/test" "$CC" $TEST_FLAGS
$CC $KORE_CFLAGS $TEST_FLAGS -c "$H/selftest.c" -o "$B/test/selftest.o"
$CC $TEST_FLAGS "$B/test/selftest.o" $(kore_objs "$B/test") $LINK -o "$OUT/kore_selftest"

ls -l "$OUT"
