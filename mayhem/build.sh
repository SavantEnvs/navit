#!/usr/bin/env bash
#
# mayhem/build.sh — build navit's fuzz targets and its functional oracle.
#
# Three out-of-tree CMake builds of upstream navit (all under the gitignored /build/):
#   build/fuzz  libnavit_core + every built-in module, statically (USE_PLUGINS=n), with
#               $SANITIZER_FLAGS + SanCov (-fsanitize=fuzzer-no-link) + DWARF 3. The libFuzzer
#               harnesses in mayhem/harnesses (map drivers, TraFF, bookmarks, command language)
#               link against it.
#   build/afl   maptool (OSM XML / o5m / PBF -> binfile converter) built with afl-clang-fast and the
#               same sanitizers: the maptool_* targets run the real CLI on a file (afl: true).
#   build/test  maptool + libnavit_core with upstream's normal flags, plus mayhem/tests/navit_selftest,
#               the known-answer oracle mayhem/test.sh runs.
#
# Sanitizers: ASan + UBSan halting, except UBSan's `alignment` check: navit stores items as packed
# int32 streams and reads 64-bit ids/longs out of them at 4-byte alignment by design (e.g.
# maptool/osm.c:1016 fires on every input with a named way), so that one check is relaxed.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

UBSAN_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) UBSAN_RELAX="-fno-sanitize=alignment" ;; esac
FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS"

COMMON_CMAKE=(
  -DUSE_PLUGINS=n -DSAMPLE_MAP=n -DSVG2PNG=n -DXSL_PROCESSING=n
  -DUSE_NATIVE_LANGUAGE_SUPPORT=n -DBUILD_MAPTOOL=y
  -Dgraphics/svg_debug=FALSE
)

mkdir -p build/bin
# LeakSanitizer off (leaks are not the bug class fuzzed here), linked into every sanitized binary.
$CC $FUZZ_CFLAGS -c "$SRC/mayhem/lsan_off.cc" -o build/bin/lsan_off.o
# The AFL maptool's scratch-directory constructor (see the file): maptool writes out.bin and its
# maptool_<pid>.tmp directory into the cwd and exits before parsing when that is not writable.
$CC $FUZZ_CFLAGS -c "$SRC/mayhem/maptool_scratch.c" -o build/bin/maptool_scratch.o

# 1) Sanitized + SanCov library build for the libFuzzer harnesses.
cmake -S . -B build/fuzz "${COMMON_CMAKE[@]}" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link" \
  -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target navit_core

# 2) AFL-instrumented, sanitized maptool. afl-clang-fast is reached by name through PATH.
#    CLASSIC (hashed-edge) instrumentation: maptool statically links all of libnavit_core, and with
#    the sanitizers the default PCGUARD mode needs ~68k edge slots (__afl_final_loc = 68373), more
#    than AFL's default 64 KiB map. A fuzzer that does not resize its map for such a target then gets
#    no usable coverage from it (afl-showmap aborts with FS_ERROR_MAP_SIZE; Mayhem saw 31 edges).
#    CLASSIC writes into the fixed 64 KiB map, so every AFL front end reads it unmodified.
#    (afl-* compilers are never routed through ccache, so this env does not affect cache safety.)
CC=afl-clang-fast CXX=afl-clang-fast++ AFL_QUIET=1 AFL_LLVM_INSTRUMENT=CLASSIC \
cmake -S . -B build/afl "${COMMON_CMAKE[@]}" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SRC/build/bin/lsan_off.o $SRC/build/bin/maptool_scratch.o"
AFL_QUIET=1 AFL_LLVM_INSTRUMENT=CLASSIC cmake --build build/afl -j"$MAYHEM_JOBS" --target maptool

# 3) Normal-flags build for the functional oracle (no sanitizers, no fuzz instrumentation).
env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
cmake -S . -B build/test "${COMMON_CMAKE[@]}" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/test -j"$MAYHEM_JOBS" --target maptool navit_core

# Static libraries of the core and every built-in module (builtin_init references them all).
navit_libs() { find "$1/navit" -name '*.a' ! -path '*/maptool/*' | sort; }
GLIB_CFLAGS=$(pkg-config --cflags glib-2.0 gmodule-2.0)
GLIB_LIBS=$(pkg-config --libs glib-2.0 gmodule-2.0)
SYS_LIBS="$GLIB_LIBS -lz -llzma -lpng -lpthread -lm"
inc() { echo "-I$1 -I$1/navit -I$SRC -I$SRC/navit"; }

# 4) libFuzzer harnesses + standalone reproducers.
$CC $FUZZ_CFLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/bin/standalone_main.o
mapfile -t FUZZ_LIBS < <(navit_libs build/fuzz)
for h in fuzz_map_binfile fuzz_map_textfile fuzz_map_csv fuzz_map_shapefile fuzz_traffic_xml fuzz_bookmarks fuzz_command; do
  $CC $FUZZ_CFLAGS $(inc build/fuzz) $GLIB_CFLAGS -c "$SRC/mayhem/harnesses/$h.c" -o "build/bin/$h.o"
  $CXX $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "build/bin/$h.o" build/bin/lsan_off.o \
    -Wl,--start-group "${FUZZ_LIBS[@]}" -Wl,--end-group $SYS_LIBS -o "build/bin/$h"
  $CXX $FUZZ_CFLAGS "build/bin/$h.o" build/bin/standalone_main.o build/bin/lsan_off.o \
    -Wl,--start-group "${FUZZ_LIBS[@]}" -Wl,--end-group $SYS_LIBS -o "build/bin/$h-standalone"
done
cp build/afl/navit/maptool/maptool build/bin/maptool-afl

# 5) The oracle program, normal flags.
mapfile -t TEST_LIBS < <(navit_libs build/test)
$CC -O1 -g $COVERAGE_FLAGS $(inc build/test) $GLIB_CFLAGS "$SRC/mayhem/tests/navit_selftest.c" \
  -Wl,--start-group "${TEST_LIBS[@]}" -Wl,--end-group $SYS_LIBS $COVERAGE_FLAGS -o build/bin/navit_selftest
cp build/test/navit/maptool/maptool build/bin/maptool
echo "build.sh: done"
