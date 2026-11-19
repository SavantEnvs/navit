#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer functional suite for navit (built by mayhem/build.sh, normal flags).
# navit ships no unit tests, so this exercises its real data paths end to end and diffs the decoded
# result against committed golden output (mayhem/tests/expected):
#   * maptool converts the same small OSM extract from XML, o5m and PBF (zlib and LZMA tiles) into a
#     binfile map; navit's binfile driver must decode the identical street/POI/town items.
#   * navit's textfile and csv map drivers decode committed sample maps.
#   * navit's TraFF parser decodes a committed feed.
#   * navit's command language evaluates committed expressions (mayhem/tests/data/expressions.txt).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

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

BIN="$SRC/build/bin"
DATA="$SRC/mayhem/tests/data"
EXP="$SRC/mayhem/tests/expected"
for b in navit_selftest maptool; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run mayhem/build.sh first" >&2; emit_ctrf navit-golden 0 1; exit 1; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/navit-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
passed=0; failed=0

check() {  # check <name> <expected file> <actual file>
  if [ -s "$3" ] && diff -u "$2" "$3"; then
    echo "PASS $1"; passed=$((passed + 1))
  else
    echo "FAIL $1"; failed=$((failed + 1))
  fi
}

# maptool <name> <maptool args...>: convert in a scratch dir, then dump the binfile it wrote.
maptool_case() {
  local name="$1"; shift
  local d="$work/$name"; mkdir -p "$d"
  ( cd "$d" && "$BIN/maptool" -U "$@" out.bin >maptool.log 2>&1 ) || echo "maptool failed for $name"
  "$BIN/navit_selftest" map binfile "$d/out.bin" >"$d/dump" 2>/dev/null
  check "$name" "$EXP/binfile.out" "$d/dump"
}

maptool_case maptool_osm_xml_zlib -i "$DATA/small.osm"
maptool_case maptool_osm_xml_lzma -C lzma -i "$DATA/small.osm"
maptool_case maptool_o5m --o5m -i "$DATA/small.o5m"
maptool_case maptool_pbf --protobuf -i "$DATA/small.osm.pbf"

"$BIN/navit_selftest" map textfile "$DATA/sample.txt" >"$work/textfile" 2>/dev/null
check map_textfile "$EXP/textfile.out" "$work/textfile"
"$BIN/navit_selftest" map csv "$DATA/sample.csv" >"$work/csv" 2>/dev/null
check map_csv "$EXP/csv.out" "$work/csv"
"$BIN/navit_selftest" traffic "$DATA/feed.xml" >"$work/traffic" 2>/dev/null
check traffic_xml "$EXP/traffic.out" "$work/traffic"

: >"$work/expr"
while IFS= read -r e; do
  printf '%s => ' "$e" >>"$work/expr"
  "$BIN/navit_selftest" expr "$e" >>"$work/expr" 2>/dev/null
done <"$DATA/expressions.txt"
check command_expressions "$EXP/expr.out" "$work/expr"

emit_ctrf navit-golden "$passed" "$failed"
