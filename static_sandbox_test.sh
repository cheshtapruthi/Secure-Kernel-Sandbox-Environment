die() {
  echo "$1" 1>&2
  exit 1
}

[[ -n "$COVERAGE" ]] && exit 0

BIN=$static_sandbox

"$BIN" || die 'FAILED: it should have exited with 0'

echo 'PASS'
