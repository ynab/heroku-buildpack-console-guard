# shellcheck shell=bash
# Test harness for heroku-buildpack-console-guard.
#
# Builds the buildpack into a temporary BUILD_DIR and then runs payloads through
# a login shell arranged to look like a Heroku one-off dyno:
#
#   * $HOME is the build directory, so $HOME/.profile.d is the compiled output
#   * $HOME/.profile sources .profile.d/*.sh, as Heroku's does, and is reached
#     through BASH_ENV rather than login-profile discovery -- see cg_run
#   * the shell is `bash -l -c "<payload>"`, so /proc/$$/cmdline has the shape
#     the profile script parses
#   * a fake `rails` and `rake` sit on PATH and report what argv they received,
#     so a test can tell "blocked" from "ran, with these arguments"
#   * a recorder listening on loopback stands in for datadog-proxy, so denial
#     records can be asserted on without a network
#
# Everything the guard decides is therefore exercised end to end: bin/compile,
# the profile script, the command wrapper and the Ruby policy behind both.

set -uo pipefail

CG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The guard reads the dyno command from /proc/$$/cmdline, so there is nothing to
# test on a platform without procfs.
if [[ ! -r /proc/$$/cmdline ]]; then
  echo "FATAL: this suite needs /proc (the guard reads /proc/\$\$/cmdline)." >&2
  echo "       Run it on Linux, or in a Heroku stack image:" >&2
  echo "       docker run --rm -v \"\$PWD:/src\" -w /src heroku/heroku:24 ./test/run_tests.sh" >&2
  exit 1
fi

# The guard's policy is Ruby, and bin/compile refuses to install without an
# interpreter. Fail here rather than as a hundred build failures.
if ! command -v ruby > /dev/null 2>&1; then
  echo "FATAL: this suite needs a ruby on PATH (the guard's policy is Ruby)." >&2
  exit 1
fi

CG_TMP_ROOT="$(mktemp -d)"
CG_TESTS_RUN=0
CG_TESTS_FAILED=0
CG_CURRENT_ENV=""
CG_STICKY_ENV=""

cg_cleanup() {
  [[ -n "${CG_RECORDER_PID:-}" ]] && kill "$CG_RECORDER_PID" 2> /dev/null
  rm -rf "$CG_TMP_ROOT"
}
trap cg_cleanup EXIT

# ---------------------------------------------------------------- recorder

# Stands in for datadog-proxy. Started once for the suite and shared by every
# build, because the guard reaches it over loopback rather than through a fake
# binary on PATH -- the reporter is Net::HTTP now, not curl.
CG_RECORD_LOG="$CG_TMP_ROOT/records.log"
: > "$CG_RECORD_LOG"
ruby "$CG_ROOT/test/lib/recorder.rb" "$CG_RECORD_LOG" "$CG_TMP_ROOT/recorder.port" &
CG_RECORDER_PID=$!

for _cg_wait in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [[ -s "$CG_TMP_ROOT/recorder.port" ]] && break
  sleep 0.1
done
unset _cg_wait

if [[ ! -s "$CG_TMP_ROOT/recorder.port" ]]; then
  echo "FATAL: the denial recorder did not start, so no record could be asserted." >&2
  exit 1
fi
CG_RECORDER_PORT="$(cat "$CG_TMP_ROOT/recorder.port")"

# ---------------------------------------------------------------- build

# cg_build <name> [CONFIG_VAR=value ...]
#
# Compiles into $CG_TMP_ROOT/<name>/app with the given vars present in ENV_DIR
# (i.e. as app config vars at build time). Sets CG_APP to the build directory.
cg_build() {
  local name="$1"; shift
  local base="$CG_TMP_ROOT/$name"
  local env_dir="$base/env" cache_dir="$base/cache"

  rm -rf "$base"
  mkdir -p "$base/app" "$env_dir" "$cache_dir" "$base/fakebin"

  local pair
  for pair in "$@"; do
    printf '%s' "${pair#*=}" > "$env_dir/${pair%%=*}"
  done

  CG_APP="$base/app"
  CG_BUILD_LOG="$base/build.log"

  if ! "$CG_ROOT/bin/compile" "$CG_APP" "$cache_dir" "$env_dir" \
        > "$CG_BUILD_LOG" 2>&1; then
    echo "FATAL: bin/compile failed for build '$name':" >&2
    cat "$CG_BUILD_LOG" >&2
    exit 1
  fi

  # A fake rails/rake that reports its argv and the environment the guard left
  # behind. Stands in for the real binaries the wrapper execs into.
  local fake
  for fake in rails rake bundle; do
    cat > "$base/fakebin/$fake" <<EOF
#!/usr/bin/env bash
echo "RAN ${fake} \$*"
echo "EDITOR=\${EDITOR-unset}"
echo "AUDIT=\${CONSOLE_AUDIT_ENABLED-unset}"
echo "USER=\${CONSOLE_USER-unset}"
EOF
    chmod 755 "$base/fakebin/$fake"
  done

  # Stand in for Heroku's own .profile.
  cat > "$CG_APP/.profile" <<EOF
# Every non-interactive bash inherits BASH_ENV, so without this the fake
# rails/rake would re-enter the gate and be denied as \`bash …\`.
unset BASH_ENV
export PATH="$base/fakebin:\$PATH"
for _f in "\$HOME"/.profile.d/*.sh; do
  # shellcheck disable=SC1090
  [ -r "\$_f" ] && . "\$_f"
done
unset _f
EOF

  cg_preflight "$name"
}

# cg_preflight <build name> -- proves the gate is actually in the loop before any
# assertion runs. Without it a harness that never reaches .profile.d reports as
# a hundred unrelated failures, every one of them a lie about the guard.
cg_preflight() {
  cg_run 'rails c'
  [[ "$CG_OUT" == *"RAN rails c"* ]] && return 0

  {
    echo "FATAL: the console guard did not activate in build '$1'."
    echo "       A permitted command did not reach the fake rails on PATH, so"
    echo "       .profile was never sourced or the gate denied it."
    echo "--- probe output ---"
    printf '%s\n' "$CG_OUT"
    echo "--- environment the login shell saw ---"
    # shellcheck disable=SC2016  # expanded by the dyno's shell, not this one
    cg_run 'echo "HOME=$HOME"; echo "PATH=$PATH"; ls -la "$HOME"'
    printf '%s\n' "$CG_OUT"
  } >&2
  exit 1
}

# cg_write_metadata <json>  -- writes the dyno metadata file this build reads.
cg_write_metadata() {
  printf '%s' "$1" > "$(dirname "$CG_APP")/dyno-metadata.json"
}
cg_metadata_path() { echo "$(dirname "$CG_APP")/dyno-metadata.json"; }

# ---------------------------------------------------------------- run

# cg_env VAR=value ... -- environment for the next cg_run, as `heroku run -e`
# would supply it (per-session, after config vars).
cg_env() { CG_CURRENT_ENV="$*"; }

# cg_env_sticky VAR=value ... -- environment for every subsequent cg_run, until
# called again with no arguments. Applied before cg_env's one-shot values, so a
# single test can still override.
cg_env_sticky() { CG_STICKY_ENV="$*"; }

# cg_run <payload> -- runs the payload as the dyno command. Sets CG_OUT/CG_STATUS.
cg_run() {
  local payload="$1"
  local -a env_args=(
    "HOME=$CG_APP"
    "PATH=/usr/local/bin:/usr/bin:/bin"
    "DYNO=run.1234"
    "CONSOLE_USER=becky"
    "CONSOLE_REASON=testing"
  )
  # shellcheck disable=SC2206  # deliberate word splitting of the caller's list
  [[ -n "$CG_STICKY_ENV" ]] && env_args+=($CG_STICKY_ENV)
  # shellcheck disable=SC2206
  [[ -n "$CG_CURRENT_ENV" ]] && env_args+=($CG_CURRENT_ENV)

  # BASH_ENV, not login-profile discovery: `--noprofile` keeps the host's
  # /etc/profile out of the run, and a system profile that reassigns $HOME (some
  # CI images do) would otherwise send the login shell looking for .profile
  # somewhere else, leaving every payload ungated and every test failing.
  CG_OUT="$(cd "$CG_APP" && env -i "${env_args[@]}" "BASH_ENV=$CG_APP/.profile" \
    /bin/bash --noprofile -l -c "$payload" 2>&1)"
  # shellcheck disable=SC2034  # available to tests that want the exit status
  CG_STATUS=$?
  CG_CURRENT_ENV=""
  return 0
}

# cg_run_no_dash_c <payload> -- runs the payload through a login shell whose argv
# has no `-c`, by feeding it on stdin. This is the shape the gate cannot vet: it
# has an argv to report but no command string in it.
cg_run_no_dash_c() {
  CG_OUT="$(cd "$CG_APP" && printf '%s\n' "$1" | env -i \
    "HOME=$CG_APP" \
    "PATH=/usr/local/bin:/usr/bin:/bin" \
    "DYNO=run.1234" \
    "CONSOLE_USER=becky" \
    "CONSOLE_REASON=testing" \
    "BASH_ENV=$CG_APP/.profile" \
    /bin/bash --noprofile -l 2>&1)"
  # shellcheck disable=SC2034  # available to tests that want the exit status
  CG_STATUS=$?
  return 0
}

# ---------------------------------------------------------------- assertions

_cg_report() {
  local ok="$1" label="$2" detail="${3:-}"
  CG_TESTS_RUN=$((CG_TESTS_RUN + 1))
  if [[ "$ok" == "true" ]]; then
    printf '  \033[32mok\033[0m   %s\n' "$label"
  else
    CG_TESTS_FAILED=$((CG_TESTS_FAILED + 1))
    printf '  \033[31mFAIL\033[0m %s\n' "$label"
    [[ -n "$detail" ]] && printf '%s\n' "$detail" | sed 's/^/         /'
    printf '%s\n' "--- output ---" | sed 's/^/         /'
    printf '%s\n' "$CG_OUT" | sed 's/^/         /'
  fi
}

# assert_ran <payload> [expected argv suffix]
assert_ran() {
  local payload="$1" expect="${2:-}"
  cg_run "$payload"
  if [[ "$CG_OUT" != *"RAN "* ]]; then
    _cg_report false "allows: $payload" "expected the command to run"
    return
  fi
  if [[ -n "$expect" && "$CG_OUT" != *"RAN $expect"* ]]; then
    _cg_report false "allows: $payload" "expected argv 'RAN $expect'"
    return
  fi
  _cg_report true "allows: $payload"
}

# assert_blocked <payload> [substring the denial must mention]
assert_blocked() {
  local payload="$1" expect="${2:-}"
  cg_run "$payload"
  if [[ "$CG_OUT" == *"RAN "* ]]; then
    _cg_report false "blocks: $payload" "the command ran"
    return
  fi
  if [[ -n "$expect" && "$CG_OUT" != *"$expect"* ]]; then
    _cg_report false "blocks: $payload" "denial did not mention '$expect'"
    return
  fi
  _cg_report true "blocks: $payload"
}

# assert_output <label> <payload> <substring>
assert_output() {
  local label="$1" payload="$2" expect="$3"
  cg_run "$payload"
  if [[ "$CG_OUT" == *"$expect"* ]]; then
    _cg_report true "$label"
  else
    _cg_report false "$label" "expected output to contain '$expect'"
  fi
}

# assert_no_output <label> <payload> <substring>
assert_no_output() {
  local label="$1" payload="$2" unexpected="$3"
  cg_run "$payload"
  if [[ "$CG_OUT" != *"$unexpected"* ]]; then
    _cg_report true "$label"
  else
    _cg_report false "$label" "expected output NOT to contain '$unexpected'"
  fi
}

# ------------------------------------------------- denial records

# The URL the guard is given for these tests. The credential is in it, as it is
# in the real config var, so that a test can prove it never reaches the operator.
# shellcheck disable=SC2034  # read by run_tests.sh
CG_REPORT_CRED="s3cr3t-not-for-operators"
CG_REPORT_PATH="/webhooks/console_audit"
CG_REPORT_URL="http://reporter:${CG_REPORT_CRED}@127.0.0.1:${CG_RECORDER_PORT}${CG_REPORT_PATH}"

# cg_reported_bodies -- the request bodies seen since the last cg_run.
cg_reported_bodies() { sed -n 's/^BODY //p' "$CG_RECORD_LOG"; }

# cg_run_reporting <payload> -- as cg_run, with the endpoint configured and the
# request log cleared first.
cg_run_reporting() {
  : > "$CG_RECORD_LOG"
  # shellcheck disable=SC2086  # deliberate word splitting: keep any cg_env values
  cg_env "CONSOLE_LOGGING_DATADOG_PROXY_URL=$CG_REPORT_URL" $CG_CURRENT_ENV
  cg_run "$1"
}

# assert_reported <label> <payload> <substring the record must contain>
assert_reported() {
  local label="$1" payload="$2" expect="$3" bodies
  cg_run_reporting "$payload"
  bodies="$(cg_reported_bodies)"
  if [[ -z "$bodies" ]]; then
    _cg_report false "$label" "no denial record was POSTed"
    return
  fi
  if [[ "$bodies" != *"$expect"* ]]; then
    _cg_report false "$label" "record did not contain '$expect'; got: $bodies"
    return
  fi
  _cg_report true "$label"
}

# assert_not_reported_field <label> <payload> <substring the record must NOT have>
# A record is still required: this distinguishes "the field is absent" from "no
# record was sent", which would otherwise pass for the wrong reason.
assert_not_reported_field() {
  local label="$1" payload="$2" unexpected="$3" bodies
  cg_run_reporting "$payload"
  bodies="$(cg_reported_bodies)"
  if [[ -z "$bodies" ]]; then
    _cg_report false "$label" "no denial record was POSTed at all"
    return
  fi
  if [[ "$bodies" == *"$unexpected"* ]]; then
    _cg_report false "$label" "record contained '$unexpected': $bodies"
    return
  fi
  _cg_report true "$label"
}

# assert_not_reported <label> <payload>
assert_not_reported() {
  local label="$1" payload="$2" bodies
  cg_run_reporting "$payload"
  bodies="$(cg_reported_bodies)"
  if [[ -n "$bodies" ]]; then
    _cg_report false "$label" "a denial record was POSTed: $bodies"
    return
  fi
  _cg_report true "$label"
}

# assert_true <label> <command...> -- generic assertion for build-time checks
assert_true() {
  local label="$1"; shift
  CG_OUT=""
  if "$@" > /dev/null 2>&1; then
    _cg_report true "$label"
  else
    _cg_report false "$label" "command failed: $*"
  fi
}

# assert_false <label> <command...>
assert_false() {
  local label="$1"; shift
  CG_OUT=""
  if "$@" > /dev/null 2>&1; then
    _cg_report false "$label" "command unexpectedly succeeded: $*"
  else
    _cg_report true "$label"
  fi
}

cg_section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cg_finish() {
  printf '\n%d assertions, %d failed\n' "$CG_TESTS_RUN" "$CG_TESTS_FAILED"
  [[ "$CG_TESTS_FAILED" -eq 0 ]]
}
