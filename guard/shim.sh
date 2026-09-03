#!/bin/bash
# Console guard command wrapper. Installed by heroku-buildpack-console-guard as
# `rails`, `rake` and `bundle` in a directory prepended to PATH on one-off dynos.
#
# All argument policy is in Ruby -- see ConsoleGuard::Command. This file exists
# because the wrapper has to be an executable the shell finds on PATH, and
# because $0 is what distinguishes `rails` from `rake` from `bundle` and is lost
# once the interpreter takes over.
#
# `#!/bin/bash`, not `/usr/bin/env bash`: PATH is `heroku run -e`-settable, so an
# env lookup would let an operator choose the interpreter for the thing vetting
# their command.

set -uo pipefail

# Substituted by bin/compile, as it is in the profile script, so both halves run
# on the interpreter the build resolved. Not read from the environment: this
# wrapper vets an operator's command, and letting them name its interpreter
# would be handing them the thing doing the vetting.
_cg_ruby="@@CG_RUBY@@"
_cg_root="${HOME:-/app}/.console-guard"

if [[ ! -x "$_cg_ruby" ]]; then
  # Fail closed and loudly: silently doing nothing would look like a broken app
  # rather than a guard problem.
  {
    echo ""
    echo "console-guard: no Ruby interpreter at \`${_cg_ruby}\`, so \`${0##*/}\`"
    echo "               cannot be vetted."
    echo "               This is a buildpack bug, not an operator mistake."
    echo ""
  } >&2
  exit 1
fi

exec "$_cg_ruby" --disable=gems,rubyopt \
     "$_cg_root/libexec/run_command.rb" "${0##*/}" "$@"
