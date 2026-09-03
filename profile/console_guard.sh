# shellcheck shell=bash
# Console gate for one-off Heroku dynos.
# Installed by heroku-buildpack-console-guard into .profile.d/
#
# This file is SOURCED by the login shell that runs the dyno command. It has no
# shebang on purpose: it is not executable.
#
# All policy is in Ruby -- see ConsoleGuard::Gate. What is left here is the set
# of things only the login shell itself can do, because it is the process that
# will run the operator's command and a child cannot reach into its parent:
#
#   - read /proc/$$/cmdline, which is where the dyno command is
#   - exit, which is how a denial refuses the session
#   - prepend the command wrapper to PATH, so `rails` and `rake` reach it
#   - unset EDITOR/VISUAL and export CONSOLE_AUDIT_ENABLED
#
# The gate reports back through its exit status. Adding a rule means editing the
# Ruby, not this file.

# Substituted by bin/compile at build time. Absolute, and never a PATH lookup:
# PATH is `heroku run -e`-settable, so looking the interpreter up here would let
# an operator hand the gate its own Ruby.
_cg_ruby="@@CG_RUBY@@"
_cg_root="${HOME:-/app}/.console-guard"

if [[ -x "$_cg_ruby" ]]; then
  # `--disable=gems,rubyopt` closes RUBYOPT and RubyGems, both of which an
  # operator can point at their own code. RUBYLIB is closed inside the gate,
  # before it requires anything.
  #
  # $$ is this login shell, whose argv is `bash -c <the dyno command>`. A child
  # process reading its own /proc entry would see the gate's argv instead.
  CONSOLE_GUARD_CMDLINE="/proc/$$/cmdline" \
    "$_cg_ruby" --disable=gems,rubyopt "$_cg_root/libexec/run_gate.rb"
  _cg_status=$?
else
  _cg_status=99
fi

case "$_cg_status" in
  0)
    # A long-running dyno. The audit hook is a console concern.
    ;;
  10)
    # Scheduler and release dynos: audited, but not gated. There is no
    # interactive operator to supply a user or a reason, and the command comes
    # from app configuration.
    export CONSOLE_AUDIT_ENABLED=true
    ;;
  20 | 21)
    # Prepended, so `rails` and `rake` resolve to the wrapper, which re-resolves
    # the real binary from the rest of PATH.
    export PATH="$_cg_root/bin:$PATH"

    # `rails credentials:edit` and `rails encrypted:edit` spawn $EDITOR, which an
    # operator can set with `-e`. The wrapper blocks those subcommands; this
    # removes the mechanism as well.
    unset EDITOR VISUAL

    # Exported after the gate: .profile.d runs after config vars and
    # `heroku run -e` vars are applied, so this overrides any operator-supplied
    # value. It is exported in permit mode too, so that phase 1 still produces
    # console audit records.
    export CONSOLE_AUDIT_ENABLED=true

    if [[ "$_cg_status" == 21 ]]; then
      # Permit mode with no CONSOLE_USER. console1984 raises MissingUsername on
      # an empty one, so the console would die anyway and permit mode would fail
      # to permit. Deliberately not a plausible username: it has to be obvious in
      # an audit record that nobody identified themselves.
      export CONSOLE_USER="[not provided]"
    fi
    ;;
  99)
    # The interpreter bin/compile resolved is not there any more -- the app's
    # buildpacks were reordered, or its Ruby was removed, since the last build.
    # Not something an operator can arrange: the path above is absolute and does
    # not depend on anything `-e` can set.
    #
    # $DYNO is spoofable, and is used anyway, because the thing that would read
    # the un-spoofable metadata file is the gate this branch cannot run. Refuse
    # anything that might be a one-off dyno; leave long-running dynos running
    # rather than taking the whole app down over a console control.
    case "${DYNO:-}" in
      run.* | scheduler.* | release.* | "")
        {
          echo ""
          echo "=========================================="
          echo "  No Ruby interpreter for the console guard, so this session"
          echo "  cannot be vetted. Refusing to run."
          echo "  console-guard @@CG_VERSION@@"
          echo "=========================================="
          echo ""
        } >&2
        unset _cg_ruby _cg_root _cg_status
        exit 1
        ;;
      *)
        echo "console-guard: no Ruby interpreter found; the audit hook is not active" >&2
        ;;
    esac
    ;;
  *)
    # A denial. The gate has already printed the banner, recorded the denial and
    # emitted the CLI's exit-status marker if one was called for.
    unset _cg_ruby _cg_root _cg_status
    exit 1
    ;;
esac

# This script is sourced, so clean up after ourselves rather than leaking state
# into the console session.
unset _cg_ruby _cg_root _cg_status
