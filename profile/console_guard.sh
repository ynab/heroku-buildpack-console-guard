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
#   - name /proc/$$/cmdline. The gate does the reading, but `$$` has to be
#     expanded here: this shell's argv is `bash -c <the dyno command>`, and a
#     child looking up its own PID would find the gate's argv instead
#   - exit, which is how a denial refuses the session
#   - prepend the command wrapper to PATH, so `rails` and `rake` reach it
#   - unset EDITOR/VISUAL, and export CONSOLE_AUDIT_ENABLED and CONSOLE_USER
#
# Adding a rule means editing the Ruby, not this file.
#
# WHAT THE GATE'S EXIT STATUS MEANS
#
# Two independent things can apply to a dyno, and the status says which:
#
#   gated    the guard vets the command before it runs -- the caller must
#            identify themselves, and the command and its arguments must pass
#            policy. This is what refuses a session.
#   audited  CONSOLE_AUDIT_ENABLED is exported, so the console_audit gem inside
#            the app records what the session does. This refuses nothing; it is
#            the record, not the control.
#
# Gated implies audited. The reverse does not hold, and status 10 is that case.
#
#    0  neither. A long-running dyno (web, worker, ...), which is not a console.
#    1  denied. The gate has already told the operator and recorded it.
#   10  audited, not gated. See ConsoleGuard::Gate for why the distinction
#       exists and which dynos land here.
#   20  gated and audited. An operator's `heroku run`, and it passed.
#   21  as 20, and dry-run mode needs CONSOLE_USER supplied. This shell script
#       will set a placeholder value.
#
# Any other status is a gate that died rather than decided, and is treated as a
# denial. The case where the gate cannot be started at all is handled before it
# is reached, and does not borrow this channel.

# CG_RUBY is defined by bin/compile at build time, and is a fixed absolute path.
_cg_ruby="@@CG_RUBY@@"
_cg_root="${HOME:-/app}/.console-guard"

if [[ ! -x "$_cg_ruby" ]]; then
  # The interpreter bin/compile resolved is not there any more -- the app's
  # buildpacks were reordered, or its Ruby removed, since the last build. Not
  # something an operator can arrange: the path above is absolute and does not
  # depend on anything `-e` can set.
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
      unset _cg_ruby _cg_root
      exit 1
      ;;
    *)
      echo "console-guard: no Ruby interpreter found; the audit hook is not active" >&2
      ;;
  esac

  unset _cg_ruby _cg_root
  return 0
fi

# `--disable=gems,rubyopt` closes RUBYOPT and RubyGems, both of which an
# operator can point at their own code. RUBYLIB is closed inside the gate,
# before it requires anything.
CONSOLE_GUARD_CMDLINE="/proc/$$/cmdline" \
  "$_cg_ruby" --disable=gems,rubyopt "$_cg_root/libexec/run_gate.rb"
_cg_status=$?

case "$_cg_status" in
  0)
    # Neither gated nor audited.
    ;;
  10)
    # Audited, not gated: record what the session does, but vet nothing and
    # refuse nothing.
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
    # value. It is exported in dry-run mode too, so that phase 1 still produces
    # console audit records.
    export CONSOLE_AUDIT_ENABLED=true

    if [[ "$_cg_status" == 21 ]]; then
      # Dry-run mode with no CONSOLE_USER. console1984 raises MissingUsername on
      # an empty one, so the console would die anyway and dry-run mode would stop
      # being a dry run. Deliberately not a plausible username: it has to be
      # obvious in an audit record that nobody identified themselves.
      export CONSOLE_USER="[not provided]"
    fi
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
