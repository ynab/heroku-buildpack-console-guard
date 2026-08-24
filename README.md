# heroku-buildpack-console-guard

A [Heroku buildpack](https://devcenter.heroku.com/articles/buildpacks) that gates
[one-off dynos](https://devcenter.heroku.com/articles/one-off-dynos) on a Rails app. On every
`heroku run` session it requires the caller to identify themselves and give a reason, restricts
which commands may be run, and exports a signal that an in-app audit logger can key off.

It is aimed at teams applying least-privilege to production Rails apps, where a console session
needs an attributable record of who ran what, and why.

## What it does

Once added to an app, the buildpack installs a `.profile.d` script that runs inside every one-off
dyno, before the operator's command. It:

* requires the `CONSOLE_USER` and `CONSOLE_REASON` environment variables
* rejects compound statements (shell metacharacters)
* permits only `rails` and `rake` invocations, minus an explicit deny list
* warns if [dyno metadata](https://devcenter.heroku.com/articles/dyno-metadata) is not enabled
* exports `CONSOLE_AUDIT_ENABLED=true` once every check has passed

The script returns immediately unless `DYNO` starts with `run.`, so web and worker dynos are
unaffected.

The buildpack sends nothing over the network and holds no credential of its own. It does not log
console statements — that is the job of a gem inside the app, activated by `CONSOLE_AUDIT_ENABLED`
(see [Companion gem](#companion-gem)).

Typical permitted usage:

```
heroku run -e 'CONSOLE_USER=name;CONSOLE_REASON=multiword reason' rails c -a app_name
heroku run:detached -e 'CONSOLE_USER=name;CONSOLE_REASON=multiword reason' rake some_task:some_action -a app_name
heroku run:detached -e 'CONSOLE_USER=name;CONSOLE_REASON=multiword reason' rails runner Model.some_method -a app_name
```

Because `.profile.d` scripts are sourced *after* config vars and `heroku run -e` variables are
applied, an operator cannot override what the script exports.

## Command policy

The buildpack runs inside the dyno, so it can only police the **dyno command** — the string after
`heroku run`. Heroku CLI commands that never start a dyno are out of its reach; see
[Limitations](#limitations).

### Allowed

Only `rails` and `rake` invocations, because those are the only paths that enter a Rails process
where an in-app audit hook can observe what runs. This is an **allowlist**: anything that is not a
`rails` or `rake` invocation is blocked, whether or not it is named below.

`bin/rails`, `bin/rake`, `./bin/rails` and `./bin/rake` are accepted as the same thing.
`bundle exec` is not accepted, since it would also allow `bundle exec bash`.

### Blocked, even though they start with `rails` or `rake`

| Blocked | Why |
|---|---|
| `rails dbconsole`, `rails db` | Drops to a raw `psql` session; no statement is seen by the Rails console hook |
| `rails runner -` (a bare `-` in any argument position) | Reads the program from **stdin**, so the executed code appears neither in the dyno command string nor in an `ARGV` capture inside the app. The session still produces a complete record with a correct user, reason and dyno UUID, while the code that ran is unrecorded |
| `rails runner --file <f>`, `rails runner /path/to/file` | Same shape — the command string names a file rather than the code that runs |
| `db:reset`, `db:drop`, `db:schema:load`, `db:migrate:reset` (and `:all` variants), in either the `rake` or `rails` spelling | Destructive |
| `-c` in any argument position | Reaches a shell (`bash -c`). No legitimate `rails`/`rake` invocation uses it. `rails c` — the console shorthand — is unaffected |

The `rails runner <path>` check is a **heuristic**: an argument is treated as a file if it starts
with `/`, `./` or `../`, or ends in `.rb`. Rails itself decides file-vs-inline-code by whether the
path exists on disk, which the buildpack cannot reproduce.

### Blocked outright (non-Rails commands)

These all fall through the allowlist. Named here because they are the cases most likely to come up:

| Blocked | Why |
|---|---|
| `bash`, `sh`, `zsh`, `-c` invocations | Interactive shell; nothing is logged |
| `irb`, `ruby`, `node`, `python` | REPL or script outside the Rails console hook |
| `psql`, `pg_dump`, `pg_restore`, `pgcli` | Direct database access with no statement logging. This only blocks running them *inside a dyno* — see [Limitations](#limitations) |
| `curl`, `wget`, `nc`, `ssh`, `scp` | Data transfer out of the dyno, with no audit value |
| `env`, `printenv`, `cat` | Dump config vars, including credentials |

### Compound statements

The allowlist is a prefix match, so without this check an operator could append a second command:
`heroku run 'rails runner "1"; bash'` would pass the `rails` check and then open a shell. The
command is therefore rejected if it contains any of:

```
;   &   |   `   $(   newline
```

This is best effort. `rails runner 'system("bash")'` contains no metacharacter and still reaches a
shell.

### If the command cannot be read

The command is read from `/proc/$$/cmdline`, unwrapping Heroku's `bash -c <command>`. If it cannot
be read, the session is **refused** — the gate cannot vet a command it cannot see.

## Setup

Add the buildpack to a Heroku app alongside its existing buildpacks, **pinned to a commit SHA**:

```
heroku buildpacks:add https://github.com/ynab/heroku-buildpack-console-guard.git#<commit-sha> -a app_name
```

Pin to a commit SHA rather than a tag or branch. This buildpack sits in the app's production build
path, and a tag can be moved, so it is not a real pin. For testing, you can append `#branch-name`
instead of a SHA.

The buildpack should be added after your application buildpacks (e.g. `heroku/ruby`). Verify the
order with:

```
heroku buildpacks -a app_name
```

Then trigger a new deploy so the buildpack is compiled and the profile script is installed.

### Also recommended on the app

1. **Enable dyno metadata.** This sets `HEROKU_DYNO_ID`, which is what lets an audit record be
   correlated with Heroku's own `api:dyno` webhook record for the same session. Without it that
   correlation is unavailable. The buildpack prints a warning when it is missing, but does not
   block.

   ```
   heroku labs:enable runtime-dyno-metadata -a app_name
   ```

2. **Disable `runtime-heroku-exec`.** `heroku ps:exec` opens a shell on an already-running dyno,
   bypassing this buildpack entirely. The feature is per-app and enabled by default on new apps.

   ```
   heroku features -a app_name        # runtime-heroku-exec should be off
   ```

## Companion gem

The buildpack blocks commands and exports `CONSOLE_AUDIT_ENABLED=true`; it does not record anything
itself. Recording console statements is done in-app by
[console1984-datadog](https://github.com/ynab/console1984-datadog), which activates when
`CONSOLE_AUDIT_ENABLED` is set. See that repository for what it records and how to configure it.

The two are independent: an app with the buildpack and no gem blocks commands and logs nothing; an
app with the gem and no buildpack logs statements but does not require a user, a reason, or an
allowlisted command.

## Phased rollout

Enforcement will break any existing `heroku run` caller that omits the required environment
variables or uses a non-permitted command, so the buildpack supports rolling out in two phases.

**Phase 1 — permit but do not block.** Set `CONSOLE_BLOCK_ENFORCE=false` as an app config var.
Every check still runs and reports on stderr, but a failure is a warning rather than an exit, and
`CONSOLE_AUDIT_ENABLED=true` is still exported so audit records are produced throughout. Use this
to find non-permitted commands and missing environment variables, and update the callers.

**Phase 2 — block.** Remove the config var. Enforcement is the **default**, so an app that was
never configured fails closed.

`CONSOLE_BLOCK_ENFORCE` is not tamper-proof — an operator can set it via `-e`. During phase 1
nothing blocks anyway, so that gains them nothing.

Before enabling enforcement anywhere, grep your CI and deploy tooling for existing `heroku run`
callers and update them, or they break the moment the requirement is turned on.

## Setting `CONSOLE_USER` and `CONSOLE_REASON`

Every caller of `heroku run` — human and automated — must set both. `CONSOLE_USER` should be the
`heroku whoami` value, so it can be compared against the authenticated Heroku actor.

* **Interactive use.** Wrapper scripts should populate `CONSOLE_USER` from `heroku whoami`
  automatically and prompt for a reason.
* **CI / automation.** CI jobs authenticated as a service account can also use `heroku whoami`.
  A CI run URL makes a good `CONSOLE_REASON`.

    ```
    CONSOLE_USER="$(heroku whoami)"
    CONSOLE_REASON="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
    heroku run -e "CONSOLE_USER=${CONSOLE_USER};CONSOLE_REASON=${CONSOLE_REASON}" ...
    ```

Do not set these as permanent config vars on the app. They are meant to be supplied per-session via
`-e`, so that each session carries its own reason.

## Environment variables

Provided per-session via `-e`, and required for every `heroku run`:

| Variable | Required | Notes |
|---|---|---|
| `CONSOLE_USER` | Yes | Self-reported operator identity; should be the `heroku whoami` value. Whitespace-only counts as missing. Session exits if unset |
| `CONSOLE_REASON` | Yes | Free-text justification. Whitespace-only counts as missing. Session exits if unset |

Set as a config var on the app:

| Variable | Required | Notes |
|---|---|---|
| `CONSOLE_BLOCK_ENFORCE` | No | `false` opts into phase 1 permit mode. Defaults to enforcing |

Set by the buildpack itself:

| Variable | Value | Notes |
|---|---|---|
| `CONSOLE_AUDIT_ENABLED` | `true` | Exported once all checks pass, and also in permit mode. Activates the audit hook in the companion gem. Because `.profile.d` scripts run *after* config vars and `-e` vars are applied, an operator cannot disable it via `-e`. In local and development environments, where this buildpack does not run, set it manually to opt in |

Populated automatically by Heroku:

| Variable | Notes |
|---|---|
| `DYNO` | Always set. The buildpack does nothing unless it starts with `run.` |
| `HEROKU_DYNO_ID` | Requires [dyno metadata](https://devcenter.heroku.com/articles/dyno-metadata); the buildpack warns if it is missing |

## Limitations

The buildpack gates `heroku run` sessions and nothing else.

**Direct database access is out of scope.** Anyone with production Heroku access can run
`heroku config:get DATABASE_URL` from their own machine and connect with a local `psql` or GUI
client, with no dyno involved. The same command discloses every other secret in the app's config.
A buildpack cannot see or block this.

The Heroku Postgres CLI commands — `heroku pg:psql`, `heroku pg:pull`, `heroku pg:backups:*` — are
also outside the gate. They apply only to a Heroku-attached database; on an app whose database is
hosted elsewhere they simply error.

**`heroku ps:exec` bypasses the gate.** It opens a shell on an already-running web or worker dyno.
The profile script only activates on one-off dynos, so `CONSOLE_AUDIT_ENABLED` is never exported;
and because no dyno is created, Heroku emits no `api:dyno` webhook either. Disable
`runtime-heroku-exec` to close this.

**Command policy is best effort.** `rails runner 'system("bash")'` reaches a shell without using
any blocked token.

**Rake tasks that do not depend on `:environment` are not logged.** Such a task never boots Rails,
so an in-app hook never runs, and the buildpack permits it. For the same reason the task cannot
reach models or the database.

**`CONSOLE_USER` is self-reported** and is not verified by the buildpack. Heroku's own audit trail
(`heroku access -a app_name`) is the authoritative record of who started a session.

**Statements executed after the audit path is disabled are not recorded.** A statement that
disables auditing is itself recorded if the gem logs before execution, but statements after it are
not.

## License

MIT. See [LICENSE](LICENSE).
