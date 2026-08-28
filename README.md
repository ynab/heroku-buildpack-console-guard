# heroku-buildpack-console-guard

A [Heroku buildpack](https://devcenter.heroku.com/articles/buildpacks) that gates
[one-off dynos](https://devcenter.heroku.com/articles/one-off-dynos) on a Rails app. On every
`heroku run` session it requires the caller to identify themselves and give a reason, restricts
which commands may be run, and exports a signal that an in-app audit logger can key off.

It is aimed at teams applying least-privilege to production Rails apps, where a console session
needs an attributable record of who ran what, and why.

## What it does

Once added to an app, the buildpack installs two things:

1. a `.profile.d` script that runs inside every one-off dyno, before the operator's command
2. a wrapper for `rails`, `rake` and `bundle` on `PATH`, which the profile script makes reachable

Together they:

* require the `CONSOLE_USER` and `CONSOLE_REASON` environment variables
* reject compound statements and redirections, while allowing the `--exit-code` marker the Heroku CLI appends
* permit only unqualified `rails`, `rake` and `bundle exec rails|rake` invocations, minus an
  explicit deny list, and allowlist the options those may be given
* warn if [dyno metadata](https://devcenter.heroku.com/articles/dyno-metadata) is not enabled
* export `CONSOLE_AUDIT_ENABLED=true`

Long-running dynos (`web`, `worker`, and any other process type) are unaffected.

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

## How the two halves fit together

This matters for reading the code and for adding rules in the right place.

The profile script is sourced by the login shell that will run the dyno command, so it can only see
that command as a **string** — before the shell performs quote removal, parameter expansion and
pathname expansion. Anything it decides by string comparison is therefore deciding about something
other than what `rails` will actually receive:

```
rails "dbconsole"          the string contains `"dbconsole"`, argv contains `dbconsole`
rails runner "$P"  (P=-)   the string contains `"$P"`,        argv contains `-`
rails runner *.r?          the string contains the glob,      argv contains a filename
```

So the profile script checks only what is sound to check on a raw string:

| Checked in the profile script | Why it is sound there |
|---|---|
| Which dyno this is | Read from dyno metadata, not from the command |
| `CONSOLE_USER` / `CONSOLE_REASON` | Environment, not the command |
| Compound statements and redirections | Presence of a character in the raw string is exactly the question |
| `argv[0]` is literally `rails`, `rake` or `bundle` | Quoting or expanding it makes it stop matching, so it fails closed |

Everything about the **arguments** lives in the command wrapper
(`guard/shim.sh`, installed as `.console-guard/bin/{rails,rake,bundle}`), which runs after the shell has
finished expanding and therefore sees the real `argv`. Because `argv[0]` is guaranteed to be
literally `rails`, `rake` or `bundle`, and because the wrapper directory is prepended to `PATH`, control
always reaches the wrapper.

**Add argument rules to the wrapper, not to the profile script.** A rule added to the profile script
looks like it works and is bypassable with one quote character.

## Command policy

The buildpack runs inside the dyno, so it can only police the **dyno command** — the string after
`heroku run`. Heroku CLI commands that never start a dyno are out of its reach; see
[Limitations](#limitations).

### Allowed

Only `rails` and `rake` invocations — plain, or under `bundle exec` — because those are the only
paths that enter a Rails process where an in-app audit hook can observe what runs. This is an
**allowlist**: anything that is not one of those is blocked, whether or not it is named below.

The name must be **unqualified**. `bin/rails`, `./bin/rails` and `/app/bin/rails` are rejected even
though they are the same program: naming a path skips the `PATH` lookup that reaches the command
wrapper, and the wrapper is where argument policy is enforced. A leading `VAR=value` assignment is
rejected for the same reason — `PATH=/app/bin rails c` would take the wrapper out of the picture.

### `bundle exec` is required, not optional

Heroku's Ruby buildpack rewrites `rake <task>` on a one-off dyno to
`bundle exec rake <task>` **before the login shell runs**, so the profile script never sees the
command the operator typed. `bundle` is therefore on the allowlist: without it no rake task works at
all. Confirmed on the platform — `rails` is *not* rewritten, only `rake`.

Admitting `bundle` does not admit what it can wrap. The `bundle` wrapper permits `bundle exec`
followed by an unqualified `rails` or `rake` and nothing else, then applies the same argument rules
to the rest of the command. `bundle exec bash` is still blocked; it just dies on `bash` one layer
later than it used to.

This matters more than a convenience: `bundle exec` unshifts Bundler's own bin directory onto `PATH`,
so `rails` and `rake` resolve to `vendor/bundle/.../bin/` rather than to the wrapper. The `bundle`
wrapper is the *only* place argument policy can be applied to a rewritten command — which is why it
duplicates every rule rather than delegating.

### Blocked, even though they start with `rails` or `rake`

| Blocked | Why |
|---|---|
| `rails dbconsole`, `rails db` | Drops to a raw `psql` session; no statement is seen by the Rails console hook |
| `rails credentials:*`, `rails encrypted:*` | Spawns `$EDITOR`, which the operator controls — a shell escape. `EDITOR` and `VISUAL` are also unset |
| `rails runner -` (a bare `-` in any argument position) | Reads the program from **stdin**, so the executed code appears neither in the dyno command string nor in an `ARGV` capture inside the app. The session still produces a complete record with a correct user, reason and dyno UUID, while the code that ran is unrecorded |
| `rails runner --file <f>`, or any `runner` argument that exists on disk | Same shape — the command string names a file rather than the code that runs |
| Any argument beginning with `-` that is not on the option allowlist | See [Option allowlist](#option-allowlist) below |
| `-c` in any argument position | Reaches a shell (`bash -c`). No legitimate `rails`/`rake` invocation uses it. `rails c` — the console shorthand — is unaffected, because that argument is `c`, not `-c` |
| `rails console --sandbox` / `-s` (console only) | The sandbox transaction is rolled back on exit, and a database-backed ActiveJob queue on the primary database puts the audit enqueue inside it — so the rollback discards the audit trail and the session runs entirely unlogged ([console1984#91](https://github.com/basecamp/console1984/issues/91)). Scoped to `console`/`c`, because `-s` is `rake`'s silent flag. Thor also takes `--sandbox=<value>`, so the `=` forms are refused whatever they carry, `false` included — `--no-sandbox` is the spelling that opts out, and is unaffected |

Because these are checked after expansion, the quoted, variable and glob spellings of each are
blocked too: `rails "dbconsole"`, `rails "credentials:edit"`, `rails runner "-"` and
`rails runner *.r?` are all rejected.

The sandbox block has a second layer behind it: the `console_audit` gem sets Rails' own
`config.disable_sandbox = true` whenever auditing is active, so a sandboxed console is refused
even if the command never reaches this wrapper. Both layers apply to the same dynos — the gem
activates on `CONSOLE_AUDIT_ENABLED`, which this buildpack exports only for one-off, scheduler
and release dynos. A console on a long-running dyno reached via `heroku ps:exec` is covered by
neither; see the `ps:exec` note below.

Destructive `db:*` tasks — `db:drop`, `db:reset`, `db:rollback` and the rest — are **not** blocked
here. This guard is about making sure what runs is logged, not about preventing damage, and blocking
them impedes on-call. They still reach an `api:dyno` webhook, and the app is the right place for a
task-level guard.

The `runner` file check tests whether the argument **exists on disk**, which is the same decision
Rails itself makes. There is no heuristic on how the argument looks, so
`rails runner 'Model.where(x: 1).rb'` is permitted and `rails runner ~/script` is not.

### Option allowlist

Arguments beginning with `-` are **allowlisted, not screened**. Anything not named below is
refused.

The reason is `rake -e/-p/-E CODE` (`--execute`, `--execute-print`, `--execute-continue`). Rake
evaluates `CODE` inside its own option parser — before the Rakefile is loaded, without booting
Rails — and then exits. Nothing the code does reaches the console audit hook, which makes it
weaker than the `rails runner 'system("bash")'` case [below](#limitations), where Rails at least
boots and the invocation is recorded. `rails` is affected too: it hands any command it does not
recognise to that same parser with the whole argv, so `rails -e CODE` and `rails db:migrate -e
CODE` reach it.

A deny list would have to model which of Rake's short options take an argument, in order to know
where a bundle such as `-Ne` or `-se` stops being flags. Get that wrong for one option — in this
version of Rake or a later one — and the bundle hides an `-e`. An allowlist fails the other way:
an unlisted option is refused, so being wrong costs a denial rather than an unlogged shell. It
also refuses things nobody had to think of, such as `-g`/`--system`, which loads tasks from
`$HOME/.rake` — `/app/.rake` on a dyno.

Every command gets a list; none is exempt. `rails console` and `rails runner` parse their own
options and never reach Rake, so `-e` there is the *environment* — but they get a list of their
own rather than being waved through, because a mistake in a list is a denial while a mistake in
an exemption is a silent bypass.

| After | Permitted |
|---|---|
| `rails console` / `c` | `-e`/`--environment`, `--no-sandbox`, `-h`/`--help` |
| `rails runner` / `r` | `-e`/`--environment`, `-w`/`--skip-executor`, `-h`/`--help` |
| everything else (Rake's parser) | `-T`/`--tasks`, `-D`/`--describe`, `-W`/`--where`, `-P`/`--prereqs`, `-A`/`--all`, `--comments`, `--rules`, `-t`/`--trace`, `--backtrace`, `--job-stats`, `-s`/`--silent`, `-q`/`--quiet`, `-n`/`--dry-run`, `-v`/`--verbose`, `-V`/`--version`, `-m`/`--multitask`, `-j`/`--jobs`, `-B`/`--build-all`, `-X`/`--no-deprecation-warnings`, `-h`/`-H`/`--help` |

Task names, task arguments (`some:task[a,b]`) and `VAR=value` assignments are not options and are
not screened, so `rake db:rollback STEP=99` is unaffected.

Two consequences worth knowing before you hit them:

- **Short options are matched whole**, so `-sq` is refused where `-s -q` is permitted. This is
  what makes `-se CODE` refusable without reasoning about bundling at all.
- **Abbreviated long forms are refused.** Rake accepts `--task` for `--tasks`; the allowlist does
  not. Denials list the permitted set, so this is self-service.

Deliberately absent from the Rake list: `-e`/`-E`/`-p` (evaluate code), `-f`/`-r`/`-I`/`-R`/`-C`
(name a path — the same shape as a bare `-`), and `-g`/`-G`/`-N` (change which Rakefile is found).
Exploiting the path-naming options needs a file already in the slug, i.e. the same deploy-access
trust boundary as the `BASH_ENV` limitation below.

### Blocked outright (non-Rails commands)

These all fall through the allowlist. Named here because they are the cases most likely to come up:

| Blocked | Why |
|---|---|
| `bash`, `sh`, `zsh`, `-c` invocations | Interactive shell; nothing is logged |
| `irb`, `ruby`, `node`, `python` | REPL or script outside the Rails console hook |
| `psql`, `pg_dump`, `pg_restore`, `pgcli` | Direct database access with no statement logging. This only blocks running them *inside a dyno* — see [Limitations](#limitations) |
| `curl`, `wget`, `nc`, `ssh`, `scp` | Data transfer out of the dyno, with no audit value |
| `env`, `printenv`, `cat` | Dump config vars, including credentials |

### Compound statements and redirections

The allowlist matches `argv[0]`, so without this check an operator could append a second command:
`heroku run 'rails runner "1"; bash'` would pass the `rails` check and then open a shell.
Redirections are rejected for the same reason the wrapper rejects a bare `-`:
`rails c < /app/payload.rb` feeds a program in through stdin, so the command string names a file
rather than the code that runs. The command is therefore rejected if it contains any of:

```
;   &   |   `   $(   <   >   newline
```

This is best effort. `rails runner 'system("bash")'` contains none of these and still reaches a
shell.

### `heroku run --exit-code`

`heroku run` does not report a command's exit status unless you pass `--exit-code`, and the CLI
implements that flag by appending to the dyno command:

```
rake db:version ; echo "<U+FFFF> heroku-command-exit-status: $?"
```

It then reads that line off **stdout** to decide what to exit with. Two consequences, both handled
here:

1. **Every `--exit-code` caller is a compound statement.** Untreated, the check above denies all of
   them. This is not something a caller can avoid by simplifying its command — the `;` is the CLI's,
   not theirs, so rewriting a pipeline as a single rake task does not help.
2. **A denial exits during `.profile.d`, so the appended `echo` never runs.** No marker reaches
   stdout, the CLI has nothing to read, and it reports success for a command that was refused. A
   blocked CI job would go green.

So the guard strips the marker before vetting, and emits `<U+FFFF> heroku-command-exit-status: 1` on
stdout itself when it denies a session that carried one.

The strip is an **exact literal match, anchored to the end, applied at most once**. A looser pattern
would be a shell escape: `rails c ; bash # heroku-command-exit-status` must not be stripped back to
`rails c`. Two markers leave one behind, which the compound check then rejects, and what precedes the
marker is still vetted in full — `psql ; echo "<marker>"` is denied on the allowlist.

If Heroku changes the marker, the strip stops matching and `--exit-code` callers are denied again.
Noisy, but the safe direction.

> The sentinel is written as explicit UTF-8 bytes (`$'\xef\xbf\xbf'`) rather than `$'\uffff'`. A
> one-off dyno runs in the C locale, where bash cannot represent U+FFFF and silently yields the
> six-character string `\uFFFF` instead — the strip would never match, and the emitted marker would
> be unrecognisable to the CLI.

### If the command cannot be read

The command is read from `/proc/$$/cmdline`, unwrapping Heroku's `bash -c <command>` (and combined
forms such as `bash -lc <command>`). If it cannot be read, the session is **refused** — the gate
cannot vet a command it cannot see. Likewise, if the command wrapper is not installed, the session is
refused rather than run under half a policy.

"Cannot be read" covers two distinct cases, and they get distinct messages because they have
different fixes:

| Message | Means |
|---|---|
| `Could not read the dyno command` | `/proc/$$/cmdline` was empty or unreadable |
| `Could not determine the dyno command` | The login shell's argv had no `-c` payload, so it is not the `bash -c <command>` shape the gate is built on. The denial reports the argv it did see |

Neither is an operator mistake, and neither is reported as a policy violation. Earlier versions
guessed a command string from the whole argv when there was no `-c` payload, which surfaced as the
allowlist denial naming a "command" nobody typed.

### Denials echo what was parsed

Every command-policy denial prints the command string the gate parsed, and the allowlist denial also
names the first word it rejected. An operator's screenshot is then enough to tell whether the gate
objected to the command that was typed or to something else — a wrapper, a prefix, or a shape the
parser does not handle. Long commands are truncated at 300 characters.

### Denials are recorded, not just printed

That banner reaches only the operator's terminal, over the rendezvous connection. It is not in the
app's log stream and it never reaches Datadog. Left there, the only durable trace of a blocked
command is Heroku's own `api:dyno` record — which shows that *something* was attempted but cannot
distinguish a guard denial from an application error, and forces the audit cross-check to read "no
console record for this dyno" as "blocked, or lost".

So each denial also POSTs one record, to the same endpoint and with the same credential as the
companion gem — `CONSOLE_LOGGING_DATADOG_PROXY_URL`. `event` is what tells the two apart:

```json
{
  "event": "command_denied",
  "enforced": true,
  "rule": "command_not_allowed",
  "command": "psql",
  "operator": "becky@example.com",
  "reason": "checking a migration",
  "dyno_id": "b922dfe5-0ede-45c8-a267-78bff7a23481",
  "guard_version": "7f1e0d8",
  "timestamp": "2026-08-28T06:24:43.000Z"
}
```

- **`rule`** is a short stable identifier for the check that refused — group a monitor by this rather
  than by the denial text, which gets reworded. Current values: `dyno_name_spoofed`,
  `wrapper_missing`, `identity_missing`, `command_unreadable`, `command_not_bash_c`,
  `compound_statement`, `command_not_allowed`, `bundle_not_exec`, `bundle_exec_not_allowed`,
  `raw_database_session`, `editor_escape`, `stdin_program`, `dash_c_flag`, `sandbox_console`,
  `runner_file`.
- **`enforced`** is `false` in [permit mode](#phased-rollout). Phase 1 exists to measure what
  enforcement would block, and that is only measurable if the would-be denials are recorded, so they
  are sent in both modes.
- **`command`** is what that half of the guard judged: the pre-expansion command string from the
  profile script, the post-expansion argv from the command wrapper. The CLI's `--exit-code` marker
  is stripped first, so a CI denial records the command the caller wrote.
- **`dyno_id`** comes from the dyno metadata file, not from `HEROKU_DYNO_ID`, which `-e` can set to
  anything. It is the join key against the `api:dyno` webhook.
- No `service` / `env` / `app` fields. The gem sends those but stamps them on the **worker**, because
  `heroku run -e` can rewrite every one of them and a record tagged `env:staging` would keep flowing
  to Datadog while dropping quietly out of a production-scoped monitor. This runs inside the one-off
  dyno, where that defence is not available, so it sends none of them and lets the proxy attribute
  the record from the credential it was authenticated with.

Reporting is **fail-open and best effort**: one attempt, a 4-second ceiling, no retry, and a failure
warns on stderr without holding up the denial. Refusing the command is the control; recording it must
not be able to block that. A failure is reported as a status code — never as the URL, which carries
the credential.

It is also **not sufficient on its own.** The URL variable is inherited by the one-off dyno, so an
operator who knows about this can suppress their own denial record with
`heroku run -e CONSOLE_LOGGING_DATADOG_PROXY_URL=`. What survives that is the `api:dyno` webhook and
the exit status. Closing it properly needs the record to originate somewhere the operator cannot
reach, which a buildpack cannot be.

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

Then trigger a new deploy so the buildpack is compiled and the guard is installed. The build log
records the installed version:

```
-----> Installing console guard 7f1e0d8
       profile script: .profile.d/zzz_console_guard.sh
       command wrapper: .console-guard/bin/{rails,rake,bundle}
       denial reporter: .console-guard/lib/denial_report.sh
       dyno metadata file: /etc/heroku/dyno
       enforcement: blocking unless CONSOLE_BLOCK_ENFORCE=false at run time
```

### Also recommended on the app

1. **Enable dyno metadata.** This writes the dyno's name and UUID to a file inside the dyno, and sets
   `HEROKU_DYNO_ID`. The guard uses both: the UUID is what lets an audit record be correlated with
   Heroku's own `api:dyno` webhook record for the same session, and the **file** is what makes the
   dyno name un-spoofable, since `heroku run -e DYNO=web.1` would otherwise let an operator skip the
   gate. Without metadata the guard falls back to `$DYNO` and warns.

   ```
   heroku labs:enable runtime-dyno-metadata -a app_name
   ```

2. **Restrict who can run `heroku ps:exec`.** It opens an SSH shell on an already-running dyno, which
   never goes through the one-off `heroku run` login shell — so this buildpack is not in the loop and
   cannot gate or audit it.

   ```
   heroku features:disable runtime-heroku-exec -a app_name   # necessary but NOT sufficient
   ```

   Disabling the feature is not a durable control: `heroku ps:exec` re-enables it on demand (with a
   dyno restart) for any caller who can manage the app's features, and then connects anyway. The only
   real controls are access-level — limit who holds deploy/operate access on the app (Heroku
   Enterprise Teams, Private Spaces roles) — and rely on Heroku's own audit trail of exec sessions.
   Treat `ps:exec` as an ungated channel that must be governed outside this buildpack.

## Companion gem

The buildpack blocks commands and exports `CONSOLE_AUDIT_ENABLED=true`; the only thing it records
itself is [its own denials](#denials-are-recorded-not-just-printed). Recording console statements is done in-app by
[console1984-datadog](https://github.com/ynab/console1984-datadog), which activates when
`CONSOLE_AUDIT_ENABLED` is set. See that repository for what it records and how to configure it.

The two are independent: an app with the buildpack and no gem blocks commands and logs nothing; an
app with the gem and no buildpack logs statements but does not require a user, a reason, or an
allowlisted command.

## Phased rollout

Enforcement will break any existing `heroku run` caller that omits the required environment
variables or uses a non-permitted command, so the buildpack supports rolling out in two phases.

**Phase 1 — permit but do not block.** Set `CONSOLE_BLOCK_ENFORCE=false` as an app config var. Every
check still runs and reports on stderr, but a failure is a warning rather than an exit, and
`CONSOLE_AUDIT_ENABLED=true` is still exported so audit records are produced throughout. Use this to
find non-permitted commands and missing environment variables, and update the callers.

In permit mode a missing `CONSOLE_USER` is replaced with the literal `[not provided]` before the
command runs. This is not cosmetic: console1984 raises `MissingUsername` on an empty operator
(`ask_for_username_if_empty` defaults to `false`), so without a value the console dies anyway and
permit mode fails to permit — the one thing it exists to do. The placeholder is deliberately not a
plausible username, so an audit record can never be mistaken for an identified session, and it can
never collide with a real `heroku whoami` value. When enforcing, the session is refused instead and
no placeholder is set.

**Phase 2 — block.** Remove the config var. Enforcement is the **default**, so an app that was never
configured fails closed. Only the exact value `false` opts into permit mode; anything else enforces.

`CONSOLE_BLOCK_ENFORCE` and permit mode are both **temporary**, and will be removed together once
enough apps have run in phase 1 to be confident no necessary production use case is blocked. Because
of that the variable is not tamper-proof: an operator can set it per session with
`heroku run -e CONSOLE_BLOCK_ENFORCE=false`, but only for as long as permit mode exists at all —
and while permit mode is on, nothing blocks anyway.

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

`heroku run -e` separates variables with `;`, so **a reason containing a semicolon is silently
truncated** and its tail becomes a bogus variable name. Any wrapper script that prompts for a reason
should strip or replace `;`.

Do not set these as permanent config vars on the app. They are meant to be supplied per-session via
`-e`, so that each session carries its own reason.

## Environment variables

Provided per-session via `-e`, and required for every `heroku run`:

| Variable | Required | Notes |
|---|---|---|
| `CONSOLE_USER` | Yes | Self-reported operator identity; should be the `heroku whoami` value. Whitespace-only counts as missing. Session exits if unset when enforcing; in permit mode it becomes `[not provided]` |
| `CONSOLE_REASON` | Yes | Free-text justification. Whitespace-only counts as missing. May not contain `;`. Session exits if unset |

Set as a config var on the app, and read at **run** time:

| Variable | Required | Notes |
|---|---|---|
| `CONSOLE_BLOCK_ENFORCE` | No | `false` opts into phase 1 permit mode. Defaults to enforcing, and only the exact value `false` opts out. Temporary: removed at the end of phase 1, and until then not tamper-proof |
| `CONSOLE_LOGGING_DATADOG_PROXY_URL` | No | Where to POST a [denial record](#denials-are-recorded-not-just-printed). Same variable, endpoint and Basic credential as the companion gem. Unset means denials are not recorded. Read on the one-off dyno, so `-e` can suppress it |

Set as a config var on the app, and read at **build** time:

| Variable | Required | Notes |
|---|---|---|
| `CONSOLE_GUARD_DYNO_METADATA_FILE` | No | Where to read the dyno name and UUID. Defaults to `/etc/heroku/dyno`. An unreadable path degrades to the `$DYNO` fallback |
| `CONSOLE_GUARD_VERSION` | No | Overrides the version string in build logs and denial messages. Defaults to the buildpack's short commit SHA |

Set by the buildpack itself:

| Variable | Value | Notes |
|---|---|---|
| `CONSOLE_AUDIT_ENABLED` | `true` | Exported on `run`, `scheduler` and `release` dynos, in both enforcement modes. Activates the audit hook in the companion gem. Because `.profile.d` scripts run *after* config vars and `-e` vars are applied, an operator cannot disable it via `-e`. In local and development environments, where this buildpack does not run, set it manually to opt in |
| `CONSOLE_GUARD_DYNO_ID` | dyno UUID | Exported on gated dynos only, from the dyno metadata file, so the command wrapper's denial records carry a join key `-e` cannot forge. Empty when metadata is disabled |
| `PATH` | prepended | With `.console-guard/bin`, so `rails`, `rake` and `bundle` resolve to the command wrapper |
| `EDITOR`, `VISUAL` | unset | They are a shell escape via `rails credentials:edit` |

Populated automatically by Heroku:

| Variable | Notes |
|---|---|
| `DYNO` | Used only as a fallback, and only when the dyno metadata file is unavailable. A `$DYNO` that disagrees with the metadata file is treated as tampering and the session is refused |
| `HEROKU_DYNO_ID` | Requires [dyno metadata](https://devcenter.heroku.com/articles/dyno-metadata); the guard warns if it is missing |

## Which dynos are affected

| Dyno | Command policy | `CONSOLE_AUDIT_ENABLED` |
|---|---|---|
| `run.N` (`heroku run`, `heroku run:detached`) | Enforced | Exported |
| `scheduler.N` (Heroku Scheduler) | Not enforced | Exported |
| `release.N` (release phase) | Not enforced | Exported |
| `web.N`, `worker.N`, any other process type | Not enforced | Not exported |
| Unknown or missing dyno name | Enforced (fails closed) | Exported |

Scheduler and release dynos are one-off dynos, but there is no interactive operator to supply a user
and a reason, and their commands come from app configuration rather than from an ad-hoc invocation.
They are audited but not gated. See [Limitations](#limitations).

## Development

```
./test/run_tests.sh                 # end-to-end suite, no dependencies beyond bash + coreutils
shellcheck -s bash bin/* profile/*.sh guard/*.sh test/*.sh test/lib/*.sh
```

The suite compiles the buildpack into a temporary build directory and runs payloads through a login
shell arranged to look like a one-off dyno — `$HOME` is the build directory, `$HOME/.profile` sources
`.profile.d/*.sh` the way Heroku's does, and a fake `rails`/`rake`/`bundle` on `PATH` reports the `argv` it
received. A test therefore distinguishes "blocked" from "ran, with exactly these arguments".

Every bypass fixed in this repo has a regression case, and CI runs the suite inside the
`heroku/heroku:22` and `heroku/heroku:24` stack images as well as on `ubuntu-latest`.

When adding a rule, put it in `guard/shim.sh` if it is about the command's **arguments** and in
`profile/console_guard.sh` only if it is about the environment or the raw command string. See
[How the two halves fit together](#how-the-two-halves-fit-together).

## Limitations

The buildpack gates `heroku run` sessions and nothing else.

**Direct database access is out of scope.** Anyone with production Heroku access can run
`heroku config:get DATABASE_URL` from their own machine and connect with a local `psql` or GUI
client, with no dyno involved. The same command discloses every other secret in the app's config.
A buildpack cannot see or block this.

The Heroku Postgres CLI commands — `heroku pg:psql`, `heroku pg:pull`, `heroku pg:backups:*` — are
also outside the gate. They apply only to a Heroku-attached database; on an app whose database is
hosted elsewhere they simply error.

**`heroku ps:exec` bypasses the gate.** It opens an SSH shell on an already-running web or worker
dyno, which never goes through the one-off login shell. The profile script does not enforce policy
there, so `CONSOLE_AUDIT_ENABLED` is never exported; and because no dyno is created, Heroku emits no
`api:dyno` webhook either. Disabling `runtime-heroku-exec` is necessary but not sufficient:
`ps:exec` re-enables the feature on demand (with a dyno restart) for any caller who can manage the
app's features, then connects anyway. The only durable control is access-level — limit who can run
it — plus Heroku's own audit of exec sessions. See [Also recommended on the app](#also-recommended-on-the-app).

**Heroku Scheduler and release-phase commands are audited but not gated.** They run arbitrary app
commands on one-off dynos with no `CONSOLE_USER` or `CONSOLE_REASON`, and Scheduler entries are
editable in the Heroku dashboard by anyone with app access. `CONSOLE_AUDIT_ENABLED` is exported so a
Rails task run there still produces console audit records, but the command itself is not restricted.

**Command policy is best effort.** `rails runner 'system("bash")'` reaches a shell without using any
blocked token or argument. Nothing inside the dyno can prevent inline Ruby from shelling out; that is
what makes the in-app audit record — which sees the code — the primary control, and this buildpack a
supporting one.

**Rake tasks that do not depend on `:environment` are not logged.** Such a task never boots Rails,
so an in-app hook never runs, and the buildpack permits it. For the same reason the task cannot
reach models or the database.

**`CONSOLE_USER` is self-reported** and is not verified by the buildpack. Heroku's own audit trail
(`heroku access -a app_name`) is the authoritative record of who started a session.

**A denial record can be suppressed by the operator it is about.** The endpoint is read from
`CONSOLE_LOGGING_DATADOG_PROXY_URL`, which a one-off dyno inherits, so `-e` on that variable stops
the POST. The gem does not have this problem because its *worker* reads the variable, out of the
operator's reach; nothing running inside the dyno can borrow that defence. Suppression leaves the
`api:dyno` webhook and the exit status, so the attempt is still visible — just not identifiable as a
guard denial. Treat the record as evidence of what was blocked, not as proof that nothing was.

**Statements executed after the audit path is disabled are not recorded.** A statement that disables
auditing is itself recorded if the gem logs before execution, but statements after it are not.

**A pre-existing file plus `-e BASH_ENV` reaches a shell before the gate.** Bash sources `$BASH_ENV`
at the start of every non-interactive shell — including the login shell that loads the guard, which
runs it *before* `.profile`, so no in-dyno code runs earlier to stop it. Exploiting it needs a file
already on disk with useful contents: dyno filesystems are ephemeral and per-run, so the file must
ship in the slug or base image, which means deploy access — and anyone who can deploy can already
edit the app or drop the buildpack. It is therefore the same trust boundary as the rest of this
section: the guard assumes the deployed slug is trusted and gates runtime operator commands, not the
code. The profile unsets `EDITOR`/`VISUAL` for the same class of reason but cannot unset `BASH_ENV`
early enough to matter.

**`heroku run -e` cannot override `HOME` to skip the gate.** Confirmed against the platform:
`-e HOME=/tmp` still reaches the profile script and is denied, so Heroku sources `.profile.d`
regardless of an operator-supplied `HOME`. The gate does still depend on the command arriving through
a login shell whose `argv` is `bash -c <command>`; a future change in how Heroku invokes one-off
commands could break that assumption.

## License

MIT. See [LICENSE](LICENSE).
