# pacrank

Pick the fastest Archlinux mirrors for your location and write them to
`/etc/pacman.d/mirrorlist`.

Auto-detects your closest countries by sample-pinging the global mirror list
(or pass `--country` explicitly), filters the official mirrors list by
country and freshness, pings each candidate a few times, downloads the
largest package from `core` on the survivors to measure real throughput,
and atomically replaces the mirrorlist with the winners.

## How pacrank compares to reflector

pacrank is not a clone or rewrite of
[`reflector`](https://wiki.archlinux.org/title/Reflector). reflector is the
broader tool — configurable scoring formulas, threaded bandwidth probing,
many output modes. pacrank takes a narrower shape on purpose:

- **One opinionated pipeline, few knobs.** Filter mirrors by country and
  freshness, keep the lowest-latency survivors, then measure real throughput
  by downloading the largest `core` package for a bounded time. Rank by
  observed bytes per second. Two tunables: `--ping-k` and `--dl-k`.
- **Throughput measured serially, one mirror at a time.** Concurrent probes
  split your local bandwidth across workers and distort each mirror's
  number; a sequential probe tells you what a real `pacman -Sy` will see on
  your link.
- **Privilege handling is the tool's job, not yours.** pacrank drops to
  `nobody` before opening a single socket and replaces the mirrorlist with
  an atomic `rename(2)` that preserves the original file mode. No root
  process is alive while the measurements run — the escalations bracket
  them instead. You don't compose this yourself with `sudo` and shell
  redirection. See [Privileges](#privileges) for why the measurements run
  under an account that isn't yours.

Reach for reflector when you want configurability and a rich set of output
options. Reach for pacrank when you want one command that gives you an
honest measurement and rewrites the file safely.

## Installation

Pick whichever fits your setup. `sudo` is required at run time to rewrite
`/etc/pacman.d/mirrorlist`, regardless of install method.

**Arch Linux (AUR)** — install the `pacrank-bin` package with your AUR
helper of choice; it pulls the prebuilt binary from GitHub Releases and
installs bash / zsh / fish completions automatically:

```
yay -S pacrank-bin     # or: paru -S pacrank-bin
```

The PKGBUILD lives in-repo under [`packaging/arch/`](packaging/arch/PKGBUILD).

**Pre-built binary, no Rust needed** — download from the
[latest GitHub release](https://github.com/mexus/pacrank/releases/latest) and
drop it on your `PATH`. For the common `x86_64-unknown-linux-gnu` case:

```
mkdir -p ~/.local/bin
curl -L https://github.com/mexus/pacrank/releases/latest/download/pacrank-x86_64-unknown-linux-gnu.tar.gz \
  | tar -xz -C ~/.local/bin
```

Make sure `~/.local/bin` is on your `PATH`.

**Pre-built binary via [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall)** — needs `cargo` on your `PATH` but skips the compile step:

```
cargo binstall pacrank
```

**From the git repository** — requires Rust 1.91+:

```
cargo install --git https://github.com/mexus/pacrank
```

**From a local checkout** — requires Rust 1.91+:

```
cargo install --path .
```

## Quick start

```
pacrank
```

With no flags, pacrank auto-detects your closest countries by
sample-pinging the global mirror list, then sudo prompts for your password
(see [Privileges](#privileges) below), the latency and download phases run,
and `/etc/pacman.d/mirrorlist` is rewritten with the top picks — which takes
one more sudo, silent unless your timestamp expired while the phases were
running. The detected countries are cached under
`$XDG_CACHE_HOME/pacrank/countries.json` (or
`~/.cache/pacrank/countries.json`) and reused as long as your public IP
prefix is unchanged and the entry is fresh.

If you'd rather pick countries yourself, pass `--country` (repeat the flag
to pool candidates across countries — useful near a border or when one
country has few mirrors). `--ping-k` and `--dl-k` remain **global** caps
applied to the combined pool, not per-country:

```
pacrank --country DE --country NL --country FR
```

Dry run — nothing written, and the country cache left alone. The
measurements still happen inside the `nobody` sandbox, which is what its
one sudo prompt pays for ([how to remove it](#passwordless-sandboxing)):

```
pacrank --dry-run
```

## Options

- `--country <CC>` / `-c <CC>` — ISO country code filter (`RU` for Russia,
  `CN` for China, `DE` for Germany, `US` for the USA and so on). Repeat the
  flag to pool mirrors from several countries, e.g. `-c US -c CA`. **When
  omitted, the closest countries are auto-detected.**
- `--ping-k N` — keep the N lowest-latency mirrors after the ping phase (default 10)
- `--dl-k N` — keep the N fastest-download mirrors for the final list (default 5)
- `--dry-run` — run both phases, print results, don't touch the mirrorlist
  or the country cache. Still escalates once to build the sandbox: a dry
  run downloads and parses exactly what a real one does
- `--no-sandbox` — with `--dry-run` only: measure in this very process, as
  you, with no sudo prompt and no `nobody` to contain a hostile `core.db`

Country auto-detection (only used when `--country` is not passed):

- `--detect-baseline-n N` — number of fastest-pinged mirrors whose median
  latency forms the per-mirror baseline (default 5)
- `--detect-threshold F` — drop mirrors slower than `F * baseline` before
  picking countries (default 1.5)
- `--detect-k-countries N` — maximum number of distinct countries returned
  (default 3)
- `--no-country-cache` — bypass the country cache for this invocation
  (always re-detect, never persist)

Log level follows `RUST_LOG` (e.g. `RUST_LOG=debug`). The parent passes its
filter to each child on the command line, so it survives the sudo steps
without asking sudo to preserve anything.

## Privileges

Rewriting `/etc/pacman.d/mirrorlist` needs root, but the network I/O that
fills it is a much larger attack surface than an atomic rename. So root is
confined to the file write itself — and, just as much, to the moment of it.
Invoked as a regular user, pacrank stays unprivileged from start to finish
and spawns two short-lived root children instead:

1. The parent runs country auto-detection as you, then spawns
   `sudo pacrank --worker` (absolute path — a PATH-planted `sudo` lookalike
   must not intercept us). That child is root only until it
   `setgid`/`setuid`s to `nobody`, which it does before opening a single
   socket. Escalating at all is what buys the sandbox: dropping to `nobody`
   is itself a privileged operation.
2. The `nobody` worker does all the HTTP — mirrors list, latency probes,
   `core.db` downloads, package downloads — and prints the selected URLs to
   stdout as JSON. This is the slow part, and no privileged process is
   attached to it.
3. The unprivileged parent reads that JSON and spawns `sudo pacrank
   --apply`, piping the mirrors into its stdin. That child atomically
   replaces the mirrorlist — write to a `NamedTempFile` in
   `/etc/pacman.d/`, `fsync`, copy the old file's mode onto it, `rename(2)`
   into place — and exits.

Each root process therefore lives for milliseconds rather than for the
minutes the measurements take. The cost is that `sudo` runs twice: the
second call is silent while your sudo timestamp is still valid, and prompts
again if the run outlived it. Both escalations say in the log what they are
for.

Already root (`sudo pacrank`)? Then there is nothing to shorten — the
worker is spawned directly and the parent writes the file itself.

`--dry-run` takes step 1 and stops before step 3: it spawns the sandboxed
worker, prints what it would have installed, and never brings an `--apply`
child into existence. Writing nothing is not the same as touching nothing
— a dry run downloads and parses exactly what a real run does — so it is
sandboxed exactly like one. Its prompt can be removed for good (see
[Passwordless sandboxing](#passwordless-sandboxing)), or traded away for
the run with `--no-sandbox`, which measures in the process you started, as
you, and says so in the log.

**Why `nobody`, and not just your own user?** The parent is unprivileged
already, so the extra hop looks redundant — until you look at what the
worker parses. `core.db` arrives from whichever mirror is being measured,
its compression is picked by sniffing the file's own magic bytes, and the
zstd branch of that choice is a C library (`zstd-sys`). The mirror list
carries plain `http://` entries too, so those bytes need not even come from
the mirror operator to begin with. The rest of the pipeline — hyper,
rustls, serde_json, tar — is Rust, and rustls reaches C only through
hardened crypto primitives; that decompressor is the one place where a
whole attacker-chosen file meets a general-purpose C parser, and every mode
but `--no-sandbox` reaches it from inside the worker. As `nobody` it cannot
read your SSH or GPG keys, reach your browser session, or append a line to
your shell rc files. As you, it could do all three.

The drop itself is `setgroups` → `setgid` → `setuid`, in that order.
Neither of the last two touches the supplementary group vector, so without
the first the worker would keep the one it inherited — which, under sudo,
is root's.

### Passwordless sandboxing

The worker is an escalation you pay for and get no writes out of: it holds
root only long enough to reach `setuid(nobody)`. That one is safe to hand
out without a password — and doing so is what makes a sandboxed `--dry-run`
silent:

```
# sudo visudo -f /etc/sudoers.d/pacrank
mexus ALL=(root) NOPASSWD: /usr/bin/pacrank ^--worker( .*)?$
```

Replace `mexus` with your login (or `%wheel` for the group), and confirm
the path with `readlink -f "$(command -v pacrank)"` — the rule has to name
the binary pacrank re-executes. The regular-expression form needs sudo
1.9.10 or newer; on anything older, `/usr/bin/pacrank --worker *` does the
same job. No `SETENV` tag is needed, which is why pacrank passes its log
filter on the command line instead of through the environment.

**Only ever aim a rule like this at a binary you cannot write.**
`/usr/bin/pacrank` from the AUR package qualifies; a `~/.cargo/bin/pacrank`
does not. A NOPASSWD rule on a file you can overwrite is a passwordless
root shell, whatever that file happens to contain today.

What the rule grants is bounded by what `--worker` is able to do: it writes
no file, it drops to `nobody` before its first socket, and it refuses to
share a command line with `--apply` — so the trailing wildcard, which in
sudoers matches whitespace and therefore whole extra arguments, cannot be
bent into a free mirrorlist rewrite. Everything else it matches is a
measurement parameter.

`--apply` stays out of the rule on purpose. It is the branch that writes to
`/etc`, and the password in front of it is the point. With the rule in
place an update prompts once, at the end, rather than once up front and
possibly again later when the measurements outlive your sudo timestamp —
and a dry run stops prompting at all.

## Development

CI runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D
warnings` and `cargo test --all-targets`, plus a build against the MSRV in
`Cargo.toml`. The fmt check is also available as a pre-push hook, so a
formatting slip fails on your machine in a second rather than in a red build
after the tag is already pushed. Enable it once per clone:

```console
$ git config core.hooksPath .githooks
```

It rejects a push whose working tree isn't rustfmt-clean and prints the
offending diff. `git push --no-verify` bypasses it for one push.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Copyright (c) 2026 mexus (uses Arch btw)
