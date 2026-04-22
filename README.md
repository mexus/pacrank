# pacrank

Pick the fastest Archlinux mirrors for one or more countries and write them
to `/etc/pacman.d/mirrorlist`.

Fetches the official mirrors list, filters by country and freshness, pings
each candidate a few times, downloads the largest package from `core` on
the survivors to measure real throughput, and atomically replaces the
mirrorlist with the winners.

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
- **Privilege handling is the tool's job, not yours.** pacrank escalates
  through `sudo`, drops to `nobody` before opening a single socket, and
  replaces the mirrorlist with an atomic `rename(2)` that preserves the
  original file mode. You don't compose this yourself with `sudo` and shell
  redirection.

Reach for reflector when you want configurability and a rich set of output
options. Reach for pacrank when you want one command that gives you an
honest measurement and rewrites the file safely.

## Quick start

Needs Rust 1.91+ (edition 2024) and `sudo`.

```
cargo install --path .
pacrank --country BR
```

sudo prompts for your password (see [Privileges](#privileges) below),
the latency and download phases run, and `/etc/pacman.d/mirrorlist`
is rewritten with the top picks.

Pass `--country` multiple times to pool candidates across countries — useful
near a border or when one country has few mirrors. `--ping-k` and `--dl-k`
remain **global** caps applied to the combined pool, not per-country:

```
pacrank --country DE --country NL --country FR
```

Dry run — no sudo, nothing written:

```
pacrank --country BR --dry-run
```

## Options

- `--country <CC>` / `-c <CC>` — ISO country code filter (`RU` for Russia,
  `CN` for China, `DE` for Germany, `US` for the USA and so on). Repeat the
  flag to pool mirrors from several countries, e.g. `-c US -c CA`.
- `--ping-k N` — keep the N lowest-latency mirrors after the ping phase (default 10)
- `--dl-k N` — keep the N fastest-download mirrors for the final list (default 5)
- `--dry-run` — run both phases, print results, don't touch the mirrorlist

Log level follows `RUST_LOG` (e.g. `RUST_LOG=debug`); the variable survives
the sudo step.

## Privileges

Rewriting `/etc/pacman.d/mirrorlist` needs root, but the network I/O that
fills it is a much larger attack surface than an atomic rename. So root is
confined to the file write itself:

1. Invoked as a regular user, the binary re-execs itself through
   `/usr/bin/sudo` (absolute path — a PATH-planted `sudo` lookalike must
   not intercept us).
2. The root copy spawns itself again with `--worker`, which immediately
   `setgid`/`setuid`s to `nobody` before opening a single socket.
3. The `nobody` worker does all the HTTP — mirrors list, latency probes,
   `core.db` downloads, package downloads — and prints the selected URLs
   to stdout as JSON.
4. The root parent reads the JSON and atomically replaces the mirrorlist:
   write to a `NamedTempFile` in `/etc/pacman.d/`, `fsync`, copy the old
   file's mode onto it, `rename(2)` into place.

A `PACRANK_ESCALATED` env var is set on the sudo child and checked
on the way in to break any hypothetical escalation loop.

Already root? Step 1 is skipped and execution jumps straight to step 2.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Copyright (c) 2026 mexus (uses Arch btw)
