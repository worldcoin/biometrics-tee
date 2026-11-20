# di-migration-stage

Runs DI migrations against stage for real stage users. Each user gets a World ID on chain, an Orb enrollment, and a staging credential for the reference PCP. Users are deleted when the run ends.

This crate is not a member of the root workspace. It has its own `Cargo.lock`, seeded from orb-tools, so the walletkit and oxide dependency graph stays out of the services.

## Setup

- The staging test Attestation Gateway key, from orb-tools' `fetch-ag-keys.sh`:

  ```shell
  aws sso login --profile tfh-orb-stage-poweruseraccess
  ./fetch-ag-keys.sh   # in orb-tools; writes .keys/ag_priv.pem
  ```

- A decrypted (tier 0) reference PCP directory, such as `pcp.<signup>.tier0.decrypted/`.
- libsodium (`brew install libsodium`).

## Usage

Run these from `tools/stage-migration`, so `.cargo/config.toml` applies.

```shell
export AG_PRIVATE_KEY_PATH=<orb-tools>/.keys/ag_priv.pem

# One migration, end to end.
cargo run -- migrate --pcp <pcp-dir> --pcrs <pcrs.json> --out migrated.tar.gz

# Load: 8 users in flight, 80 migrations in total.
cargo run --release -- load --pcp <pcp-dir> --pcrs <pcrs.json> --users 8 --jobs 80 > jobs.jsonl
```

`load` prints one JSON line per job on stdout, with its outcome and per-step times. A summary goes to stderr at the end.

By default each user starts its next job as soon as the last one ends. `--rate-per-min` starts jobs at a fixed rate instead and counts the starts that found no idle user. `--duration-secs` stops new starts after that time; with `--jobs` too, whichever comes first wins.

```sh
cargo run --release -- load --pcp <pcp-dir> --pcrs <pcrs.json> --users 16 --rate-per-min 10 --duration-secs 1800 > soak.jsonl
```

`load` sets up every user before the timed run. Each user takes one migration slot, since the API holds one active job per `sub`. Each job proves ownership over a fresh challenge. Ctrl-C stops the run and still deletes the users.
