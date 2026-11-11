# Fixed profile entry admission — November 11, 2026

Created by Jason Stys. Native application version **1.1.1** retains the original
project engines, roles, schemas, profile marker, custom CLI paths and runtime pins.
The earlier 1.1.0 release and historical documentation retain their own identities.

## Confirmed issue and narrow correction

In a fresh owned fixture, a pre-existing hardlink from the selected profile's
SQLite shared-memory path to an inert file outside that profile allowed SQLite
initialization to modify the outside file. The selected profile, outside sentinel
and every database belonged to the same disposable test root. No normal user data
or concurrent adversarial filesystem replacement was used in that reproduction.

Before initialization writes, the application now admits each existing fixed
marker, lock, database and SQLite `-journal`, `-wal` and `-shm` path as an ordinary
one-link file, refusing symbolic/reparse links, hardlinks and nonregular entries.
Each later SQLite connection repeats database/sidecar admission. Missing ordinary
paths may be created normally. It neither deletes sidecars nor resets a database.

Independent regression cases exercise actual hardlinks and directories for every
fixed entry, symbolic/dangling aliases where the OS permits their creation, and
actual SQLite recovery. A deliberately terminated inert child leaves a committed
WAL or hot rollback journal; reopening must recover the correct retained output
and original history. Alias refusal preserves the outside sentinel byte-for-byte.
These are original-core/SQLite checks, not mocked passing filesystem predicates.

## Data continuity and limits

Existing ordinary 1.1.0 profiles retain the same paths, marker and schema. Preserve
the complete profile after a normal close before backup or upgrade. A linked or
nonregular fixed entry now stops startup rather than following it. Do not remove
recovery files as a workaround; preserve all work and restore a complete ordinary
copied profile for review. The application never repairs aliases by deleting data.

This closes demonstrated pre-existing alias admission, not arbitrary concurrent
same-OS-user races, administrator threats, encryption or multiuser authentication.
Original source tests, coverage floors, native workflows, CodeQL and dependency
gates remain required. Exact local/hosted/package/install outcomes have separate
source-bound receipts; this report does not invent a future run or deployment.

## Observed local source validation

The complete Python suite on isolated CPython 3.14.10 / Windows completed with
**182 passed, 4 explicit platform-limited skips**, no failures or errors,
and **95.87% combined line/branch coverage** against the unchanged
configured floor. The new actual-hardlink and nonregular-entry fixtures passed.
Symbolic-link setup is explicitly unavailable in this Windows test context;
Linux CI must exercise those paths. Strict lint, formatting, types, source maps,
file inventory and applicable repository privacy checks also passed.

These local source observations are separate from the required clean-source
frozen-app consumer and hosted gates, which are retained without reduced checks.
No local live collection, enforcement, normal-profile update or release occurred.
