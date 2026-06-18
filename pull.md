## feat(relay-daemon): implement persistent peer ban enforcement across restarts — closes #102

### Problem

The previous `PeerList::ban_peer()` stored bans only in memory. A relay node
that restarted (crash, power cycle, OS update) would silently lose all active
bans, allowing a previously-detected malicious peer to reconnect immediately.
Issue-035 specifies a 24-hour ban; a restart after 1 hour wiped the remaining
23 hours. This made the strike-based system effectively toothless against any
attacker who could trigger or wait for a restart.

---

### Solution

Introduced a new `relay-daemon` workspace crate that wires a SQLite database
into every ban lifecycle event:

| When | What happens |
|---|---|
| Peer is banned | `db.save_ban()` is called **before** `peer_list.ban_peer()` so the record is durable even if the process crashes between the two steps |
| Daemon restarts | Startup code calls `db.load_active_bans()`, filters already-expired rows, then calls `peer_list.ban_peer(remaining_secs)` for each live ban |
| Ban expires in memory | `PeerBanManager::check_expirations()` calls `peer_list.check_ban_expirations()` then `db.remove_ban()` for each lifted pubkey |

---

### Files added / changed

#### `relay-daemon/Cargo.toml` _(new)_
Declares the `relay-daemon` crate with:
- `rusqlite` (bundled SQLite) for the persistence layer
- `tokio` (full) for async runtime
- `thiserror` for typed error propagation

#### `relay-daemon/src/persistence/db.rs` _(new)_
Core persistence layer.

```
banned_peers schema
  pubkey      BLOB NOT NULL PRIMARY KEY   -- [u8; 32] raw bytes
  banned_at   INTEGER NOT NULL            -- Unix timestamp (for audit)
  expires_at  INTEGER NOT NULL            -- Unix timestamp
  reason      TEXT NOT NULL               -- Human-readable reason
```

Public API:
- `Database::open(path) -> Result<Database, DbError>` — opens or creates the
  SQLite file; runs `CREATE TABLE IF NOT EXISTS` on first use
- `async fn save_ban(pubkey, expires_at, reason)` — `INSERT OR REPLACE`
- `async fn remove_ban(pubkey)` — `DELETE` by pubkey
- `async fn load_active_bans()` — `SELECT … WHERE expires_at > now()`

`Database` is `Clone` (via `Arc<Mutex<Connection>>`) so the same handle can be
shared across `PeerBanManager`, `protocol.rs`, and the daemon entry point.

#### `relay-daemon/src/discovery/peer_list.rs` _(new)_
`PeerList` maintains the existing in-memory map of `pubkey → BanEntry { expires_at: Instant }`.

- `ban_peer(pubkey, duration_secs)` — writes `Instant::now() + duration`
- `is_banned(pubkey)` — compares stored expiry to `Instant::now()`
- `check_ban_expirations() -> Vec<[u8;32]>` — sweeps expired entries, returns
  lifted pubkeys so the caller can mirror the removal into the database

#### `relay-daemon/src/security/peer_ban.rs` _(new)_
`PeerBanManager` is the seam between `PeerList` and `Database`:

- `ban_peer(pubkey, duration_secs, reason)` — persist-then-update pattern
- `check_expirations()` — calls `PeerList::check_ban_expirations()`, then
  `db.remove_ban()` for each returned pubkey

`restore_bans(db, peer_list)` is a standalone async function used at daemon
startup (and in tests) to reload live bans from the database into a fresh
`PeerList`. Returns the count of bans restored.

#### `relay-daemon/src/gossip/protocol.rs` _(new)_
`process_transaction_envelope()` detects malicious senders and calls
`ban_sender()`, which writes to the database before updating `peer_list`.
`ban_sender()` is also the correct call site for the rate-limiter violation
handler. `DEFAULT_BAN_DURATION_SECS = 86_400` (24 h).

#### `relay-daemon/src/bin/stellarconduitd.rs` _(new)_
Daemon entry point — mirrors the startup snippet from the issue spec exactly:

```rust
let active_bans = db.load_active_bans().await?;
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

for ban in active_bans {
    if ban.expires_at > now {
        let remaining_secs = ban.expires_at - now;
        peer_list.ban_peer(&ban.pubkey, remaining_secs);
    }
}
log::info!("Restored {} active peer ban(s) from database.", restored);
```

Database path is read from `STELLARCONDUIT_DB` env var (defaults to
`stellarconduit.db` in the working directory).

#### `Cargo.toml` _(modified)_
Added `"relay-daemon"` to `[workspace] members`.

---

### Tests

All four required tests live in `relay-daemon/src/persistence/db.rs` under
`#[cfg(test)]` and are reachable via `cargo test --lib persistence`:

| Test | What it proves |
|---|---|
| `test_ban_persisted_to_db` | `save_ban` + `load_active_bans` round-trip |
| `test_ban_removed_after_expiry` | `check_expirations` removes the DB row after the `Instant`-based in-memory ban expires |
| `test_ban_restored_on_startup` | `restore_bans` re-populates `PeerList` from a pre-seeded DB |
| `test_expired_ban_not_restored` | `load_active_bans` filters rows whose `expires_at ≤ now`; `restore_bans` adds nothing to `PeerList` |

All tests use an in-memory SQLite database (`:memory:`) for isolation.
`test_ban_removed_after_expiry` uses a real 2-second sleep so `Instant`-based
expiry actually fires before `check_expirations` is called.

---

### Acceptance criteria checklist

- [x] A peer banned for 24 hours survives a daemon restart
- [x] At startup, the daemon logs how many active bans were restored
- [x] Expired bans are removed from the database when they expire in memory
- [x] A peer whose ban has expired (past the Unix timestamp) is **not** loaded on restart
- [x] `test_ban_persisted_to_db` passes
- [x] `test_ban_removed_after_expiry` passes
- [x] `test_ban_restored_on_startup` passes
- [x] `test_expired_ban_not_restored` passes
- [x] `cargo test --lib persistence` passes

---

### Security notes

- The **persist-before-update** ordering in `ban_peer` and `ban_sender` ensures
  the database is the source of truth. A crash between the DB write and the
  in-memory update leaves the node over-banned (safe) rather than under-banned
  (vulnerable).
- `INSERT OR REPLACE` is used for `save_ban` so a race between two threads
  banning the same peer is idempotent — the later write wins, which is correct
  since it will always carry an equal or later expiry.
- `load_active_bans` filters at the SQL layer (`WHERE expires_at > ?`) rather
  than filtering in Rust, so expired rows are never returned regardless of clock
  skew between the filter step in `restore_bans`.
