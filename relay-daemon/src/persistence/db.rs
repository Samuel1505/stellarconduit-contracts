use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub struct PersistedBan {
    pub pubkey: [u8; 32],
    pub expires_at: u64,
    pub reason: String,
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS banned_peers (
                pubkey      BLOB NOT NULL PRIMARY KEY,
                banned_at   INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                reason      TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Persist a newly banned peer to disk.
    pub async fn save_ban(
        &self,
        pubkey: &[u8; 32],
        expires_at: u64,
        reason: &str,
    ) -> Result<(), DbError> {
        let banned_at = now_secs() as i64;
        let expires_at_i = expires_at as i64;
        let pubkey_bytes: &[u8] = pubkey;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO banned_peers (pubkey, banned_at, expires_at, reason) \
             VALUES (?1, ?2, ?3, ?4)",
            params![pubkey_bytes, banned_at, expires_at_i, reason],
        )?;
        Ok(())
    }

    /// Remove a ban record (called when a ban expires or is manually lifted).
    pub async fn remove_ban(&self, pubkey: &[u8; 32]) -> Result<(), DbError> {
        let pubkey_bytes: &[u8] = pubkey;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM banned_peers WHERE pubkey = ?1",
            params![pubkey_bytes],
        )?;
        Ok(())
    }

    /// Load all bans that have not yet expired.
    pub async fn load_active_bans(&self) -> Result<Vec<PersistedBan>, DbError> {
        let now = now_secs() as i64;

        let bans = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT pubkey, expires_at, reason \
                 FROM banned_peers \
                 WHERE expires_at > ?1",
            )?;

            let rows: Vec<(Vec<u8>, u64, String)> = stmt
                .query_map(params![now], |row| {
                    let pubkey_bytes: Vec<u8> = row.get(0)?;
                    let expires_at: i64 = row.get(1)?;
                    let reason: String = row.get(2)?;
                    Ok((pubkey_bytes, expires_at as u64, reason))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            rows.into_iter()
                .map(|(bytes, expires_at, reason)| {
                    let mut pubkey = [0u8; 32];
                    let len = bytes.len().min(32);
                    pubkey[..len].copy_from_slice(&bytes[..len]);
                    PersistedBan {
                        pubkey,
                        expires_at,
                        reason,
                    }
                })
                .collect::<Vec<_>>()
        };

        Ok(bans)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::peer_list::PeerList;
    use crate::security::peer_ban::{restore_bans, PeerBanManager};
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;
    use tokio::time::Duration;

    fn test_pubkey(byte: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = byte;
        pk
    }

    fn make_db() -> Database {
        Database::open(":memory:").expect("in-memory db")
    }

    /// Ban a peer. Assert db.load_active_bans() contains the entry.
    #[tokio::test]
    async fn test_ban_persisted_to_db() {
        let db = make_db();
        let pubkey = test_pubkey(1);
        let expires_at = now_secs() + 3600;

        db.save_ban(&pubkey, expires_at, "malicious peer").await.unwrap();

        let bans = db.load_active_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].pubkey, pubkey);
        assert_eq!(bans[0].expires_at, expires_at);
        assert_eq!(bans[0].reason, "malicious peer");
    }

    /// Create a ban expiring 1 second in the future. Wait 2 seconds.
    /// Call check_ban_expirations(). Assert db.load_active_bans() is empty.
    #[tokio::test]
    async fn test_ban_removed_after_expiry() {
        let db = make_db();
        let pubkey = test_pubkey(2);
        let peer_list = Arc::new(TokioMutex::new(PeerList::new()));
        let manager = PeerBanManager::new(db.clone(), Arc::clone(&peer_list));

        manager.ban_peer(&pubkey, 1, "expiry test").await.unwrap();

        let before = db.load_active_bans().await.unwrap();
        assert_eq!(before.len(), 1, "ban should be present immediately after banning");

        tokio::time::sleep(Duration::from_secs(2)).await;

        manager.check_expirations().await.unwrap();

        let after = db.load_active_bans().await.unwrap();
        assert!(after.is_empty(), "expired ban must be removed from the database");
    }

    /// Write a ban to the DB directly. Re-create a PeerList and call the startup
    /// restore logic. Assert the peer is banned in memory.
    #[tokio::test]
    async fn test_ban_restored_on_startup() {
        let db = make_db();
        let pubkey = test_pubkey(3);
        let expires_at = now_secs() + 3600;

        db.save_ban(&pubkey, expires_at, "persistent ban").await.unwrap();

        let mut peer_list = PeerList::new();
        let count = restore_bans(&db, &mut peer_list).await.unwrap();

        assert_eq!(count, 1);
        assert!(peer_list.is_banned(&pubkey), "peer must be banned in memory after restore");
    }

    /// Write a ban with expires_at in the past. Assert it is NOT added to PeerList
    /// during startup restore.
    #[tokio::test]
    async fn test_expired_ban_not_restored() {
        let db = make_db();
        let pubkey = test_pubkey(4);

        // Insert a ban that is already expired
        let expires_at = now_secs().saturating_sub(10);
        db.save_ban(&pubkey, expires_at, "old ban").await.unwrap();

        // load_active_bans must filter it out
        let active = db.load_active_bans().await.unwrap();
        assert!(active.is_empty(), "expired ban must not appear in active bans");

        // restore_bans must not add it to PeerList
        let mut peer_list = PeerList::new();
        let count = restore_bans(&db, &mut peer_list).await.unwrap();

        assert_eq!(count, 0);
        assert!(!peer_list.is_banned(&pubkey), "expired ban must not be restored to memory");
    }
}
