use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::discovery::peer_list::PeerList;
use crate::persistence::db::{Database, DbError};

/// Coordinates in-memory ban state (PeerList) with durable storage (Database).
pub struct PeerBanManager {
    pub db: Database,
    peer_list: Arc<Mutex<PeerList>>,
}

impl PeerBanManager {
    pub fn new(db: Database, peer_list: Arc<Mutex<PeerList>>) -> Self {
        Self { db, peer_list }
    }

    /// Ban a peer for `duration_secs` seconds, persisting the ban to the database
    /// before updating in-memory state so durability is guaranteed even on crash.
    pub async fn ban_peer(
        &self,
        pubkey: &[u8; 32],
        duration_secs: u64,
        reason: &str,
    ) -> Result<(), DbError> {
        let expires_at = now_secs() + duration_secs;
        self.db.save_ban(pubkey, expires_at, reason).await?;
        let mut list = self.peer_list.lock().await;
        list.ban_peer(pubkey, duration_secs);
        Ok(())
    }

    /// Sweep expired in-memory bans and remove their database records.
    /// Called periodically by the daemon's maintenance loop.
    pub async fn check_expirations(&self) -> Result<(), DbError> {
        let expired = {
            let mut list = self.peer_list.lock().await;
            list.check_ban_expirations()
        };
        for pubkey in &expired {
            self.db.remove_ban(pubkey).await?;
        }
        Ok(())
    }
}

/// Reload all non-expired bans from the database into a freshly created PeerList.
/// Returns the number of bans restored. Call this once at daemon startup after the
/// database is opened and before accepting any peer connections.
pub async fn restore_bans(db: &Database, peer_list: &mut PeerList) -> Result<usize, DbError> {
    let active_bans = db.load_active_bans().await?;
    let now = now_secs();
    let mut count = 0;
    for ban in &active_bans {
        if ban.expires_at > now {
            let remaining_secs = ban.expires_at - now;
            peer_list.ban_peer(&ban.pubkey, remaining_secs);
            count += 1;
        }
    }
    Ok(count)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
