use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::discovery::peer_list::PeerList;
use crate::persistence::db::{Database, DbError};

pub const DEFAULT_BAN_DURATION_SECS: u64 = 24 * 60 * 60;

/// A gossip message received from a peer.
pub struct TransactionEnvelope {
    pub sender_pubkey: [u8; 32],
    pub payload: Vec<u8>,
}

/// Process an inbound transaction envelope.
///
/// When the envelope fails validation and the sender is determined to be
/// malicious, the peer is banned: the ban is written to `db` first for
/// durability, then applied to `peer_list` in memory.  The same pattern
/// must be followed in the rate-limiter violation handler whenever
/// `peer_list.ban_peer()` would have been called.
pub async fn process_transaction_envelope(
    envelope: &TransactionEnvelope,
    peer_list: Arc<Mutex<PeerList>>,
    db: &Database,
) -> Result<(), DbError> {
    if is_malicious(envelope) {
        ban_sender(
            &envelope.sender_pubkey,
            "malicious transaction envelope",
            DEFAULT_BAN_DURATION_SECS,
            &peer_list,
            db,
        )
        .await?;
    }
    Ok(())
}

/// Persist and enforce a peer ban arising from any protocol violation.
///
/// Writes to the database before touching in-memory state so that a crash
/// between the two steps leaves the node in a safe (over-banned) posture
/// rather than a vulnerable (under-banned) one.
pub async fn ban_sender(
    pubkey: &[u8; 32],
    reason: &str,
    duration_secs: u64,
    peer_list: &Arc<Mutex<PeerList>>,
    db: &Database,
) -> Result<(), DbError> {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + duration_secs;

    db.save_ban(pubkey, expires_at, reason).await?;

    let mut list = peer_list.lock().await;
    list.ban_peer(pubkey, duration_secs);

    Ok(())
}

fn is_malicious(envelope: &TransactionEnvelope) -> bool {
    // Placeholder: real implementation validates signatures, replay windows,
    // rate limits, and strike counters before returning true.
    let _ = envelope;
    false
}
