use std::collections::HashMap;
use std::time::{Duration, Instant};

struct BanEntry {
    expires_at: Instant,
}

pub struct PeerList {
    bans: HashMap<[u8; 32], BanEntry>,
}

impl PeerList {
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
        }
    }

    /// Mark a peer as banned for `duration_secs` seconds starting now.
    /// Overwrites any existing ban for the same pubkey.
    pub fn ban_peer(&mut self, pubkey: &[u8; 32], duration_secs: u64) {
        let expires_at = Instant::now() + Duration::from_secs(duration_secs);
        self.bans.insert(*pubkey, BanEntry { expires_at });
    }

    /// Returns true if the peer is currently banned (ban has not yet expired).
    pub fn is_banned(&self, pubkey: &[u8; 32]) -> bool {
        self.bans
            .get(pubkey)
            .map(|e| e.expires_at > Instant::now())
            .unwrap_or(false)
    }

    /// Removes all expired bans from memory and returns the pubkeys that were lifted.
    /// Callers are responsible for also removing the lifted bans from the database.
    pub fn check_ban_expirations(&mut self) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let expired: Vec<[u8; 32]> = self
            .bans
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(pk, _)| *pk)
            .collect();
        for pk in &expired {
            self.bans.remove(pk);
        }
        expired
    }
}

impl Default for PeerList {
    fn default() -> Self {
        Self::new()
    }
}
