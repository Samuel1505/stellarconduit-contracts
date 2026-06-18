use relay_daemon::discovery::peer_list::PeerList;
use relay_daemon::persistence::db::Database;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let db_path = std::env::var("STELLARCONDUIT_DB")
        .unwrap_or_else(|_| "stellarconduit.db".to_string());

    let db = Database::open(&db_path)?;

    // --- Startup: restore active bans from the previous run ---
    let mut peer_list = PeerList::new();

    let active_bans = db.load_active_bans().await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut restored = 0usize;
    for ban in active_bans {
        if ban.expires_at > now {
            let remaining_secs = ban.expires_at - now;
            peer_list.ban_peer(&ban.pubkey, remaining_secs);
            restored += 1;
        }
    }

    log::info!("Restored {} active peer ban(s) from database.", restored);

    // --- Main daemon loop (placeholder) ---
    log::info!("stellarconduitd started. DB: {}", db_path);

    Ok(())
}
