use agent::SocketEntryReadable;
use anyhow::{anyhow, Result};

pub fn catch_net(entry: SocketEntryReadable) -> Result<()> {
    // Récupère la map BLOCKLIST globale (possedée)
    let cell = crate::ebpf_state::BLOCKLIST
        .get()
        .ok_or_else(|| anyhow!("BLOCKLIST non initialisée"))?;
    let mut blocklist = cell.lock().map_err(|_| anyhow!("mutex empoisonné"))?;

    if entry.remote_addr == "1.1.1.1" {
        println!("blocking : {}", entry.remote_addr);
        let ip_be = u32::from_be_bytes([1, 1, 1, 1]); // ordre réseau
        blocklist.insert(ip_be, 1u8, 0)?;
    } else {
        println!("allow : {}", entry.remote_addr);
    }

    Ok(())
}
