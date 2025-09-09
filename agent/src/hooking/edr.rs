use agent::SocketEntryReadable;
use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};

pub fn catch_net(entry: SocketEntryReadable) -> Result<()> {
    // Récupère la map BLOCKLIST globale (possédée)
    let cell = crate::ebpf_state::BLOCKLIST
        .get()
        .ok_or_else(|| anyhow!("BLOCKLIST non initialisée"))?;
    let mut blocklist = cell.lock().map_err(|_| anyhow!("mutex empoisonné"))?;

    // Récupère la liste d'IPs bloquées depuis la config
    let blocked_ips = crate::ebpf_state::BLOCKED_IPS
        .get()
        .ok_or_else(|| anyhow!("BLOCKED_IPS non initialisée"))?;

    if blocked_ips.contains(&entry.remote_addr) {
        // Conversion de la chaîne en IPv4 et insertion dans la map eBPF (ordre réseau)
        if let Ok(IpAddr::V4(v4)) = entry.remote_addr.parse::<IpAddr>() {
            let ip_be: u32 = u32::from_be_bytes(v4.octets());
            let _ = blocklist.insert(ip_be, 1u8, 0)?;
            println!("blocking : {}", entry.remote_addr);
        } else {
            println!("allow (non-IPv4): {}", entry.remote_addr);
        }
    } else {
        println!("allow : {}", entry.remote_addr);
    }

    Ok(())
}
