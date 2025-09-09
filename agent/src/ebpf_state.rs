use aya::Ebpf;
use once_cell::sync::OnceCell;
use std::sync::Mutex;

pub static EBPF: OnceCell<Mutex<Ebpf>> = OnceCell::new();

use aya::maps::{HashMap as AyaHashMap, MapData};

pub static BLOCKLIST: OnceCell<Mutex<AyaHashMap<MapData, u32, u8>>> = OnceCell::new();

// Nouvelles commandes bloquées (lecture seule après init)
use std::collections::HashSet;
pub static BLOCKED_CMDS: OnceCell<HashSet<String>> = OnceCell::new();

// Nouvelles IPs bloquées (lecture seule après init)
pub static BLOCKED_IPS: OnceCell<HashSet<String>> = OnceCell::new();
