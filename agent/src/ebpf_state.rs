use aya::Ebpf;
use once_cell::sync::OnceCell;
use std::sync::Mutex;

pub static EBPF: OnceCell<Mutex<Ebpf>> = OnceCell::new();

use aya::maps::{HashMap as AyaHashMap, MapData};

pub static BLOCKLIST: OnceCell<Mutex<AyaHashMap<MapData, u32, u8>>> = OnceCell::new();
