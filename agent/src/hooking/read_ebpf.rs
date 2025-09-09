use std::fs;
use agent::SocketEntryReadable;
use crate::hooking::parse::{parse_addr_port_str, parse_state_str};

pub fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let path = format!("/proc/{}/cmdline", pid);
    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(
        bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
    )
}
pub fn read_tcp(pid: u32) -> Option<SocketEntryReadable> {
    read_sockets_readable(pid, "tcp")
}

pub fn read_udp(pid: u32) -> Option<SocketEntryReadable> {
    read_sockets_readable(pid, "udp")
}

fn read_sockets_readable(pid: u32, proto: &str) -> Option<SocketEntryReadable> {
    let path = format!("/proc/{}/net/{}", pid, proto);
    let content = fs::read_to_string(path).ok()?;

    // si le fichier est vide ou n'a que l'entête
    if content.lines().count() <= 1 {
        return None;
    }

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }

        let (local_addr, local_port) = parse_addr_port_str(cols[1])?;
        let (remote_addr, remote_port) = parse_addr_port_str(cols[2])?;
        let state = parse_state_str(cols[3]);

        return Some(SocketEntryReadable {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
        });
    }

    None
}
