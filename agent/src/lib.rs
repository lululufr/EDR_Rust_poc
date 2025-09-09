extern crate alloc;

use alloc::string::String;

#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct SocketEntryReadable {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
}