#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SocketEntry {
    pub local_addr: u32,   // IPv4 binaire (LE si issu de /proc)
    pub local_port: u16,
    pub remote_addr: u32,
    pub remote_port: u16,
    pub state: u8,
}
