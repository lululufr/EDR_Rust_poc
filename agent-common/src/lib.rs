#![no_std]

#[repr(C)]
#[derive(Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
}