#![no_std]
#![no_main]
#![allow(static_mut_refs)]  // <- add this for Rust 2024

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::perf::PerfEventArray,
    programs::TracePointContext,
};
// use aya_log_ebpf::info; // optional

use agent_common::ExecEvent;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn agent(ctx: TracePointContext) -> u32 {
    match try_agent(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_agent(ctx: TracePointContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let ev = ExecEvent { pid, tgid, comm };

    unsafe {
        // emit one record with this ExecEvent payload
        EVENTS.output(&ctx, &ev, 0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
