#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint, cgroup_sock_addr},
    maps::{perf::PerfEventArray, HashMap},
    programs::{TracePointContext, SockAddrContext},
};

use agent_common::ExecEvent;

// === EXISTANT ===
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
        EVENTS.output(&ctx, &ev, 0);
    }

    Ok(0)
}

// === BLOCK IP ===

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn block_connect4(ctx: SockAddrContext) -> i32 {
    match try_block_connect4(ctx) {
        Ok(v) => v,
        Err(_) => 1, // fail-open
    }
}

fn try_block_connect4(ctx: SockAddrContext) -> Result<i32, i64> {
    // IPv4 destination en ordre réseau (BE)
    let dst_be = unsafe { (*ctx.sock_addr).user_ip4 };

    // Si présente dans la blocklist -> deny (0), sinon allow (1)
    let deny = unsafe { BLOCKLIST.get(&dst_be).is_some() };
    Ok(if deny { 0 } else { 1 })
}

#[cgroup_sock_addr(sendmsg4)]
pub fn block_sendmsg4(ctx: SockAddrContext) -> i32 {
    match try_block_sendmsg4(ctx) {
        Ok(v) => v,
        Err(_) => 1,
    }
}

fn try_block_sendmsg4(ctx: SockAddrContext) -> Result<i32, i64> {
    let dst_be = unsafe { (*ctx.sock_addr).user_ip4 };
    let deny = unsafe { BLOCKLIST.get(&dst_be).is_some() };
    Ok(if deny { 0 } else { 1 })
}

// === FIN AJOUT ===

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
