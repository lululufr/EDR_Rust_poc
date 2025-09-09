use agent_common::ExecEvent;

use crate::hooking::read_ebpf::{read_cmdline, read_tcp, read_udp};
mod read_ebpf;
mod parse;

use crate::hooking::edr::catch_net;
mod edr;

pub fn handler_cmdline(ev:&ExecEvent){

    let nul = ev
        .comm
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..nul]).to_string();
    let argv = read_cmdline(ev.pid).unwrap_or_default();

    println!(
        "\nEDR CMD :\n - pid={}\n- tgid={}\n- comm={}\n- argv={}",
        ev.pid,
        ev.tgid,
        comm,
        argv.join(" ")
    );
}


pub fn handler_net(ev: &ExecEvent) {
    let nul = ev.comm.iter().position(|&c| c == 0).unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..nul]).to_string();

    if let Some(tcp_entries) = read_tcp(ev.pid) {
        catch_net(tcp_entries.clone()).expect("Chaud ca a pas bloqué");
        println!(
            "\nEDR NET TCP: \n- pid={}\n- tgid={}\n- comm={}\n- connexions_tcp={:?}",
            ev.pid, ev.tgid, comm, tcp_entries
        );
    }

    if let Some(udp_entries) = read_udp(ev.pid) {
        println!(
            "\nEDR NET UDP : \n- pid={}\n- tgid={}\n- comm={}\n- connexions_udp={:?}",
            ev.pid, ev.tgid, comm, udp_entries
        );
    }
}
