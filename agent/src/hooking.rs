use agent_common::ExecEvent;
use libc;

use crate::hooking::read_ebpf::{read_cmdline, read_tcp, read_udp};
mod read_ebpf;
mod parse;

use crate::hooking::edr::catch_net;
mod edr;

use crate::hooking::send_alert::send_alert_to_central;
mod send_alert;

pub fn handler_cmdline(ev:&ExecEvent){

    let nul = ev
        .comm
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..nul]).to_string();
    let argv = read_cmdline(ev.pid).unwrap_or_default();

    // Blocage par nom de binaire via config (config/blocked_cmds.json)
    let argv0_basename: String = argv
        .get(0)
        .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()).to_owned())
        .unwrap_or_else(|| "<unknown>".to_string());
    let is_banned = crate::ebpf_state::BLOCKED_CMDS
        .get()
        .map(|set| set.contains(&comm) || set.contains(&argv0_basename))
        .unwrap_or(false);
    if is_banned {
        // Envoie de l'alert vers le centrale (J'utilise tokio pour faire un appel asynchrone pour éviter de bloquer le thread principal)
        let tgid: u32 = ev.tgid;
        tokio::spawn({
        println!("EDR CMD BLOQUÉ: {} (pid={})", argv0_basename, ev.tgid);
        let alert: String = argv0_basename; // move the String
        async move {
            if let Err(e) = send_alert_to_central(&alert, tgid).await {
                eprintln!("send_alert_to_central failed: {e}");
                }
            }
        });
        unsafe { let _ = libc::kill(ev.tgid as i32, libc::SIGKILL); }
        return;
    }

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
