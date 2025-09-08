use agent_common::ExecEvent;
use crate::read_cmdline;

pub fn handler(ev:&ExecEvent){

    let nul = ev
        .comm
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(ev.comm.len());
    let comm = String::from_utf8_lossy(&ev.comm[..nul]).to_string();
    let argv = read_cmdline(ev.pid).unwrap_or_default();


    println!(
        "EDR attrape l'event : pid={} tgid={} comm={} argv={}",
        ev.pid,
        ev.tgid,
        comm,
        argv.join(" ")
    );
}