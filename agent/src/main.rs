//ADDING LOGIQUE ICI
mod hooking;
mod ebpf_state;
mod config;

use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::programs::CgroupSockAddr;
use aya::programs::CgroupAttachMode;
use aya::util::online_cpus;

use anyhow::anyhow;
use anyhow::Context;
use bytes::BytesMut;
use log::{debug, warn};

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::collections::HashSet;

use agent_common::ExecEvent;

fn current_cgroup_dir() -> anyhow::Result<PathBuf> {
    let cg_root = Path::new("/sys/fs/cgroup");
    if !cg_root.join("cgroup.controllers").exists() {
        return Err(anyhow!("cgroup v2 non détecté: /sys/fs/cgroup/cgroup.controllers absent. Montez cgroup2 (ex: mount -t cgroup2 none /sys/fs/cgroup) et relancez."));
    }
    let data = std::fs::read_to_string("/proc/self/cgroup")
        .with_context(|| "lecture de /proc/self/cgroup")?;
    // Format v2: une seule ligne 0::/path
    for line in data.lines() {
        if let Some(pos) = line.find("::") {
            let path = &line[pos + 2..];
            let full = cg_root.join(path.trim_start_matches('/'));
            if full.exists() {
                return Ok(full);
            }
        }
    }
    // Fallback: racine
    Ok(cg_root.to_path_buf())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Raise memlock limit (useful on older kernels).
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load embedded eBPF object produced by build.rs
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/agent"
    )))?;

    // Optional: forward aya-log from kernel (init puis drop immédiat)
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Attach tracepoint sched:sched_process_exec (program is "agent" in ebpf crate).
    {
        let program: &mut TracePoint = ebpf.program_mut("agent").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exec")?;
    }
    // emrunts sur `ebpf` libérés ici

    // Vérifie que cgroup v2 est monté
    let cg_root = std::path::Path::new("/sys/fs/cgroup");
    if !cg_root.join("cgroup.controllers").exists() {
        return Err(anyhow!("cgroup v2 non détecté: /sys/fs/cgroup/cgroup.controllers absent. Montez cgroup2 (ex: mount -t cgroup2 none /sys/fs/cgroup) et relancez."));
    }

    // Attache le programme cgroup_sock_addr(connect4) au cgroup racine
    {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut("block_connect4")
            .ok_or_else(|| anyhow!("program block_connect4 not found"))?
            .try_into()?;
        prog.load().with_context(|| "chargement du programme cgroup_sock_addr")?;
        let cg_file = std::fs::File::open(cg_root)
            .with_context(|| format!("ouverture du répertoire du cgroup {:?}", cg_root))?;
        prog.attach(&cg_file, CgroupAttachMode::default())
            .with_context(|| format!("attachement du programme cgroup_sock_addr(connect4) au cgroup {:?}", cg_root))?;
    }

    // Attache le programme cgroup_sock_addr(sendmsg4) au cgroup racine (UDP/DNS)
    {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut("block_sendmsg4")
            .ok_or_else(|| anyhow!("program block_sendmsg4 not found"))?
            .try_into()?;
        prog.load().with_context(|| "chargement du programme cgroup_sock_addr (sendmsg4)")?;
        let cg_file = std::fs::File::open(cg_root)
            .with_context(|| format!("ouverture du répertoire du cgroup {:?}", cg_root))?;
        prog.attach(&cg_file, CgroupAttachMode::default())
            .with_context(|| format!("attachement du programme cgroup_sock_addr(sendmsg4) au cgroup {:?}", cg_root))?;
    }

    // Expose global BLOCKLIST handle (owned via take_map)
    {
        let map = ebpf
            .take_map("BLOCKLIST")
            .ok_or_else(|| anyhow!("map BLOCKLIST not found"))?;
        let mut blocklist: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(map)?;

        // Charge les IPs interdites depuis le fichier JSON et les insère
        let blocked_ips = crate::config::load_blocked_ips("config/blocked_ips.json")
            .with_context(|| "chargement des IPs interdites")?;
        for ip in &blocked_ips {
            let key = u32::from_be_bytes(ip.octets());
            let _ = blocklist.insert(key, 1u8, 0);
        }
        // Publie aussi la liste sous forme de chaînes pour la logique userland
        let ip_strs: HashSet<String> = blocked_ips.into_iter().map(|ip| ip.to_string()).collect();
        let _ = crate::ebpf_state::BLOCKED_IPS.set(ip_strs);

        crate::ebpf_state::BLOCKLIST
            .set(std::sync::Mutex::new(blocklist))
            .expect("BLOCKLIST déjà initialisé");
    }

    // Charge et publie la liste des commandes interdites
    {
        let cmds = crate::config::load_blocked_cmds("config/blocked_cmds.json")
            .with_context(|| "chargement des commandes interdites")?;
        let _ = crate::ebpf_state::BLOCKED_CMDS.set(cmds);
    }

    // ---- PerfEventArray setup (owned handle) ----
    let mut per_cpu_bufs = Vec::new();
    {
        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow!("map EVENTS not found"))?;
        let mut events: PerfEventArray<_> = PerfEventArray::try_from(map)?;

        let cpus = online_cpus().map_err(|e| anyhow!("online_cpus failed: {:?}", e))?;
        for cpu in cpus {
            let perf_buf = events.open(cpu, None)?;
            let pool = (0..64)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<ExecEvent>()))
                .collect::<Vec<_>>();
            per_cpu_bufs.push((cpu, perf_buf, pool));
        }
    }
    // -------------------------------------------

    println!("EDR lancé !");

    // Cooperative shutdown: a Ctrl-C task toggles this flag.
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            r.store(false, Ordering::Relaxed);
        });
    }

    // Blocking poll loop on the main thread — no 'static lifetimes required.
    while running.load(Ordering::Relaxed) {
        // Iterate each CPU’s perf buffer
        for (cpu, perf_buf, pool) in per_cpu_bufs.iter_mut() {
            match perf_buf.read_events(pool.as_mut_slice()) {
                Ok(_events) => {
                    // Any BytesMut in the pool that received data is non-empty.
                    for b in pool.iter_mut() {
                        if b.is_empty() {
                            continue;
                        }
                        if b.len() >= core::mem::size_of::<ExecEvent>() {
                            // SAFETY: kernel wrote an ExecEvent payload
                            let ev: &ExecEvent = unsafe { &*(b.as_ptr() as *const ExecEvent) };

                            //LOGIQUE EDR !!!!!!!!!
                            hooking::handler_cmdline(ev);
                            hooking::handler_net(ev);
                            //LOGIQUE EDR !!!!!!!!! FIN
                        }
                        // Important: clear buffer for reuse
                        b.clear();
                    }
                }
                Err(e) => {
                    eprintln!("perf read error on CPU {}: {}", cpu, e);
                }
            }
        }

        // Small sleep to avoid busy-spinning if there’s no traffic
        std::thread::sleep(Duration::from_millis(5));
    }

    println!("\n\nExiting…");
    Ok(())
}
