
//ADDING LOGIQUE ICI
mod hooking;

use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;

use anyhow::anyhow;
use bytes::BytesMut;
use log::{debug, warn};

use std::{fs, time::Duration};

use agent_common::ExecEvent;


fn read_cmdline(pid: u32) -> Option<Vec<String>> {
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

    // Optional: forward aya-log from kernel
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Attach tracepoint sched:sched_process_exec (program is "agent" in ebpf crate).
    let program: &mut TracePoint = ebpf.program_mut("agent").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // ---- PerfEventArray setup (no threads) ----
    let map = ebpf
        .map_mut("EVENTS")
        .ok_or_else(|| anyhow!("map EVENTS not found"))?;
    let mut events: PerfEventArray<_> = PerfEventArray::try_from(map)?;

    // One perf buffer per CPU
    let cpus = online_cpus().map_err(|e| anyhow!("online_cpus failed: {:?}", e))?;
    let mut per_cpu_bufs = Vec::new(); // Vec<(cpu_id, perf_buf, pool)>
    for cpu in cpus {
        let perf_buf = events.open(cpu, None)?;
        // Pool of BytesMut buffers for this perf reader
        let pool = (0..64)
            .map(|_| BytesMut::with_capacity(core::mem::size_of::<ExecEvent>()))
            .collect::<Vec<_>>();
        per_cpu_bufs.push((cpu, perf_buf, pool));
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


                            hooking::handler(ev);


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

    println!("Exiting…");
    Ok(())
}
