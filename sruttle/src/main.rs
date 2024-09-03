use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use sruttle_common::PacketLog;
use tokio::{signal, task};
use walkdir::WalkDir;

#[derive(Debug, Default)]
struct ThrottledStatPerCpu(HashMap<u32, u64>);

impl ThrottledStatPerCpu {
    fn insert(&mut self, cgroup_inode: u32, throttled_us: u64) {
        let old = *self.0.get(&cgroup_inode).unwrap_or(&0);
        let new = old + throttled_us;
        _ = self.0.insert(cgroup_inode, new);
    }

    fn insert_by_packet_log(&mut self, packet_log: &PacketLog) {
        self.insert(packet_log.cgroup_inode, packet_log.throttled_us)
    }
}

struct ThrottledStat {
    data: Vec<Arc<Mutex<ThrottledStatPerCpu>>>,
}

impl ThrottledStat {
    fn new(cpu_num: usize) -> Self {
        let mut data = Vec::with_capacity(cpu_num);
        data.resize(
            cpu_num,
            Arc::new(Mutex::new(ThrottledStatPerCpu::default())),
        );
        ThrottledStat { data }
    }

    fn get(&self, idx: usize) -> Arc<Mutex<ThrottledStatPerCpu>> {
        self.data[idx].clone()
    }

    fn gather(&self) -> HashMap<u32, u64> {
        let mut result = HashMap::new();
        self.data.iter().for_each(|d| {
            let stat = d.lock().unwrap();
            stat.0.iter().for_each(|(&cgroup_inode, &throttled_us)| {
                let old = *result.get(&cgroup_inode).unwrap_or(&0);
                let new = old + throttled_us;
                let _ = result.insert(cgroup_inode, new);
            });
        });
        result
    }
}

lazy_static! {
    static ref THROTTLED_STAT: ThrottledStat = ThrottledStat::new(online_cpus().unwrap().len());
}

fn path_from_inode(inode: u64) -> Vec<PathBuf> {
    WalkDir::new("/sys/fs/cgroup")
        .into_iter()
        .filter_map(|e| {
            if let Ok(dir) = e {
                if let Ok(meta) = dir.metadata() {
                    if meta.ino() == inode {
                        return Some(dir.into_path());
                    }
                }
            }
            None
        })
        .collect::<Vec<PathBuf>>()
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sruttle"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sruttle"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("sruttle").unwrap().try_into()?;
    program.load()?;
    program.attach("unthrottle_cfs_rq", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let stat_per_cpu = THROTTLED_STAT.get(cpu_id as usize);

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            let events = buf.read_events(&mut buffers).await.unwrap();
            for buf in buffers.iter_mut().take(events.read) {
                let ptr = buf.as_ptr() as *const PacketLog;
                let packet_log = unsafe { ptr.read_unaligned() };
                stat_per_cpu
                    .lock()
                    .unwrap()
                    .insert_by_packet_log(&packet_log);
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    let stat = THROTTLED_STAT.gather();
    println!("cgroup-path\tthrottled_us");
    stat.iter().for_each(|(&inode, &throttled_us)| {
        if let Some(path) = path_from_inode(inode as u64).first() {
            println!("{}\t{}", path.to_str().unwrap(), throttled_us);
        }
    });

    info!("Exiting...");

    Ok(())
}
