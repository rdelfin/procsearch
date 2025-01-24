use crate::procexec_bpf::ProcexecSkelBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use log::{error, info};
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub command: String,
    pub args: Vec<String>,
}

pub struct ProcInfoFollower {
    proc_info: Arc<RwLock<HashMap<i32, ProcInfo>>>,
    jh: JoinHandle<()>,
}

impl ProcInfoFollower {
    pub fn new() -> anyhow::Result<ProcInfoFollower> {
        let proc_info = Arc::new(RwLock::default());
        let proc_info_clone = proc_info.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let jh = std::thread::spawn(move || {
            if let Err(e) = Self::rb_thread_runner(started_tx, proc_info_clone) {
                error!("Error in eBPF runner thread: {e}");
                panic!("Error in eBPF runner thread: {e}");
            }
        });
        // Just wait for recv
        started_rx.recv()?;

        Ok(ProcInfoFollower { proc_info, jh })
    }

    pub async fn get_proc_info(&self, pid: i32) -> Option<ProcInfo> {
        self.proc_info.read().await.get(&pid).cloned()
    }

    fn rb_thread_runner(
        started_tx: mpsc::Sender<()>,
        proc_info: Arc<RwLock<HashMap<i32, ProcInfo>>>,
    ) -> anyhow::Result<()> {
        info!("Setting up eBPF program...");
        let builder = ProcexecSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object)?;

        let mut skel = open_skel.load()?;

        let mut rb_builder = RingBufferBuilder::new();
        let proc_info_clone = proc_info.clone();
        rb_builder.add(&mut skel.maps.rb, move |data| {
            exec_events_handler(data, proc_info_clone.clone())
        })?;
        let ring_buffer = rb_builder.build()?;

        skel.attach()?;
        info!("Tracing execve events");

        started_tx.send(())?;
        while ring_buffer.poll(Duration::MAX).is_ok() {}
        Ok(())
    }
}

fn exec_events_handler(data: &[u8], proc_info: Arc<RwLock<HashMap<i32, ProcInfo>>>) -> i32 {
    if data.len() != std::mem::size_of::<Event>() {
        println!(
            "Invalid size {} != {}",
            data.len(),
            std::mem::size_of::<Event>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const Event) };
    let task = CStr::from_bytes_until_nul(&event.task)
        .ok()
        .and_then(|s| s.to_str().ok())
        .unwrap_or("<unknown>");

    let mut args = vec![];
    for arg in event.args {
        if arg[0] == 0 {
            break;
        }
        let c_str = CStr::from_bytes_until_nul(&arg)
            .ok()
            .and_then(|s| s.to_str().ok());
        if let Some(arg) = c_str {
            args.push(arg.to_string());
        } else {
            break;
        }
    }
    let mut proc_info = proc_info.blocking_write();
    proc_info.insert(
        event.pid,
        ProcInfo {
            pid: event.pid,
            command: task.into(),
            args,
        },
    );
    0
}

#[repr(C)]
struct Event {
    pid: i32,
    task: [u8; 256],
    args: [[u8; 256]; 16],
}
