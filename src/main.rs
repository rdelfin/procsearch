use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use procexec_bpf::ProcexecSkelBuilder;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::time::Duration;

mod procexec_bpf {
    include!(concat!(env!("OUT_DIR"), "/procexec.skel.rs"));
}

fn main() -> anyhow::Result<()> {
    simple_logger::init()?;
    println!("Setting up eBPF program...");

    let builder = ProcexecSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;

    let mut skel = open_skel.load()?;

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&mut skel.maps.rb, exec_events_handler)?;
    let ring_buffer = rb_builder.build()?;

    skel.attach()?;
    println!("Tracing execve events");

    while ring_buffer.poll(Duration::MAX).is_ok() {}
    Ok(())
}

fn exec_events_handler(data: &[u8]) -> i32 {
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
    log::info!("task: {task}; pid={}; args={args:?}", event.pid);
    0
}

#[repr(C)]
struct Event {
    pid: u32,
    task: [u8; 256],
    args: [[u8; 256]; 16],
}
