// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use core::time::Duration;
use std::path::PathBuf;
use std::process::exit;

use anyhow::{bail, Result};
use chrono::Local;
use libbpf_rs::{MapFlags, ObjectBuilder, PerfBufferBuilder};
use plain::Plain;
use structopt::StructOpt;

/// Trace high run queue latency
#[derive(Debug, StructOpt)]
struct Command {
    /// Trace latency higher than this value
    #[structopt(default_value = "10000")]
    latency: u64,
    /// Verbose debug output
    #[structopt(short, long)]
    verbose: bool,
    /// Path to runqslower bpf object file
    #[structopt(short, long, default_value = "/bin/runqslower.bpf.o")]
    obj_path: PathBuf,
}

#[repr(C)]
#[derive(Default)]
struct Event {
    pub task: [u8; 16],
    pub delta_us: u64,
    pub pid: i32,
}

unsafe impl Plain for Event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = Local::now();
    let task = std::str::from_utf8(&event.task).unwrap();

    println!(
        "{:8} {:16} {:<7} {:<14}",
        now.format("%H:%M:%S"),
        task.trim_end_matches(char::from(0)),
        event.pid,
        event.delta_us
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    if !opts.obj_path.as_path().exists() {
        eprintln!("{} does not exist", opts.obj_path.as_path().display());
        exit(1);
    }

    let mut obj_builder = ObjectBuilder::default();
    if opts.verbose {
        obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut obj = obj_builder.open_file(opts.obj_path)?.load()?;

    // Write latency value into map
    obj.map_unwrap("min_us").update(
        &0u32.to_le_bytes(),
        &opts.latency.to_le_bytes(),
        MapFlags::empty(),
    )?;

    // NB it's crucial that these are named underscore variables otherwise
    // the link is immediately dropped and our progs aren't run.
    let _wakup_link = obj.prog_unwrap("handle__sched_wakeup").attach()?;
    let _wakeup_new_link = obj.prog_unwrap("handle__sched_wakeup_new").attach()?;
    let _switch_link = obj.prog_unwrap("handle__sched_switch").attach()?;

    println!("Tracing run queue latency higher than {} us", opts.latency);
    println!("{:8} {:16} {:7} {:14}", "TIME", "COMM", "TID", "LAT(us)");

    let events = obj.map_unwrap("events");
    let perf = PerfBufferBuilder::new(events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        let ret = perf.poll(Duration::from_millis(100));
        match ret {
            Ok(()) => (),
            Err(e) => {
                eprintln!("Error polling perf buffer: {}", e);
                exit(1);
            }
        };
    }
}
