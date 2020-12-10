// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use core::time::Duration;
use std::process::exit;

use anyhow::{bail, Result};
use chrono::Local;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use structopt::StructOpt;

mod bpf;
use bpf::*;

/// Trace high run queue latency
#[derive(Debug, StructOpt)]
struct Command {
    /// Trace latency higher than this value
    #[structopt(default_value = "10000")]
    latency: u64,
    /// Process PID to trace
    #[structopt(default_value = "0")]
    pid: i32,
    /// Thread TID to trace
    #[structopt(default_value = "0")]
    tid: i32,
    /// Verbose debug output
    #[structopt(short, long)]
    verbose: bool,
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

    let mut skel_builder = RunqslowerSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    // Write arguments into prog
    open_skel.rodata().min_us = opts.latency;
    open_skel.rodata().targ_pid = opts.pid;
    open_skel.rodata().targ_tgid = opts.tid;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;
    println!("Tracing run queue latency higher than {} us", opts.latency);
    println!("{:8} {:16} {:7} {:14}", "TIME", "COMM", "TID", "LAT(us)");

    let perf = PerfBufferBuilder::new(skel.maps().events())
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
