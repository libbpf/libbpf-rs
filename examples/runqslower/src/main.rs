// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use core::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use time::macros::format_description;
use time::OffsetDateTime;

mod runqslower {
    include!(concat!(env!("OUT_DIR"), "/runqslower.skel.rs"));
}

use runqslower::*;

/// Trace high run queue latency
#[derive(Debug, Parser)]
struct Command {
    /// Trace latency higher than this value
    #[clap(default_value = "10000")]
    latency: u64,
    /// Process PID to trace
    #[clap(default_value = "0")]
    pid: i32,
    /// Thread TID to trace
    #[clap(default_value = "0")]
    tid: i32,
    /// Verbose debug output
    #[clap(short, long)]
    verbose: bool,
}

unsafe impl Plain for runqslower_bss_types::event {}

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
    let mut event = runqslower_bss_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let task = std::str::from_utf8(&event.task).unwrap();

    println!(
        "{:8} {:16} {:<7} {:<14}",
        now,
        task.trim_end_matches(char::from(0)),
        event.pid,
        event.delta_us
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let opts = Command::parse();

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

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
