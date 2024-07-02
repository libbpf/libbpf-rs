// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use std::mem::MaybeUninit;
use std::str;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use time::macros::format_description;
use time::OffsetDateTime;

mod runqslower {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/runqslower.skel.rs"
    ));
}

use runqslower::*;

/// Trace high run queue latency
#[derive(Debug, Parser)]
struct Command {
    /// Trace latency higher than this value
    #[arg(default_value = "10000")]
    latency: u64,
    /// Process PID to trace
    #[arg(default_value = "0")]
    pid: i32,
    /// Thread TID to trace
    #[arg(default_value = "0")]
    tid: i32,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

unsafe impl Plain for runqslower_types::event {}

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
    let mut event = runqslower_types::event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let task = str::from_utf8(&event.task).unwrap();

    println!(
        "{:8} {:16} {:<7} {:<14}",
        now,
        task.trim_end_matches(char::from(0)),
        event.pid,
        event.delta_us
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = RunqslowerSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Write arguments into prog
    open_skel.maps.rodata_data.min_us = opts.latency;
    open_skel.maps.rodata_data.targ_pid = opts.pid;
    open_skel.maps.rodata_data.targ_tgid = opts.tid;

    // Begin tracing
    let mut object = MaybeUninit::uninit();
    let mut skel = open_skel.load(&mut object)?;
    skel.attach()?;
    println!("Tracing run queue latency higher than {} us", opts.latency);
    println!("{:8} {:16} {:7} {:14}", "TIME", "COMM", "TID", "LAT(us)");

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
