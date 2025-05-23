// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

//! An example illustrating how to trace long running tasks using BPF.

use std::mem::MaybeUninit;
use std::str;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;

use blazesym::symbolize::source::Kernel;
use blazesym::symbolize::source::Source;
use blazesym::symbolize::Input;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;

mod task_longrun {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/task_longrun.skel.rs"
    ));
}

#[allow(clippy::wildcard_imports)]
use task_longrun::*;

/// Trace high run queue latency
#[derive(Debug, Parser)]
struct Command {
    /// Runtime threshold in ms
    #[arg(short = 't', long, default_value = "100")]
    thresh_ms: u64,
    /// Backtrace capture interval in ms
    #[arg(short = 'i', long, default_value = "10")]
    backtrace_interval_ms: u64,
    /// Only consider kernel threads
    #[arg(short = 'k', long)]
    kthread_only: bool,
    /// Only consider percpu threads
    #[arg(short = 'p', long)]
    percpu_only: bool,
}

unsafe impl Plain for task_longrun::types::event {}

fn main() -> Result<()> {
    let opts = Command::parse();

    let skel_builder = TaskLongrunSkelBuilder::default();

    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .expect("`rodata` is not memory mapped");

    // Write arguments into prog
    rodata.runtime_thresh_ns = opts.thresh_ms * 1000000;
    rodata.backtrace_interval_ns = opts.backtrace_interval_ms * 1000000;
    rodata.kthread_only = opts.kthread_only;
    rodata.percpu_only = opts.percpu_only;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;
    println!("Tracing tasks running longer than {} ms", opts.thresh_ms);

    let stacks = &skel.maps.stacks;
    let src = Source::Kernel(Kernel::default());
    let symbolizer = Symbolizer::new();

    let handle_event = move |_cpu: i32, data: &[u8]| {
        let mut event = task_longrun::types::event::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

        let task = str::from_utf8(&event.comm).unwrap();
        let duration_ms = event.duration as f64 / 1_000_000.0;

        println!(
            "{}[{}]  ran_for={:.2}ms  bt_samples={}",
            task.trim_end_matches(char::from(0)),
            event.pid,
            duration_ms,
            event.bt_sample_cnt
        );
        let bt_start = event.bt_sample_cnt.saturating_sub(64) as usize;
        for bti in bt_start..event.bt_sample_cnt as usize {
            let stkid = event.bt[bti % 64];
            match stacks.lookup(&stkid.to_ne_bytes(), MapFlags::empty()) {
                Ok(Some(stack)) => {
                    let valid_addrs = stack
                        .chunks_exact(8)
                        .map(|chunk| u64::from_ne_bytes(chunk.try_into().unwrap()))
                        .filter(|&addr| addr != 0)
                        .collect::<Vec<_>>();
                    match symbolizer.symbolize(&src, Input::AbsAddr(&valid_addrs)) {
                        Ok(syms) => {
                            for sym in syms {
                                match sym {
                                    Symbolized::Sym(Sym { name, .. }) => {
                                        println!("  {name}");
                                    }
                                    Symbolized::Unknown(reason) => {
                                        println!("<no-symbol> ({reason})")
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("Failed to symbolize addresses: {e}");
                        }
                    }
                }
                Ok(None) => {
                    println!("  Stack id {stkid} not found");
                }
                Err(e) => {
                    println!("Failed to lookup stack id {stkid}: {e}");
                }
            }
            println!();
        }
        println!();
    };

    let handle_lost_events = move |cpu: i32, count: u64| {
        eprintln!("Lost {count} events on CPU {cpu}");
    };

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
