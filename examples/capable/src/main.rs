// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 BMC Software, Inc.
// Author Devasia Thomas <https://www.linkedin.com/in/devasiathomas/>
//
// Based on capable(8) by Brendan Gregg
use core::time::Duration;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
use phf::phf_map;
use plain::Plain;
use time::macros::format_description;
use time::OffsetDateTime;

mod capable {
    include!(concat!(env!("OUT_DIR"), "/capable.skel.rs"));
}

use capable::capable_rodata_types::uniqueness;
use capable::*;

static CAPS: phf::Map<i32, &'static str> = phf_map! {
    0i32 => "CAP_CHOWN",
    1i32 => "CAP_DAC_OVERRIDE",
    2i32 => "CAP_DAC_READ_SEARCH",
    3i32 => "CAP_FOWNER",
    4i32 => "CAP_FSETID",
    5i32 => "CAP_KILL",
    6i32 => "CAP_SETGID",
    7i32 => "CAP_SETUID",
    8i32 => "CAP_SETPCAP",
    9i32 => "CAP_LINUX_IMMUTABLE",
    10i32 => "CAP_NET_BIND_SERVICE",
    11i32 => "CAP_NET_BROADCAST",
    12i32 => "CAP_NET_ADMIN",
    13i32 => "CAP_NET_RAW",
    14i32 => "CAP_IPC_LOCK",
    15i32 => "CAP_IPC_OWNER",
    16i32 => "CAP_SYS_MODULE",
    17i32 => "CAP_SYS_RAWIO",
    18i32 => "CAP_SYS_CHROOT",
    19i32 => "CAP_SYS_PTRACE",
    20i32 => "CAP_SYS_PACCT",
    21i32 => "CAP_SYS_ADMIN",
    22i32 => "CAP_SYS_BOOT",
    23i32 => "CAP_SYS_NICE",
    24i32 => "CAP_SYS_RESOURCE",
    25i32 => "CAP_SYS_TIME",
    26i32 => "CAP_SYS_TTY_CONFIG",
    27i32 => "CAP_MKNOD",
    28i32 => "CAP_LEASE",
    29i32 => "CAP_AUDIT_WRITE",
    30i32 => "CAP_AUDIT_CONTROL",
    31i32 => "CAP_SETFCAP",
    32i32 => "CAP_MAC_OVERRIDE",
    33i32 => "CAP_MAC_ADMIN",
    34i32 => "CAP_SYSLOG",
    35i32 => "CAP_WAKE_ALARM",
    36i32 => "CAP_BLOCK_SUSPEND",
    37i32 => "CAP_AUDIT_READ",
    38i32 => "CAP_PERFMON",
    39i32 => "CAP_BPF",
    40i32 => "CAP_CHECKPOINT_RESTORE",
};

impl FromStr for uniqueness {
    type Err = &'static str;
    fn from_str(unq_type: &str) -> Result<Self, Self::Err> {
        let unq_type_lower: &str = &unq_type.to_lowercase();
        match unq_type_lower {
            "off" => Ok(uniqueness::UNQ_OFF),
            "pid" => Ok(uniqueness::UNQ_PID),
            "cgroup" => Ok(uniqueness::UNQ_CGROUP),
            _ => Err("Use 1 for pid (default), 2 for cgroups"),
        }
    }
}

/// Trace capabilities
#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "examples", about = "Usage instructions")]
struct Command {
    /// verbose: include non-audit checks
    #[clap(short, long)]
    verbose: bool,
    /// only trace <pid>
    #[clap(short, long, default_value = "0")]
    pid: u32,
    /// extra fields: Show TID and INSETID columns
    #[clap(short = 'x', long = "extra")]
    extra_fields: bool,
    /// don't repeat same info for the same <pid> or <cgroup>
    #[clap(long = "unique", default_value = "off")]
    unique_type: uniqueness,
    /// debug output for libbpf-rs
    #[clap(long)]
    debug: bool,
}

unsafe impl Plain for capable_bss_types::event {}

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

fn print_banner(extra_fields: bool) {
    #[allow(clippy::print_literal)]
    if extra_fields {
        println!(
            "{:9} {:6} {:6} {:6} {:16} {:4} {:20} {:6} {}",
            "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT", "INSETID"
        );
    } else {
        println!(
            "{:9} {:6} {:6} {:16} {:4} {:20} {:6}",
            "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT"
        );
    }
}

fn _handle_event(opts: Command, event: capable_bss_types::event) {
    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let comm_str = std::str::from_utf8(&event.comm)
        .unwrap()
        .trim_end_matches(char::from(0));
    let cap_name = match CAPS.get(&event.cap) {
        Some(&x) => x,
        None => "?",
    };
    if opts.extra_fields {
        println!(
            "{:9} {:6} {:<6} {:<6} {:<16} {:<4} {:<20} {:<6} {}",
            now,
            event.uid,
            event.tgid,
            event.pid,
            comm_str,
            event.cap,
            cap_name,
            event.audit,
            event.insetid
        );
    } else {
        println!(
            "{:9} {:6} {:<6} {:<16} {:<4} {:<20} {:<6}",
            now, event.uid, event.tgid, comm_str, event.cap, cap_name, event.audit
        );
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = CapableSkelBuilder::default();
    if opts.debug {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;
    //Pass configuration to BPF
    open_skel.rodata().tool_config.tgid = opts.pid; //tgid in kernel is pid in userland
    open_skel.rodata().tool_config.verbose = opts.verbose;
    open_skel.rodata().tool_config.unique_type = opts.unique_type;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    print_banner(opts.extra_fields);
    let handle_event = move |_cpu: i32, data: &[u8]| {
        let mut event = capable_bss_types::event::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
        _handle_event(opts, event);
    };
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
