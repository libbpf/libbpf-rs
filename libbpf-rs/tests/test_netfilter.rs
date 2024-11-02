#[allow(dead_code)]
mod common;

use std::process::Command;

use libbpf_rs::Map;
use libbpf_rs::NetfilterOpts;
use libbpf_rs::Object;
use test_tag::tag;

use libbpf_rs::NFPROTO_IPV4;
use libbpf_rs::NFPROTO_IPV6;

// use libbpf_rs::NF_INET_FORWARD;
use libbpf_rs::NF_INET_LOCAL_IN;
// use libbpf_rs::NF_INET_LOCAL_OUT;
use libbpf_rs::NF_INET_POST_ROUTING;
use libbpf_rs::NF_INET_PRE_ROUTING;

use crate::common::bump_rlimit_mlock;
use crate::common::get_map_mut;
use crate::common::get_prog_mut;
use crate::common::get_test_object;

// copy from test
// I wasn't sure if I could just move this function to common so I copied it
fn with_ringbuffer<F>(map: &Map, action: F) -> i32
where
    F: FnOnce(),
{
    let mut value = 0i32;
    {
        let callback = |data: &[u8]| {
            plain::copy_from_bytes(&mut value, data).expect("Wrong size");
            0
        };

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(map, callback).expect("failed to add ringbuf");
        let mgr = builder.build().expect("failed to build");

        action();
        mgr.consume().expect("failed to consume ringbuf");
    }

    value
}

fn test_attach_and_detach(obj: &mut Object, pf: u32, hooknum: u32, hook_desc: &str) {
    let prog = get_prog_mut(obj, "handle_netfilter");
    let netfilter_opt = libbpf_rs::NetfilterOpts {
        pf,
        hooknum,
        ..NetfilterOpts::default()
    };
    let error_message = format!(
        "Failed to attach netfilter protocol {}, hook: {}",
        pf, hook_desc
    );
    let link = prog.attach_netfilter(netfilter_opt).expect(&error_message);

    let map = get_map_mut(obj, "ringbuf");

    if pf == 2 {
        let result = match hook_desc {
            "PRE_ROUTING" | "LOCAL_IN" | "LOCAL_OUT" | "POST_ROUTING" => {
                let action = || {
                    Command::new("sh")
                        .arg("-c")
                        .arg("echo 'Test data' | nc -u 127.0.0.1 12345")
                        .output()
                        .expect("Failed to send packet");
                };
                with_ringbuffer(&map, action)
            }
            "FORWARD" => 1,
            _ => {
                panic!("unknow hook")
            }
        };
        assert_eq!(result, 1);
    }
    assert!(link.detach().is_ok());
}

#[tag(root)]
#[test]
fn test_netfilter() {
    bump_rlimit_mlock();
    let mut obj = get_test_object("netfilter.bpf.o");

    // IPv4 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_LOCAL_IN, "LOCAL_IN");
    // test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_FORWARD, "FORWARD");
    // test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_LOCAL_OUT, "LOCAL_OUT");
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_POST_ROUTING, "POST_ROUTING");

    // IPv6 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_LOCAL_IN, "LOCAL_IN");
    // test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_FORWARD, "FORWARD");
    // test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_LOCAL_OUT, "LOCAL_OUT");
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_POST_ROUTING, "POST_ROUTING");
}

#[tag(root)]
#[test]
fn test_invalid_netfilter_opts() {
    let mut obj = get_test_object("netfilter.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle_netfilter");

    let invalid_opts = NetfilterOpts {
        pf: 999,
        hooknum: 999,
        ..NetfilterOpts::default()
    };

    let result = prog.attach_netfilter(invalid_opts);
    assert!(
        result.is_err(),
        "Expected error for invalid NetfilterOpts, but got Ok."
    );
}
