#[allow(dead_code)]
mod common;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::TcpListener;
use std::net::TcpStream;

use libbpf_rs::NetfilterOpts;
use libbpf_rs::Object;

use libbpf_rs::NFPROTO_IPV4;
use libbpf_rs::NFPROTO_IPV6;

use libbpf_rs::NF_INET_POST_ROUTING;
use libbpf_rs::NF_INET_PRE_ROUTING;

use crate::common::bump_rlimit_mlock;
use crate::common::get_map_mut;
use crate::common::get_prog_mut;
use crate::common::get_test_object;
use crate::common::with_ringbuffer;
use test_tag::tag;


fn test_attach_and_detach(obj: &mut Object, protocol_family: i32, hooknum: i32, hook_desc: &str) {
    let prog = get_prog_mut(obj, "handle_netfilter");
    let netfilter_opt = libbpf_rs::NetfilterOpts {
        protocol_family,
        hooknum,
        ..NetfilterOpts::default()
    };
    let link = prog
        .attach_netfilter_with_opts(netfilter_opt)
        .unwrap_or_else(|err| {
            panic!(
                "Failed to attach netfilter protocol {}, hook: {}: {err}",
                protocol_family, hook_desc
            )
        });

    let map = get_map_mut(obj, "ringbuf");

    let addr = match protocol_family {
        NFPROTO_IPV4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
        NFPROTO_IPV6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => panic!("unknow protocol family: {protocol_family}"),
    };
    // We let the kernel decide what port to bind to.
    let listener = TcpListener::bind((addr, 0)).unwrap();
    let trigger_addr = listener.local_addr().unwrap();

    let result = match hooknum {
        NF_INET_PRE_ROUTING | NF_INET_POST_ROUTING => {
            let action = || {
                let _ = TcpStream::connect(trigger_addr);
            };
            with_ringbuffer(&map, action)
        }
        _ => panic!("unsupported hook: {hooknum} ({hook_desc})"),
    };
    assert_eq!(result, 1);
    assert!(link.detach().is_ok());
}

#[tag(root)]
#[test]
fn test_netfilter() {
    bump_rlimit_mlock();
    let mut obj = get_test_object("netfilter.bpf.o");

    // We don't test all hooks here, because support for some may be
    // more limited.

    // IPv4 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_POST_ROUTING, "POST_ROUTING");

    // IPv6 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_POST_ROUTING, "POST_ROUTING");
}

#[tag(root)]
#[test]
fn test_invalid_netfilter_opts() {
    let mut obj = get_test_object("netfilter.bpf.o");
    let prog = get_prog_mut(&mut obj, "handle_netfilter");

    let invalid_opts = NetfilterOpts {
        protocol_family: 999,
        hooknum: 999,
        ..NetfilterOpts::default()
    };

    let result = prog.attach_netfilter_with_opts(invalid_opts);
    assert!(
        result.is_err(),
        "Expected error for invalid NetfilterOpts, but got Ok."
    );
}
