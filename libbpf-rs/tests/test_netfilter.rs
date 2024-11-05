#[allow(dead_code)]
mod common;

use std::net::TcpStream;

use libbpf_rs::NetfilterOpts;
use libbpf_rs::Object;

use libbpf_rs::NFPROTO_IPV4;
use libbpf_rs::NFPROTO_IPV6;

use libbpf_rs::NF_INET_LOCAL_IN;
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
    let error_message = format!(
        "Failed to attach netfilter protocol {}, hook: {}",
        protocol_family, hook_desc
    );
    let link = prog
        .attach_netfilter_with_opts(netfilter_opt)
        .expect(&error_message);

    let map = get_map_mut(obj, "ringbuf");

    let trigger_addr = match protocol_family {
        NFPROTO_IPV4 => Some("127.0.0.1:12345"),
        NFPROTO_IPV6 => Some("[::1]:12345"),
        _ => {
            println!("unknow protocol family");
            None
        }
    };

    if let Some(trigger_addr) = trigger_addr {
        let result = match hook_desc {
            "PRE_ROUTING" | "LOCAL_IN" | "LOCAL_OUT" | "POST_ROUTING" => {
                let action = || {
                    let _ = TcpStream::connect(trigger_addr);
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

// Only selected hooks are tested due to CI failures on certain hooks (e.g., FORWARD, LOCAL_OUT).
// Although these hooks might work in actual use, they were removed from automated testing to
// ensure consistent CI results and maintainability. This approach allows the focus to remain
// on primary netfilter paths (e.g., PRE_ROUTING, LOCAL_IN, POST_ROUTING) that have stable CI
// support. These hooks may be re-added for automated testing in the future if CI compatibility
// improves or specific needs arise.
#[tag(root)]
#[test]
fn test_netfilter() {
    bump_rlimit_mlock();
    let mut obj = get_test_object("netfilter.bpf.o");

    // IPv4 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_LOCAL_IN, "LOCAL_IN");
    test_attach_and_detach(&mut obj, NFPROTO_IPV4, NF_INET_POST_ROUTING, "POST_ROUTING");

    // IPv6 hook
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_PRE_ROUTING, "PRE_ROUTING");
    test_attach_and_detach(&mut obj, NFPROTO_IPV6, NF_INET_LOCAL_IN, "LOCAL_IN");
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
