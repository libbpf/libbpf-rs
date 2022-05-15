use serial_test::serial;

mod test;
use test::{bump_rlimit_mlock, get_test_object};

use nix::errno::Errno::{EINVAL, ENOENT};

use libbpf_rs::{
    Error, Object, Result, TcHook, TcHookBuilder, TC_CUSTOM, TC_EGRESS, TC_H_CLSACT,
    TC_H_MIN_EGRESS, TC_H_MIN_INGRESS, TC_INGRESS,
};
// do all TC tests on the lo network interface
const LO_IFINDEX: i32 = 1;

fn clear_clsact(fd: i32) -> Result<()> {
    // Ensure clean clsact tc qdisc
    let mut destroyer = TcHook::new(fd);
    destroyer
        .ifindex(LO_IFINDEX)
        .attach_point(TC_EGRESS | TC_INGRESS);

    let res = destroyer.destroy();
    if let Err(Error::System(err)) = res {
        if err != -(ENOENT as i32) && err != -(EINVAL as i32) {
            return res;
        }
    }

    Ok(())
}

fn test_helper_get_tc_builder(handle_str: &str) -> (Object, TcHookBuilder, i32) {
    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog(handle_str).unwrap().fd();

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);

    (obj, tc_builder, fd)
}

#[test]
#[serial]
fn test_tc_basic_cycle() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    //assert!(!destroyer.destroy().is_err());
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    assert!(egress.create().is_ok());
    assert!(egress.attach().is_ok());
    assert!(egress.query().is_ok());
    assert!(egress.detach().is_ok());
    assert!(egress.destroy().is_ok());
    assert!(clear_clsact(fd).is_ok());

    let mut ingress = tc_builder.hook(TC_EGRESS);
    assert!(ingress.create().is_ok());
    assert!(ingress.attach().is_ok());
    assert!(ingress.query().is_ok());
    assert!(ingress.detach().is_ok());
    assert!(ingress.destroy().is_ok());
    assert!(clear_clsact(fd).is_ok());

    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(ingress.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(custom.query().is_ok());
    assert!(custom.detach().is_ok());
    assert!(clear_clsact(fd).is_ok());
}

#[test]
#[serial]
fn test_tc_attach_no_qdisc() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);

    assert!(egress.attach().is_err());
    assert!(ingress.attach().is_err());
    assert!(custom.attach().is_err());
}

#[test]
#[serial]
fn test_tc_attach_basic() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    assert!(egress.attach().is_err());
    assert!(egress.create().is_ok());
    assert!(egress.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());

    let mut ingress = tc_builder.hook(TC_INGRESS);
    assert!(ingress.attach().is_err());
    assert!(ingress.create().is_ok());
    assert!(ingress.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());
}

#[test]
#[serial]
fn test_tc_attach_repeat() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    assert!(egress.create().is_ok());
    for _ in 0..10 {
        assert!(egress.attach().is_ok());
    }

    let mut ingress = tc_builder.hook(TC_INGRESS);
    for _ in 0..10 {
        assert!(ingress.attach().is_ok());
    }

    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_EGRESS);
    for _ in 0..10 {
        assert!(custom.attach().is_ok());
    }
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    for _ in 0..10 {
        assert!(custom.attach().is_ok());
    }

    assert!(clear_clsact(fd).is_ok());
}

#[test]
#[serial]
fn test_tc_attach_custom() {
    bump_rlimit_mlock();
    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    // destroy() ensures that clsact tc qdisc does not exist
    // but BPF hooks need this qdisc in order to attach
    // for ingress and egress hooks, the create() method will
    // ensure that clsact tc qdisc is available, but custom hooks
    // cannot call create(), thus we need to utilize an ingress, egress, or
    // egress|ingress hook to create() and ensure
    // the clsact tc qdisc is available

    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(custom.attach().is_err());
    assert!(custom.create().is_err());

    let mut ingress_for_parent = tc_builder.hook(TC_INGRESS);
    assert!(ingress_for_parent.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());
    assert!(custom.attach().is_err());

    custom.parent(TC_H_CLSACT, TC_H_MIN_EGRESS);
    assert!(ingress_for_parent.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());
    assert!(custom.attach().is_err());

    let mut egress_for_parent = tc_builder.hook(TC_EGRESS);
    assert!(egress_for_parent.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());
    assert!(custom.attach().is_err());

    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(egress_for_parent.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(clear_clsact(fd).is_ok());
    assert!(custom.attach().is_err());
}

#[test]
#[serial]
fn test_tc_detach_basic() {
    bump_rlimit_mlock();
    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    custom.handle(2);

    assert!(egress.create().is_ok());
    assert!(egress.attach().is_ok());
    assert!(ingress.attach().is_ok());
    assert!(custom.attach().is_ok());

    assert!(egress.detach().is_ok());
    assert!(ingress.detach().is_ok());
    assert!(custom.detach().is_ok());

    // test for double detach, error is ENOENT
    let is_enoent = |hook: &mut TcHook| {
        if let Err(Error::System(err)) = hook.detach() {
            err == -(ENOENT as i32)
        } else {
            false
        }
    };

    assert!(is_enoent(&mut egress));
    assert!(is_enoent(&mut ingress));
    assert!(is_enoent(&mut custom));

    assert!(clear_clsact(fd).is_ok());
}

#[test]
#[serial]
fn test_tc_query() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut egress = tc_builder.hook(TC_EGRESS);
    assert!(egress.create().is_ok());
    assert!(egress.attach().is_ok());
    assert!(egress.query().is_ok());

    assert!(egress.detach().is_ok());
    assert!(egress.query().is_err());

    assert!(egress.attach().is_ok());
    assert!(egress.query().is_ok());

    assert!(egress.destroy().is_ok());
    assert!(egress.query().is_err());

    assert!(egress.attach().is_ok());
    assert!(egress.query().is_ok());

    assert!(clear_clsact(fd).is_ok());
    assert!(egress.query().is_err());

    let mut ingress = tc_builder.hook(TC_INGRESS);
    assert!(ingress.create().is_ok());
    assert!(ingress.attach().is_ok());
    assert!(ingress.query().is_ok());

    assert!(ingress.detach().is_ok());
    assert!(ingress.query().is_err());

    assert!(ingress.attach().is_ok());
    assert!(ingress.query().is_ok());

    assert!(ingress.destroy().is_ok());
    assert!(ingress.query().is_err());

    assert!(ingress.attach().is_ok());
    assert!(ingress.query().is_ok());

    assert!(clear_clsact(fd).is_ok());
    assert!(ingress.query().is_err());

    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS);
    assert!(ingress.create().is_ok());
    assert!(custom.attach().is_ok());
    assert!(custom.query().is_ok());

    assert!(custom.detach().is_ok());
    assert!(custom.query().is_err());

    assert!(custom.attach().is_ok());
    assert!(custom.query().is_ok());

    assert!(clear_clsact(fd).is_ok());
    assert!(custom.query().is_err());
}

#[test]
#[serial]
fn test_tc_double_create() {
    bump_rlimit_mlock();

    let (_obj, tc_builder, fd) = test_helper_get_tc_builder("handle_tc");
    assert!(clear_clsact(fd).is_ok());

    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut egress = tc_builder.hook(TC_EGRESS);

    assert!(ingress.create().is_ok());
    assert!(egress.create().is_ok());

    assert!(clear_clsact(fd).is_ok());
}
