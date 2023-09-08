use std::os::unix::io::AsFd as _;
use std::os::unix::io::BorrowedFd;

use serial_test::serial;

mod test;
use test::bump_rlimit_mlock;
use test::get_test_object;

use libbpf_rs::ErrorKind;
use libbpf_rs::Result;
use libbpf_rs::TcHook;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_CUSTOM;
use libbpf_rs::TC_EGRESS;
use libbpf_rs::TC_H_CLSACT;
use libbpf_rs::TC_H_MIN_EGRESS;
use libbpf_rs::TC_H_MIN_INGRESS;
use libbpf_rs::TC_INGRESS;
// do all TC tests on the lo network interface
const LO_IFINDEX: i32 = 1;

fn clear_clsact(fd: BorrowedFd) -> Result<()> {
    // Ensure clean clsact tc qdisc
    let mut destroyer = TcHook::new(fd);
    destroyer
        .ifindex(LO_IFINDEX)
        .attach_point(TC_EGRESS | TC_INGRESS);

    let res = destroyer.destroy();
    if let Err(err) = &res {
        if !matches!(err.kind(), ErrorKind::NotFound | ErrorKind::InvalidInput) {
            return res;
        }
    }

    Ok(())
}

#[test]
#[serial]
fn test_sudo_tc_basic_cycle() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_attach_no_qdisc() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_attach_basic() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_attach_repeat() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_attach_custom() {
    bump_rlimit_mlock();
    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_detach_basic() {
    bump_rlimit_mlock();
    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
        if let Err(err) = hook.detach() {
            err.kind() == ErrorKind::NotFound
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
fn test_sudo_tc_query() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
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
fn test_sudo_tc_double_create() {
    bump_rlimit_mlock();

    let obj = get_test_object("tc-unit.bpf.o");
    let fd = obj.prog("handle_tc").unwrap().as_fd();

    let mut tc_builder = TcHookBuilder::new(fd);
    tc_builder
        .ifindex(LO_IFINDEX)
        .replace(true)
        .handle(1)
        .priority(1);
    assert!(clear_clsact(fd).is_ok());

    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut egress = tc_builder.hook(TC_EGRESS);

    assert!(ingress.create().is_ok());
    assert!(egress.create().is_ok());

    assert!(clear_clsact(fd).is_ok());
}
