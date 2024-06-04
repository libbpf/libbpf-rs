use std::os::fd::AsFd;

use scopeguard::defer;

use test_tag::tag;

mod test;
use test::bump_rlimit_mlock;
use test::get_test_object;

use libbpf_rs::Xdp;
use libbpf_rs::XdpFlags;

const LO_IFINDEX: i32 = 1;

#[tag(root)]
#[test]
fn test_xdp() {
    bump_rlimit_mlock();

    let obj = get_test_object("xdp.bpf.o");
    let fd = obj.prog("xdp_filter").unwrap().as_fd();

    let obj1 = get_test_object("xdp.bpf.o");
    let fd1 = obj1.prog("xdp_filter").unwrap().as_fd();

    let xdp_prog = Xdp::new(fd);
    let xdp_prog1 = Xdp::new(fd1);

    defer! {
        xdp_prog.detach(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST).unwrap();
    }

    assert!(xdp_prog
        .attach(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .is_ok());

    // Second attach should fail as a prog is already loaded
    assert!(xdp_prog
        .attach(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .is_err());

    assert!(xdp_prog
        .query_id(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .is_ok());

    assert!(xdp_prog
        .query(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .is_ok());

    let old_prog_id = xdp_prog
        .query_id(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .unwrap();
    assert!(xdp_prog1.replace(LO_IFINDEX, fd).is_ok());
    let new_prog_id = xdp_prog1
        .query_id(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .unwrap();
    // If xdp prog is replaced, prog id should change.
    assert!(old_prog_id != new_prog_id);

    assert!(xdp_prog
        .detach(LO_IFINDEX, XdpFlags::UPDATE_IF_NOEXIST)
        .is_ok());
}
