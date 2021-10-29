//! This test is in its own file because the underlying libbpf_set_print function used by
//! set_print() and ObjectBuilder::debug() sets global state. The default is to run multiple tests
//! in different threads, so this test will always race with the others unless its isolated to a
//! different process.
//!
//! For the same reason, all tests here must run serially.

use libbpf_rs::{get_print, set_print, ObjectBuilder, PrintCallback, PrintLevel};
use serial_test::serial;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
#[serial]
fn test_set_print() {
    static CORRECT_LEVEL: AtomicBool = AtomicBool::new(false);
    static CORRECT_MESSAGE: AtomicBool = AtomicBool::new(false);

    fn callback(level: PrintLevel, msg: String) {
        if level == PrintLevel::Warn {
            CORRECT_LEVEL.store(true, Ordering::Relaxed);
        }

        if msg.starts_with("libbpf: ") {
            CORRECT_MESSAGE.store(true, Ordering::Relaxed);
        }
    }

    set_print(Some((PrintLevel::Debug, callback)));
    // expect_err requires that OpenObject implement Debug, which it does not.
    let obj = ObjectBuilder::default().open_file("/dev/null");
    assert!(obj.is_err(), "Successfully loaded /dev/null?");

    let correct_level = CORRECT_LEVEL.load(Ordering::Relaxed);
    let correct_message = CORRECT_MESSAGE.load(Ordering::Relaxed);
    assert!(correct_level, "Did not capture a warning");
    assert!(correct_message, "Did not capture the correct message");
}

#[test]
#[serial]
fn test_set_restore_print() {
    fn callback1(_: PrintLevel, _: String) {
        println!("one");
    }
    fn callback2(_: PrintLevel, _: String) {
        println!("two");
    }

    set_print(Some((PrintLevel::Warn, callback1)));
    let prev = get_print();
    assert_eq!(prev, Some((PrintLevel::Warn, callback1 as PrintCallback)));

    set_print(Some((PrintLevel::Debug, callback2)));
    let prev = get_print();
    assert_eq!(prev, Some((PrintLevel::Debug, callback2 as PrintCallback)));
}

#[test]
#[serial]
fn test_set_and_save_print() {
    fn callback1(_: PrintLevel, _: String) {
        println!("one");
    }
    fn callback2(_: PrintLevel, _: String) {
        println!("two");
    }

    set_print(Some((PrintLevel::Warn, callback1)));
    let prev = set_print(Some((PrintLevel::Debug, callback2)));
    assert_eq!(prev, Some((PrintLevel::Warn, callback1 as PrintCallback)));

    let prev = set_print(None);
    assert_eq!(prev, Some((PrintLevel::Debug, callback2 as PrintCallback)));
}
