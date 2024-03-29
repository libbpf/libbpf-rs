Demonstrations of capable, the Linux eBPF/libpf-rs version.

To build this project:
```
$ cd examples/capable
$ cargo build
$ cd ../../target/debug
```
capable traces calls to the kernel cap_capable() function, which does security
capability checks, and prints details for each call. For example:
```
$ ./capable
TIME      UID    PID    COMM             CAP  NAME                 AUDIT
22:11:23  114    2676   snmpd            12   CAP_NET_ADMIN        1
22:11:23  0      6990   run              24   CAP_SYS_RESOURCE     1
22:11:23  0      7003   chmod            3    CAP_FOWNER           1
22:11:23  0      7003   chmod            4    CAP_FSETID           1
22:11:23  0      7005   chmod            4    CAP_FSETID           1
22:11:23  0      7005   chmod            4    CAP_FSETID           1
22:11:23  0      7006   chown            4    CAP_FSETID           1
22:11:23  0      7006   chown            4    CAP_FSETID           1
22:11:23  0      6990   setuidgid        6    CAP_SETGID           1
22:11:23  0      6990   setuidgid        6    CAP_SETGID           1
22:11:23  0      6990   setuidgid        7    CAP_SETUID           1
22:11:24  0      7013   run              24   CAP_SYS_RESOURCE     1
22:11:24  0      7026   chmod            3    CAP_FOWNER           1
22:11:24  0      7026   chmod            4    CAP_FSETID           1
22:11:24  0      7028   chmod            4    CAP_FSETID           1
22:11:24  0      7028   chmod            4    CAP_FSETID           1
22:11:24  0      7029   chown            4    CAP_FSETID           1
22:11:24  0      7029   chown            4    CAP_FSETID           1
22:11:24  0      7013   setuidgid        6    CAP_SETGID           1
22:11:24  0      7013   setuidgid        6    CAP_SETGID           1
22:11:24  0      7013   setuidgid        7    CAP_SETUID           1
22:11:25  0      7036   run              24   CAP_SYS_RESOURCE     1
22:11:25  0      7049   chmod            3    CAP_FOWNER           1
22:11:25  0      7049   chmod            4    CAP_FSETID           1
22:11:25  0      7051   chmod            4    CAP_FSETID           1
22:11:25  0      7051   chmod            4    CAP_FSETID           1
```

Checks where ``AUDIT`` is ``0`` are ignored by default, which can be changed
with ``-v`` but is more verbose.

We can show the ``TID`` and ``INSETID`` columns with ``-x``.
Since only a recent kernel version >= 5.1 reports the ``INSETID`` bit to cap_capable(),
the fallback value "N/A" will be displayed on older kernels.
```
$ ./capable -x
TIME      UID    PID    TID    COMM             CAP  NAME                 AUDIT  INSETID
08:22:36  0      12869  12869  chown            0    CAP_CHOWN            1      0
08:22:36  0      12869  12869  chown            0    CAP_CHOWN            1      0
08:22:36  0      12869  12869  chown            0    CAP_CHOWN            1      0
08:23:02  0      13036  13036  setuidgid        6    CAP_SETGID           1      0
08:23:02  0      13036  13036  setuidgid        6    CAP_SETGID           1      0
08:23:02  0      13036  13036  setuidgid        7    CAP_SETUID           1      1
08:23:13  0      13085  13085  chmod            3    CAP_FOWNER           1      0
08:23:13  0      13085  13085  chmod            4    CAP_FSETID           1      0
08:23:13  0      13085  13085  chmod            3    CAP_FOWNER           1      0
08:23:13  0      13085  13085  chmod            4    CAP_FSETID           1      0
08:23:13  0      13085  13085  chmod            4    CAP_FSETID           1      0
08:24:27  0      13522  13522  ping             13   CAP_NET_RAW          1      0
[...]
```

This can be useful for general debugging, and also security enforcement:
determining a whitelist of capabilities an application needs.

The output above includes various capability checks: ``snmpd`` checking
``CAP_NET_ADMIN``, run checking ``CAP_SYS_RESOURCES``, then some short-lived processes
checking ``CAP_FOWNER``, ``CAP_FSETID``, etc.
<!--
To see what each of these capabilities does, check the capabilities(7) man
page and the kernel source.
It is possible to include a kernel stack trace to the capable events by passing
-K to the command:

# ./capable.py -K
TIME      UID    PID    COMM             CAP  NAME                 AUDIT
15:32:21  1000   10708  fetchmail        7    CAP_SETUID           1
cap_capable+0x1 [kernel]
ns_capable_common+0x7a [kernel]
__sys_setresuid+0xc8 [kernel]
do_syscall_64+0x56 [kernel]
entry_SYSCALL_64_after_hwframe+0x49 [kernel]
15:32:21  1000   30047  procmail         6    CAP_SETGID           1
cap_capable+0x1 [kernel]
ns_capable_common+0x7a [kernel]
may_setgroups+0x2f [kernel]
__x64_sys_setgroups+0x18 [kernel]
do_syscall_64+0x56 [kernel]
entry_SYSCALL_64_after_hwframe+0x49 [kernel]

Similarly, it is possible to include user-space stack with -U (or they can be
used both at the same time to include user and kernel stack).

-->
Some processes can do a lot of security capability checks, generating a lot of
output. In this case, the --unique option is useful to only print once the same
set of capability, pid(1) or cgroup (2) <!-- and kernel/user
stacks (if -K or -U are used). -->
```
# ./capable --unique 1
```
<!--
The --cgroupmap option filters based on a cgroup set. It is meant to be used
with an externally created map.

# ./capable.py --cgroupmap /sys/fs/bpf/test01

For more details, see docs/special_filtering.md
-->

### USAGE:

```
sudo capable -h
examples 0.1.0
Usage instructions

USAGE:
    capable [FLAGS] [OPTIONS]

FLAGS:
        --debug           debug output for libbpf-rs
    -x, --extra           extra fields: Show TID and INSETID columns
    -h, --help            Prints help information
    -V, --version         Prints version information
    -v, --verbose         verbose: include non-audit checks

OPTIONS:
    -p, --pid <pid>               only trace <pid> [default: 0]
        --unique <unique-type>    don't repeat stacks for the same pid<1> or cgroup<2> [default: 0]
```
