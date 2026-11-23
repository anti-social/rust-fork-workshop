use std::ffi::{CStr, CString, c_char, c_int, c_short, c_void};
use std::fs::{File, OpenOptions, create_dir_all};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::process::Command;
use std::time::Duration;
use std::{io, mem, thread};

mod netcfg;
mod proxy;

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    let _ = args.next().expect("Program arg");
    let rootfs_dir = args.next().expect("Rootfs directory arg");
    let netns_pid = args.next();
    
    let mut pipe_to_child = [0; 2];
    unsafe { libc::pipe(pipe_to_child.as_mut_ptr()) };
    let mut pipe_from_child = [0; 2];
    unsafe { libc::pipe(pipe_from_child.as_mut_ptr()) };

    let mut child_arg = ChildArg {
        pipe_to_child,
        pipe_from_child,
        rootfs_dir,
        netns_pid: netns_pid.clone(),
    };
    
    let mut stack = [0; 8192];

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    
    let mut clone_flags = libc::SIGCHLD;
    if netns_pid.is_none() {
        clone_flags |= libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET;
    }
    let child_pid = unsafe {
        libc::clone(
            child,
            stack.as_mut_ptr().add(stack.len()) as *mut _,
            clone_flags,
            &mut child_arg as *mut _ as *mut _,
        )
    };
    if child_pid == -1 {
        eprintln!("Cannot fork child process");
        return Err(io::Error::last_os_error());
    }
    println!("Child pid: {child_pid}");

    if unsafe { libc::close(pipe_to_child[0]) } == -1 {
        eprintln!("Cannot close pipe to child input side");
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::close(pipe_from_child[1]) } < 0 {
        eprintln!("Cannot close pipe from child output side");
        return Err(io::Error::last_os_error());
    }

    if netns_pid.is_some() {
        let mut buf = [0; 1];
        if unsafe { libc::read(pipe_from_child[0], &raw mut buf as *mut _, buf.len()) } == -1 {
            eprintln!("Cannot read from pipe from child");
            return Err(io::Error::last_os_error());
        }
    }
    if unsafe { libc::close(pipe_from_child[0]) } == -1 {
        eprintln!("Cannot close pipe from child input side");
        return Err(io::Error::last_os_error());
    }
    // std::thread::sleep(std::time::Duration::from_millis(1000));

    if netns_pid.is_none() {
        if !Command::new("newuidmap")
            .arg(format!("{child_pid}"))
            .args(&["0", &format!("{uid}"), "1"])
            .args(&["1", "100000", "65535"])
            .status()
            .expect("Set uid map")
            .success()
        {
            return Err(io::Error::new(io::ErrorKind::Uncategorized, "newuidmap failed"))
        }
        Command::new("newgidmap")
            .arg(format!("{child_pid}"))
            .args(&["0", &format!("{gid}"), "1"])
            .args(&["1", "100000", "65535"])
            .status()
            .expect("Set gid map");
    }
    
    // std::fs::write(format!("/proc/{child_pid}/uid_map"), format!("0 {uid} 1")).expect("Write uid_map");
    // required before gid_map
    // std::fs::write(format!("/proc/{child_pid}/setgroups"), "deny").expect("Write setgroups");
    // std::fs::write(format!("/proc/{child_pid}/gid_map"), format!("0 {gid} 1\n")).expect("Write gid_map");

    // File::create(".containers/netns").expect("Netns file");
    // let netns_path = format!("/proc/{pid1}/ns/net");
    // let netns_path = CString::new(netns_path.as_str()).unwrap();
    // unsafe {
    //     if libc::mount(
    //         netns_path.as_ptr(),
    //         c".containers/netns".as_ptr(),
    //         c"bind".as_ptr(),
    //         libc::MS_BIND,
    //         std::ptr::null() as *const _,
    //     ) < 0 {
    //         eprintln!("Cannot mount netns of a container: {}", unsafe { *libc::__errno_location() });
    //     }
    // }

    unsafe { libc::close(pipe_to_child[1]) };

    if netns_pid.is_none() {
        // Heap stack, big enough for tun-rs + netlink, top aligned to 16 bytes.
        let mut net_helper_stack = vec![0u8; 256 * 1024];
        let net_helper_stack_top =
            (unsafe { net_helper_stack.as_mut_ptr().add(net_helper_stack.len()) } as usize & !15) as *mut c_void;

        let mut tun_job = TunJob {
            pid: child_pid,
            res: 0,
        };
        let net_helper_pid = unsafe {
            libc::clone(
                network_helper,
                net_helper_stack_top as *mut _,
                libc::CLONE_VM | libc::CLONE_FILES | libc::SIGCHLD,
                &mut tun_job as *mut _ as *mut _,
            )
        };
        if net_helper_pid < 0 {
            eprintln!("Cannot fork network helper process: {}", unsafe { *libc::__errno_location() });
            std::process::exit(1);
        }
        let mut status = 0;
        unsafe { libc::waitpid(net_helper_pid, &mut status, 0) };
        println!("Network helper exit status: {status}");
        println!("Tun fd: {}", tun_job.res);
        
        let tap = unsafe { File::from_raw_fd(tun_job.res) };
        thread::spawn(move || {
            if let Err(e) = proxy::run(tap) {
                eprintln!("proxy stopped: {e}");
            }
        });
    }

    let mut status1 = 0;
    unsafe { libc::waitpid(child_pid, &mut status1, 0) };
    println!("Child 1 exit status: {status1}");

    Ok(())
}

struct ChildArg {
    pipe_to_child: [c_int; 2],
    pipe_from_child: [c_int; 2],
    rootfs_dir: String,
    netns_pid: Option<String>,
}

extern "C" fn child(arg: *mut std::ffi::c_void) -> std::ffi::c_int {
    let arg = unsafe { &*(arg as *mut ChildArg) };
    unsafe { libc::close(arg.pipe_to_child[1]) };
    unsafe { libc::close(arg.pipe_from_child[0]) };
    
    println!("Hello from child: {}", unsafe { libc::getpid() });
    println!("My user id: {}", unsafe { libc::getuid() });
    println!("My new user id: {}", unsafe { libc::getuid() });

    if let Some(netns_pid) = &arg.netns_pid {
        let user_ns_file = OpenOptions::new().read(true)
            .open(format!("/proc/{}/ns/user", netns_pid))
            .expect("Open child user namespace");
        if unsafe { libc::setns(user_ns_file.as_raw_fd(), 0) } < 0 {
            eprintln!("Cannot set user namespace for child: {}", unsafe { *libc::__errno_location() });
        }
        let net_ns_file = OpenOptions::new().read(true)
            .open(format!("/proc/{}/ns/net", netns_pid))
            .expect("Open child network namespace");
        if unsafe { libc::setns(net_ns_file.as_raw_fd(), 0) } < 0 {
            eprintln!("Cannot set network namespace for child: {}", unsafe { *libc::__errno_location() });
        }

        if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) } < 0 {
            eprintln!("Cannot unshare child: {}", unsafe { *libc::__errno_location() });
        }

        if unsafe { libc::close(arg.pipe_from_child[1]) } < 0 {
            eprintln!("Cannot close pipe from child: {}", io::Error::last_os_error());
        }
        println!("Pipe from child output side is closed");

        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("Cannot fork into child pid namespace: {}", io::Error::last_os_error());
                return 1;
            }
            0 => {}
            pid => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
                // unsafe { libc::_exit(0) };
            }
        }
    } else {
        if unsafe { libc::close(arg.pipe_from_child[1]) } < 0 {
            eprintln!("Cannot close pipe from child: {}", io::Error::last_os_error());
        }
    }

    let mut buf = [0; 1];
    unsafe { libc::read(arg.pipe_to_child[0], buf.as_mut_ptr() as *mut _, buf.len()) };
    println!("Uid and gid maps are set. Continue setting up child");
    unsafe { libc::close(arg.pipe_to_child[0]) };
    
    unsafe {
        if libc::mount(
            c"tmpfs".as_ptr(),
            c".containers/current".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount tmpfs to new root");
        }
    }

    create_dir_all(".containers/current/root").expect("Create root dir");
    create_dir_all(".containers/current/old_root").expect("Create old_root dir");

    let rootfs_dir = format!(".containers/{}", arg.rootfs_dir);
    let rootfs_dir = CString::new(rootfs_dir.as_str()).unwrap();
    unsafe {
        if libc::mount(
            rootfs_dir.as_ptr(),
            c".containers/current/root".as_ptr(),
            c"bind".as_ptr(),
            libc::MS_BIND,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount rootfs to new root");
        }
    }

    std::fs::write( 
        ".containers/current/root/etc/resolv.conf",
        "nameserver 10.0.0.1\nsearch bagspace.vpn local example.com uaprom dev stg.evo evo\n",
    ).expect("write resolv.conf");
    // let _ = File::create(".containers/current/root/etc/resolv.conf");
    // unsafe {
    //     if libc::mount(
    //         c"/run/systemd/resolve/stub-resolv.conf".as_ptr(),
    //         c".containers/current/root/etc/resolv.conf".as_ptr(),
    //         c"bind".as_ptr(),
    //         libc::MS_BIND,
    //         std::ptr::null() as *const _,
    //     ) < 0 {
    //         eprintln!("Cannot mount resolv.conf to new root: {}", unsafe { *libc::__errno_location() });
    //     }
    // }

    unsafe {
        if libc::mount(
            c"proc".as_ptr(),
            c".containers/current/root/proc".as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount procfs to new root");
       }
    }

    unsafe {
        if libc::mount(
            c"sysfs".as_ptr(),
            c".containers/current/root/sys".as_ptr(),
            c"sysfs".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount sysfs to new root");
        }
    }

    unsafe {
        if libc::mount(
            c"/dev".as_ptr(),
            c".containers/current/root/dev".as_ptr(),
            c"bind".as_ptr(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount dev to new root: {}", unsafe { *libc::__errno_location() });
        }
    }

    unsafe {
        if libc::mount(
            c"tmpfs".as_ptr(),
            c".containers/current/root/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount tmpfs into new root");
        }
    }

    unsafe {
        if libc::chdir(c".containers/current/root".as_ptr()) < 0 {
            eprintln!("Cannot chdir into new root");
        }
    }
    
    unsafe {
        if libc::syscall(
            libc::SYS_pivot_root,
            c".".as_ptr(),
            c".".as_ptr(),
        ) < 0 {
            eprintln!("Cannot chroot into new root");
        }
    }

    unsafe {
        if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) < 0 {
            eprintln!("Cannot umount old root");
        }
    }
    
    let argv = [c"sh".as_ptr(), std::ptr::null::<i8>()];
    let envp = [c"PATH=/bin:/usr/bin:/sbin:/usr/sbin".as_ptr(), std::ptr::null::<i8>()];
    unsafe {
        libc::execvpe(c"/bin/sh".as_ptr(), argv.as_ptr(), envp.as_ptr())
    };
    
    return 0;
} 

struct TunJob {
    pid: libc::pid_t,
    res: i32,
}

extern "C" fn network_helper(arg: *mut c_void) -> c_int {
    let TunJob { pid, res } = unsafe { &mut *{ arg as *mut TunJob } };
    
    let ns_user_file = OpenOptions::new().read(true)
        .open(format!("/proc/{}/ns/user", pid))
        .expect("Child net user");
    if unsafe { libc::setns(ns_user_file.as_raw_fd(), 0) } < 0 {
        eprintln!("Error calling setns user: {}", io::Error::last_os_error());
        std::process::exit(2);
    }

    let ns_net_file = OpenOptions::new().read(true)
        .open(format!("/proc/{}/ns/net", pid))
        .expect("Child net ns");
    
    if unsafe { libc::setns(ns_net_file.as_raw_fd(), 0) } < 0 {
        eprintln!("Error calling setns: {}", io::Error::last_os_error());
        std::process::exit(2);
    }

    // let (tun_file, tun_name) = create_tap("tap0").expect("Create tun interface");
    let tun_dev = create_tap_ex("tap0").expect("Create tun device");
    std::fs::write("/proc/sys/net/ipv6/conf/tap0/disable_ipv6", b"1").expect("Disable tun ipv6");

    println!("Net helper: tun device created");

    *res = tun_dev.into_raw_fd();
    0    
}

fn create_tap(name: &str) -> io::Result<(File, String)> {
    let dev_tun_file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;

    let mut create_tap_req: libc::ifreq = unsafe { mem::zeroed() };
    for (src, dst) in name.as_bytes().iter().copied().zip(create_tap_req.ifr_name.iter_mut()) {
        *dst = src as _;
    }
    create_tap_req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as _;

    if unsafe {libc::ioctl(dev_tun_file.as_raw_fd(), libc::TUNSETIFF, &mut create_tap_req) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let name = unsafe { CStr::from_ptr(create_tap_req.ifr_name.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    Ok((dev_tun_file, name))
}

fn create_tap_ex(name: &str) -> io::Result<tun_rs::SyncDevice> {
    let mut tun = tun_rs::DeviceBuilder::new()
        .name(name)
        .layer(tun_rs::Layer::L2)
        .ipv4(Ipv4Addr::new(10, 0, 0, 2), 24, None) // gateway 10.0.0.1 is answered by the proxy
        .enable(true)
        .build_sync()?;

    let mut nl = netcfg::NetCfg::new()?;
    let lo_idx = netcfg::if_index("lo")?;
    nl.link_up(lo_idx)?;
    let tun_idx = netcfg::if_index(&name)?;
    nl.add_default_route_v4(tun_idx, "10.0.0.1".parse().unwrap())?;

    // Send a packet
    // Example IP packet (Replace with real IP message)
    // let packet = b"[IP Packet: 10.0.0.1 -> 10.0.0.2] Hello, TUN!";
    // tun.send(packet)?;
    // println!("Sent {} bytes IP packet", packet.len());

    // Receive a packet

    Ok(tun)
}
