use std::ffi::CString;
use std::ffi::c_int;
use std::fs::create_dir_all;
use std::io;
use std::ptr;

const STACK_SIZE: usize = 64 * 1024;

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    let _ = args.next().expect("Program arg");
    let rootfs_dir = args.next().expect("Rootfs directory arg");

    let mut pipe_to_child = [0; 2];
    unsafe { libc::pipe(pipe_to_child.as_mut_ptr()) };

    let mut child_arg = ChildArg {
        pipe_to_child,
        rootfs_dir,
    };

    let stack = unsafe {
        libc::mmap(
            ptr::null_mut(),
            STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0
        )
    };
    if stack as isize == -1 {
        eprintln!("Cannot allocate stack");
        return Err(io::Error::last_os_error());
    }
    let stack_top = unsafe { stack.add(STACK_SIZE) };
    println!("Stack top address: 0x{:x}", stack_top as usize);

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let child_pid = unsafe {
        libc::clone(
            run_child,
            stack_top,
            libc::SIGCHLD | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS,
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

    std::fs::write(format!("/proc/{child_pid}/uid_map"), format!("0 {uid} 1")).expect("Write uid_map");
    // required before gid_map
    std::fs::write(format!("/proc/{child_pid}/setgroups"), "deny").expect("Write setgroups");
    std::fs::write(format!("/proc/{child_pid}/gid_map"), format!("0 {gid} 1\n")).expect("Write gid_map");

    unsafe { libc::close(pipe_to_child[1]) };

    let mut status1 = 0;
    unsafe { libc::waitpid(child_pid, &mut status1, 0) };
    println!("Child 1 exit status: {status1}");

    Ok(())
}

struct ChildArg {
    pipe_to_child: [c_int; 2],
    rootfs_dir: String,
}

extern "C" fn run_child(arg: *mut std::ffi::c_void) -> std::ffi::c_int {
    let arg = unsafe { &*(arg as *mut ChildArg) };
    unsafe { libc::close(arg.pipe_to_child[1]) };
    
    let mut buf = [0; 1];
    unsafe { libc::read(arg.pipe_to_child[0], buf.as_mut_ptr() as *mut _, buf.len()) };
    unsafe { libc::close(arg.pipe_to_child[0]) };

    println!("Hello from child: {}", unsafe { libc::getpid() });
    println!("My user id: {}", unsafe { libc::getuid() });
    println!("My group id: {}", unsafe { libc::getgid() });

    if init_container_root(&arg.rootfs_dir).is_err() {
        return 1;
    }
    
    let argv = [c"env".as_ptr(), c"sh".as_ptr(), std::ptr::null()];
    let envp = [c"PATH=/sbin:/bin:/usr/sbin:/usr/bin".as_ptr(), std::ptr::null()];
    if unsafe {
        libc::execvpe(c"/usr/bin/env".as_ptr(), argv.as_ptr(),envp.as_ptr())
    } < 0 {
        eprintln!("Error executing a program: {}", io::Error::last_os_error());
        return 1;
    }

    return 0;
} 

fn init_container_root(image_name: &str) -> io::Result<()> {
    unsafe {
        if libc::mount(
            c"tmpfs".as_ptr(),
            c"../.containers/current".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount tmpfs to new root");
            return Err(io::Error::last_os_error());
        }
    }

    create_dir_all("../.containers/current/root")?;
    let rootfs_dir = format!("../.containers/{}", image_name);
    let rootfs_dir = CString::new(rootfs_dir.as_str()).unwrap();
    unsafe {
        if libc::mount(
            rootfs_dir.as_ptr(),
            c"../.containers/current/root".as_ptr(),
            c"bind".as_ptr(),
            libc::MS_BIND,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount rootfs to new root");
            return Err(io::Error::last_os_error());
        }
    }

    create_dir_all("../.containers/current/root/proc")?;
    unsafe {
        if libc::mount(
            c"proc".as_ptr(),
            c"../.containers/current/root/proc".as_ptr(),
            c"proc".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount procfs to new root");
            return Err(io::Error::last_os_error());
        }
    }

    create_dir_all("../.containers/current/root/dev")?;
    unsafe {
        if libc::mount(
            c"/dev".as_ptr(),
            c"../.containers/current/root/dev".as_ptr(),
            c"bind".as_ptr(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount dev to new root: {}", io::Error::last_os_error());
            return Err(io::Error::last_os_error());
        }
    }

    unsafe {
        if libc::mount(
            c"tmpfs".as_ptr(),
            c"../.containers/current/root/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null() as *const _,
        ) < 0 {
            eprintln!("Cannot mount tmpfs to new root tmp dir");
            return Err(io::Error::last_os_error());
        }
    }
    
    unsafe {
        if libc::chdir(c"../.containers/current/root".as_ptr()) < 0 {
            eprintln!("Cannot chdir into new root");
            return Err(io::Error::last_os_error());
        }
    }

    unsafe {
        if libc::syscall(
            libc::SYS_pivot_root,
            c".".as_ptr(),
            c".".as_ptr(),
        ) < 0 {
            eprintln!("Cannot chroot into new root");
            return Err(io::Error::last_os_error());
        }
    }

    unsafe {
        if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) < 0 {
            eprintln!("Cannot umount old root");
            return Err(io::Error::last_os_error());
        }
    }
    
    Ok(())
}
