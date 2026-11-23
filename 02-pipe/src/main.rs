use std::ffi::c_int;
use std::io;

use snafu::ResultExt;

fn mk_pipe() -> io::Result<[c_int; 2]> {
    let mut pipe = [0; 2];
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(pipe)
}

fn close(fd: c_int) -> io::Result<()> {
    if unsafe { libc::close(fd) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn dup2(src: c_int, dst: c_int) -> io::Result<()> {
    if unsafe { libc::dup2(src, dst) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn waitpid(pid: libc::pid_t, status: *mut c_int, options: c_int) -> io::Result<()> {
    if unsafe { libc::waitpid(pid, status, options) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fork() -> io::Result<libc::pid_t> {
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

fn main() -> Result<(), snafu::Whatever> {
    let pipe = mk_pipe().whatever_context("Error creating pipe")?;
    
    let pid1 = fork().whatever_context("Cannot fork child1")?;
    if pid1 == 0 {
        close(pipe[0]).whatever_context("[child1] Cannot close pipe[0]")?;
        dup2(pipe[1], libc::STDOUT_FILENO).whatever_context("[child1] Cannot dup pipe[1]")?;
        close(pipe[1]).whatever_context("[child1] Cannot close pipe[1]")?;
        unsafe {
            libc::execlp(c"cat".as_ptr(), c"cat".as_ptr(), c"src/main.rs".as_ptr(), std::ptr::null::<*const i8>())
        };
    }

    let pid2 = fork().whatever_context("Cannot fork child2")?;
    if pid2 == 0 {
        close(pipe[1]).whatever_context("[child2] Cannot close pipe[1]")?;
        dup2(pipe[0], libc::STDIN_FILENO).whatever_context("[child2] Cannot dup pipe[0]")?;
        close(pipe[0]).whatever_context("[child2] Cannot close pipe[0]")?;
        unsafe {
            libc::execlp(c"wc".as_ptr(), c"wc".as_ptr(), c"-l".as_ptr(), std::ptr::null::<*const i8>())
        };
    }

    close(pipe[0]).whatever_context("Cannot close pipe[0]")?;
    close(pipe[1]).whatever_context("Cannot close pipe[1]")?;

    let mut status1 = 0;
    let mut status2 = 0;
    waitpid(pid1, &mut status1, 0).whatever_context("Error waiting child1")?;
    waitpid(pid2, &mut status2, 0).whatever_context("Error waiting child2")?;
    println!("Children exit codes: {status1}, {status2}");

    Ok(())
}
