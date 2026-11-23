use std::ffi::{c_int, c_void};
use std::ptr;
use std::time::Instant;

fn main() {
    let mut bigdata = vec![0; 1024 * 1024 * 1024];
    for i in 0..1024 * 1024 {
        bigdata[i * 1024] = i;
    }
    
    let stack = [0; 2 * 4096];
    let stack_top = unsafe { stack.as_ptr().add(stack.len()) };

    let start_at = Instant::now();
    
    match unsafe {
        libc::clone(exec_cmd, stack_top as *mut _, libc::CLONE_VM | libc::SIGCHLD, ptr::null_mut())
    } {
        -1 => {
            eprintln!("Cannot fork child process");
            unsafe { libc::_exit(1) };
        }
        pid => {
            println!("Hello from the parent!");
            println!("Fork duration: {:?}", start_at.elapsed());
            std::hint::black_box(bigdata);
            let mut status = 0; 
            if unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
        }
    }

    
}

extern "C" fn exec_cmd(_arg: *mut c_void) -> c_int {
    // println!("Hello from child");
    let cmd = c"/usr/bin/env".as_ptr();
    let args = &[c"env".as_ptr(), c"ls".as_ptr(), ptr::null()];
    let args_ptr = args.as_ptr();
    if unsafe { libc::execv(cmd, args_ptr) } == -1 {
        // eprintln!("Cannot exec command");
        return 2;
    }
    0
}
