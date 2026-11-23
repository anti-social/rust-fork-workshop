fn main() {
    let pid = unsafe { libc::fork() };
    match pid {
        ..0 => {
            eprintln!("Cannot fork child process");
        }
        0 => {
            println!("Hello from the child!");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            let parent_pid = unsafe { libc::getppid() };
            println!("Parent pid: {parent_pid}");
        }
        pid => {
            println!("Hello from the parent!");
            let mut status = 0; 
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    }
}
