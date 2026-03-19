//! Process termination functions.

use std::sync::Mutex;

use crate::syscall;

// Global list of atexit handlers
static ATEXIT_HANDLERS: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

pub fn run_atexit_handlers() {
    // 1. Run atexit handlers in reverse order
    // POSIX: if a function registered by atexit registers another, it must also be called.
    loop {
        let handlers = if let Ok(mut lock) = ATEXIT_HANDLERS.lock() {
            if lock.is_empty() {
                break;
            }
            let mut extracted = Vec::new();
            std::mem::swap(&mut *lock, &mut extracted);
            extracted
        } else {
            break;
        };

        for handler in handlers.into_iter().rev() {
            handler();
        }
    }
}

pub fn exit(status: i32) -> ! {
    run_atexit_handlers();

    // 2. Flush stdio buffers:
    // Handled in the ABI layer (frankenlibc-abi/src/stdlib_abi.rs).
    // If this core `exit` is called directly, stdio streams managed by the ABI
    // layer won't be flushed. The ABI layer should call `run_atexit_handlers`
    // and then perform flushing itself.

    // 3. Terminate process
    // Use a raw syscall to avoid recursion through our interposed `exit` ABI.
    syscall::sys_exit_group(status)
}
pub fn atexit(func: extern "C" fn()) -> i32 {
    if let Ok(mut handlers) = ATEXIT_HANDLERS.lock() {
        handlers.push(func);
        0
    } else {
        -1
    }
}
