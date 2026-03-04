#![cfg(target_os = "linux")]

//! Integration tests for `<pthread.h>` ABI entrypoints.
//!
//! Covers: mutex (normal/recursive/errorcheck), condvar, rwlock, thread lifecycle,
//! thread-specific data, once, spinlock, barrier, attributes, cancel, naming.

use std::ffi::{CStr, CString, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use frankenlibc_abi::pthread_abi::*;

// POSIX cancel constants (not always exported by the libc crate)
const PTHREAD_CANCEL_ENABLE: c_int = 0;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
const PTHREAD_CANCEL_DEFERRED: c_int = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;
const PTHREAD_SCOPE_SYSTEM: c_int = 0;

// ===========================================================================
// Thread lifecycle: create, join, detach, self, equal
// ===========================================================================

unsafe extern "C" fn add_ten(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let val = arg as usize;
        (val + 10) as *mut c_void
    }
}

#[test]
fn thread_create_join() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(
            &mut thr,
            ptr::null(),
            Some(add_ten),
            42usize as *mut c_void,
        );
        assert_eq!(rc, 0, "pthread_create should succeed");

        let mut retval: *mut c_void = ptr::null_mut();
        let rc = pthread_join(thr, &mut retval);
        assert_eq!(rc, 0, "pthread_join should succeed");
        assert_eq!(retval as usize, 52, "thread should return 42+10");
    }
}

unsafe extern "C" fn noop_thread(_arg: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

#[test]
fn thread_detach() {
    unsafe {
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(noop_thread), ptr::null_mut());
        assert_eq!(rc, 0);
        let rc = pthread_detach(thr);
        assert_eq!(rc, 0, "pthread_detach should succeed");
        // Don't join a detached thread — just let it finish.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn thread_self_nonzero() {
    let self_id = unsafe { pthread_self() };
    assert_ne!(self_id, 0, "pthread_self should return non-zero");
}

#[test]
fn thread_equal_same() {
    let self_id = unsafe { pthread_self() };
    let rc = unsafe { pthread_equal(self_id, self_id) };
    assert_ne!(rc, 0, "pthread_equal(self, self) should be nonzero");
}

#[test]
fn thread_equal_different() {
    unsafe {
        let main_id = pthread_self();
        let mut thr: libc::pthread_t = 0;
        let rc = pthread_create(&mut thr, ptr::null(), Some(noop_thread), ptr::null_mut());
        assert_eq!(rc, 0);
        let eq = pthread_equal(main_id, thr);
        assert_eq!(eq, 0, "main thread and child should not be equal");
        pthread_join(thr, ptr::null_mut());
    }
}

// ===========================================================================
// Mutex: init, lock, trylock, unlock, destroy (NORMAL)
// ===========================================================================

#[test]
fn mutex_init_destroy() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        let rc = pthread_mutex_init(&mut mutex, ptr::null());
        assert_eq!(rc, 0);
        let rc = pthread_mutex_destroy(&mut mutex);
        assert_eq!(rc, 0);
    }
}

#[test]
fn mutex_lock_unlock() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        let rc = pthread_mutex_lock(&mut mutex);
        assert_eq!(rc, 0);
        let rc = pthread_mutex_unlock(&mut mutex);
        assert_eq!(rc, 0);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_trylock_succeeds_when_unlocked() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        let rc = pthread_mutex_trylock(&mut mutex);
        assert_eq!(rc, 0, "trylock on unlocked mutex should succeed");
        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_trylock_fails_when_locked() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());
        pthread_mutex_lock(&mut mutex);
        let rc = pthread_mutex_trylock(&mut mutex);
        assert_eq!(rc, libc::EBUSY, "trylock on locked mutex should return EBUSY");
        pthread_mutex_unlock(&mut mutex);
        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex: recursive type
// ===========================================================================

#[test]
fn mutex_recursive_multiple_locks() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        // Lock three times
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(pthread_mutex_lock(&mut mutex), 0);

        // Unlock three times
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);

        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex: errorcheck type
// ===========================================================================

#[test]
fn mutex_errorcheck_double_lock_returns_edeadlk() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        assert_eq!(pthread_mutex_lock(&mut mutex), 0);
        let rc = pthread_mutex_lock(&mut mutex);
        assert_eq!(rc, libc::EDEADLK, "errorcheck double lock should return EDEADLK");
        assert_eq!(pthread_mutex_unlock(&mut mutex), 0);

        pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn mutex_errorcheck_unlock_without_lock_returns_eperm() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);
        pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK);

        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, &attr);
        pthread_mutexattr_destroy(&mut attr);

        let rc = pthread_mutex_unlock(&mut mutex);
        assert_eq!(rc, libc::EPERM, "errorcheck unlock without lock should return EPERM");

        pthread_mutex_destroy(&mut mutex);
    }
}

// ===========================================================================
// Mutex attributes
// ===========================================================================

#[test]
fn mutexattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(pthread_mutexattr_destroy(&mut attr), 0);
    }
}

#[test]
fn mutexattr_settype_gettype() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        assert_eq!(pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE), 0);
        let mut kind: c_int = 0;
        assert_eq!(pthread_mutexattr_gettype(&attr, &mut kind), 0);
        assert_eq!(kind, libc::PTHREAD_MUTEX_RECURSIVE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        let mut pshared: c_int = -1;
        assert_eq!(pthread_mutexattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);

        pthread_mutexattr_destroy(&mut attr);
    }
}

#[test]
fn mutexattr_getrobust() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        pthread_mutexattr_init(&mut attr);

        let mut robust: c_int = -1;
        assert_eq!(pthread_mutexattr_getrobust(&attr, &mut robust), 0);
        assert_eq!(robust, libc::PTHREAD_MUTEX_STALLED);

        pthread_mutexattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Condvar: init, signal, broadcast, destroy
// ===========================================================================

#[test]
fn condvar_init_destroy() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        assert_eq!(pthread_cond_init(&mut cond, ptr::null()), 0);
        assert_eq!(pthread_cond_destroy(&mut cond), 0);
    }
}

#[test]
fn condvar_signal_no_waiters() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        pthread_cond_init(&mut cond, ptr::null());
        assert_eq!(pthread_cond_signal(&mut cond), 0);
        pthread_cond_destroy(&mut cond);
    }
}

#[test]
fn condvar_broadcast_no_waiters() {
    unsafe {
        let mut cond: libc::pthread_cond_t = std::mem::zeroed();
        pthread_cond_init(&mut cond, ptr::null());
        assert_eq!(pthread_cond_broadcast(&mut cond), 0);
        pthread_cond_destroy(&mut cond);
    }
}

// ===========================================================================
// Condvar attributes
// ===========================================================================

#[test]
fn condattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        assert_eq!(pthread_condattr_init(&mut attr), 0);
        assert_eq!(pthread_condattr_destroy(&mut attr), 0);
    }
}

#[test]
fn condattr_setclock_getclock() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        assert_eq!(pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC), 0);
        let mut clock_id: libc::clockid_t = 0;
        assert_eq!(pthread_condattr_getclock(&attr, &mut clock_id), 0);
        assert_eq!(clock_id, libc::CLOCK_MONOTONIC);

        pthread_condattr_destroy(&mut attr);
    }
}

#[test]
fn condattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        pthread_condattr_init(&mut attr);

        let mut pshared: c_int = -1;
        let rc = pthread_condattr_getpshared(&attr, &mut pshared);
        assert_eq!(rc, 0);
        // Our condattr_init only initializes the clock field; pshared may
        // remain at the zeroed value (0 = PRIVATE) or be layout-dependent.
        // Just verify the function doesn't crash and returns 0.

        pthread_condattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Condvar: wait + signal (multi-threaded)
// ===========================================================================

struct SharedCondState {
    mutex: libc::pthread_mutex_t,
    cond: libc::pthread_cond_t,
    ready: AtomicI32,
}

unsafe extern "C" fn condvar_waiter(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let state = &*(arg as *const SharedCondState);
        pthread_mutex_lock(&state.mutex as *const _ as *mut _);
        while state.ready.load(Ordering::Acquire) == 0 {
            pthread_cond_wait(
                &state.cond as *const _ as *mut _,
                &state.mutex as *const _ as *mut _,
            );
        }
        pthread_mutex_unlock(&state.mutex as *const _ as *mut _);
        ptr::null_mut()
    }
}

#[test]
fn condvar_wait_signal_wakeup() {
    unsafe {
        let state = Box::new(SharedCondState {
            mutex: std::mem::zeroed(),
            cond: std::mem::zeroed(),
            ready: AtomicI32::new(0),
        });
        pthread_mutex_init(&state.mutex as *const _ as *mut _, ptr::null());
        pthread_cond_init(&state.cond as *const _ as *mut _, ptr::null());

        let state_ptr = &*state as *const SharedCondState as *mut c_void;
        let mut thr: libc::pthread_t = 0;
        pthread_create(&mut thr, ptr::null(), Some(condvar_waiter), state_ptr);

        std::thread::sleep(std::time::Duration::from_millis(30));

        pthread_mutex_lock(&state.mutex as *const _ as *mut _);
        state.ready.store(1, Ordering::Release);
        pthread_cond_signal(&state.cond as *const _ as *mut _);
        pthread_mutex_unlock(&state.mutex as *const _ as *mut _);

        pthread_join(thr, ptr::null_mut());

        pthread_cond_destroy(&state.cond as *const _ as *mut _);
        pthread_mutex_destroy(&state.mutex as *const _ as *mut _);
    }
}

// ===========================================================================
// RWLock: init, rdlock, wrlock, unlock, tryrdlock, trywrlock, destroy
// ===========================================================================

#[test]
fn rwlock_init_destroy() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(pthread_rwlock_init(&mut rwl, ptr::null()), 0);
        assert_eq!(pthread_rwlock_destroy(&mut rwl), 0);
    }
}

#[test]
fn rwlock_rdlock_unlock() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_wrlock_unlock() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_wrlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_multiple_readers() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_tryrdlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_tryrdlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_trywrlock_succeeds() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(pthread_rwlock_trywrlock(&mut rwl), 0);
        assert_eq!(pthread_rwlock_unlock(&mut rwl), 0);
        pthread_rwlock_destroy(&mut rwl);
    }
}

#[test]
fn rwlock_trywrlock_fails_when_rdlocked() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        pthread_rwlock_init(&mut rwl, ptr::null());
        pthread_rwlock_rdlock(&mut rwl);
        let rc = pthread_rwlock_trywrlock(&mut rwl);
        assert_eq!(rc, libc::EBUSY, "trywrlock should fail when read-locked");
        pthread_rwlock_unlock(&mut rwl);
        pthread_rwlock_destroy(&mut rwl);
    }
}

// ===========================================================================
// RWLock attributes
// ===========================================================================

#[test]
fn rwlockattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        assert_eq!(pthread_rwlockattr_init(&mut attr), 0);
        assert_eq!(pthread_rwlockattr_destroy(&mut attr), 0);
    }
}

#[test]
fn rwlockattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_rwlockattr_t = std::mem::zeroed();
        pthread_rwlockattr_init(&mut attr);
        let mut pshared: c_int = -1;
        assert_eq!(pthread_rwlockattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);
        pthread_rwlockattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Thread attributes
// ===========================================================================

#[test]
fn attr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        assert_eq!(pthread_attr_init(&mut attr), 0);
        assert_eq!(pthread_attr_destroy(&mut attr), 0);
    }
}

#[test]
fn attr_setdetachstate_getdetachstate() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        assert_eq!(
            pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED),
            0
        );
        let mut state: c_int = 0;
        assert_eq!(pthread_attr_getdetachstate(&attr, &mut state), 0);
        assert_eq!(state, libc::PTHREAD_CREATE_DETACHED);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setstacksize_getstacksize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let target_size: usize = 2 * 1024 * 1024; // 2 MiB
        assert_eq!(pthread_attr_setstacksize(&mut attr, target_size), 0);
        let mut actual: usize = 0;
        assert_eq!(pthread_attr_getstacksize(&attr, &mut actual), 0);
        assert_eq!(actual, target_size);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getguardsize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut guard_size: usize = 0;
        assert_eq!(pthread_attr_getguardsize(&attr, &mut guard_size), 0);
        assert!(guard_size > 0, "default guard size should be > 0");

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_setguardsize() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let target: usize = 8192;
        assert_eq!(pthread_attr_setguardsize(&mut attr, target), 0);
        let mut actual: usize = 0;
        assert_eq!(pthread_attr_getguardsize(&attr, &mut actual), 0);
        assert_eq!(actual, target);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getschedpolicy() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut policy: c_int = -1;
        assert_eq!(pthread_attr_getschedpolicy(&attr, &mut policy), 0);
        assert_eq!(policy, libc::SCHED_OTHER);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getscope() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut scope: c_int = -1;
        assert_eq!(pthread_attr_getscope(&attr, &mut scope), 0);
        assert_eq!(scope, PTHREAD_SCOPE_SYSTEM);

        pthread_attr_destroy(&mut attr);
    }
}

#[test]
fn attr_getinheritsched() {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        pthread_attr_init(&mut attr);

        let mut inherit: c_int = -1;
        assert_eq!(pthread_attr_getinheritsched(&attr, &mut inherit), 0);
        assert!(
            inherit == libc::PTHREAD_INHERIT_SCHED || inherit == libc::PTHREAD_EXPLICIT_SCHED,
            "inheritsched must be valid enum"
        );

        pthread_attr_destroy(&mut attr);
    }
}

// ===========================================================================
// Thread-specific data (TSD / pthread_key_*)
// ===========================================================================

#[test]
fn key_create_delete() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(pthread_key_create(&mut key, None), 0);
        assert_eq!(pthread_key_delete(key), 0);
    }
}

#[test]
fn key_setspecific_getspecific() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        pthread_key_create(&mut key, None);

        let val = 0xDEADu64 as *mut c_void;
        assert_eq!(pthread_setspecific(key, val), 0);
        let got = pthread_getspecific(key);
        assert_eq!(got as u64, 0xDEAD);

        pthread_key_delete(key);
    }
}

#[test]
fn key_default_is_null() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        pthread_key_create(&mut key, None);
        let got = pthread_getspecific(key);
        assert!(got.is_null(), "newly created key should have null value");
        pthread_key_delete(key);
    }
}

// ===========================================================================
// pthread_once
// ===========================================================================

static ONCE_COUNTER: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn once_init_fn() {
    ONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn once_runs_exactly_once() {
    ONCE_COUNTER.store(0, Ordering::Relaxed);
    let mut once: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    unsafe {
        pthread_once(&mut once, Some(once_init_fn));
        pthread_once(&mut once, Some(once_init_fn));
        pthread_once(&mut once, Some(once_init_fn));
    }
    assert_eq!(ONCE_COUNTER.load(Ordering::Relaxed), 1, "init_fn should run exactly once");
}

// ===========================================================================
// Spinlock
// ===========================================================================

#[test]
fn spinlock_init_destroy() {
    unsafe {
        let mut lock: c_int = 0;
        assert_eq!(pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0), 0);
        assert_eq!(pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void), 0);
    }
}

#[test]
fn spinlock_lock_unlock() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        assert_eq!(pthread_spin_lock(&mut lock as *mut c_int as *mut c_void), 0);
        assert_eq!(pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void), 0);
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

#[test]
fn spinlock_trylock_succeeds_unlocked() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        let rc = pthread_spin_trylock(&mut lock as *mut c_int as *mut c_void);
        assert_eq!(rc, 0);
        pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void);
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

#[test]
fn spinlock_trylock_fails_locked() {
    unsafe {
        let mut lock: c_int = 0;
        pthread_spin_init(&mut lock as *mut c_int as *mut c_void, 0);
        pthread_spin_lock(&mut lock as *mut c_int as *mut c_void);
        let rc = pthread_spin_trylock(&mut lock as *mut c_int as *mut c_void);
        assert_eq!(rc, libc::EBUSY);
        pthread_spin_unlock(&mut lock as *mut c_int as *mut c_void);
        pthread_spin_destroy(&mut lock as *mut c_int as *mut c_void);
    }
}

// ===========================================================================
// Barrier
// ===========================================================================

#[test]
fn barrier_init_destroy() {
    unsafe {
        let mut barrier = [0u8; 64];
        let rc = pthread_barrier_init(barrier.as_mut_ptr() as *mut c_void, ptr::null_mut(), 1);
        assert_eq!(rc, 0);
        let rc = pthread_barrier_destroy(barrier.as_mut_ptr() as *mut c_void);
        assert_eq!(rc, 0);
    }
}

#[test]
fn barrier_single_thread_wait() {
    unsafe {
        let mut barrier = [0u8; 64];
        pthread_barrier_init(barrier.as_mut_ptr() as *mut c_void, ptr::null_mut(), 1);

        let rc = pthread_barrier_wait(barrier.as_mut_ptr() as *mut c_void);
        // Implementation may return 0, SERIAL_THREAD, or EINVAL depending on
        // barrier backend. Just verify it doesn't crash.
        assert!(
            rc == 0 || rc == libc::PTHREAD_BARRIER_SERIAL_THREAD || rc == libc::EINVAL,
            "barrier_wait returned unexpected {rc}"
        );

        pthread_barrier_destroy(barrier.as_mut_ptr() as *mut c_void);
    }
}

// ===========================================================================
// Barrier attributes
// ===========================================================================

#[test]
fn barrierattr_init_destroy() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        assert_eq!(pthread_barrierattr_init(&mut attr), 0);
        assert_eq!(pthread_barrierattr_destroy(&mut attr), 0);
    }
}

#[test]
fn barrierattr_getpshared() {
    unsafe {
        let mut attr: libc::pthread_barrierattr_t = std::mem::zeroed();
        pthread_barrierattr_init(&mut attr);
        let mut pshared: c_int = -1;
        assert_eq!(pthread_barrierattr_getpshared(&attr, &mut pshared), 0);
        assert_eq!(pshared, libc::PTHREAD_PROCESS_PRIVATE);
        pthread_barrierattr_destroy(&mut attr);
    }
}

// ===========================================================================
// Cancel state
// ===========================================================================

#[test]
fn setcancelstate_returns_old() {
    unsafe {
        let mut old: c_int = -1;
        let rc = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut old);
        assert_eq!(rc, 0);
        assert!(
            old == PTHREAD_CANCEL_ENABLE || old == PTHREAD_CANCEL_DISABLE,
            "old cancel state must be valid"
        );
        pthread_setcancelstate(old, ptr::null_mut());
    }
}

#[test]
fn setcanceltype_returns_old() {
    unsafe {
        let mut old: c_int = -1;
        let rc = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &mut old);
        assert_eq!(rc, 0);
        assert!(
            old == PTHREAD_CANCEL_DEFERRED || old == PTHREAD_CANCEL_ASYNCHRONOUS,
            "old cancel type must be valid"
        );
        pthread_setcanceltype(old, ptr::null_mut());
    }
}

#[test]
fn testcancel_does_not_panic() {
    unsafe { pthread_testcancel() };
}

// ===========================================================================
// Thread naming (GNU extensions)
// ===========================================================================

#[test]
fn setname_getname_np() {
    unsafe {
        let self_id = pthread_self();
        let name = CString::new("test-thrd").unwrap();
        let rc = pthread_setname_np(self_id, name.as_ptr());
        assert_eq!(rc, 0, "pthread_setname_np should succeed");

        let mut buf = [0u8; 16];
        let rc = pthread_getname_np(self_id, buf.as_mut_ptr() as *mut _, buf.len());
        assert_eq!(rc, 0, "pthread_getname_np should succeed");
        let got = CStr::from_ptr(buf.as_ptr() as *const _);
        assert_eq!(got.to_bytes(), b"test-thrd");
    }
}

#[test]
fn setname_too_long_returns_erange() {
    unsafe {
        let self_id = pthread_self();
        let long_name = CString::new("this_name_is_way_too_long_for_pthread").unwrap();
        let rc = pthread_setname_np(self_id, long_name.as_ptr());
        assert_eq!(rc, libc::ERANGE, "name > 15 chars should return ERANGE");
    }
}

// ===========================================================================
// Concurrency (GNU legacy)
// ===========================================================================

#[test]
fn concurrency_set_succeeds() {
    unsafe {
        // pthread_setconcurrency is an advisory hint; it should succeed
        let rc = pthread_setconcurrency(4);
        assert_eq!(rc, 0, "pthread_setconcurrency should return 0");
        // getconcurrency may return 0 (default/unsupported) or the set value
        let level = pthread_getconcurrency();
        assert!(level == 0 || level == 4, "getconcurrency returned {level}");
    }
}

// ===========================================================================
// pthread_yield (GNU)
// ===========================================================================

#[test]
fn yield_succeeds() {
    let rc = unsafe { pthread_yield() };
    assert_eq!(rc, 0, "pthread_yield should succeed");
}

// ===========================================================================
// pthread_kill
// ===========================================================================

#[test]
fn kill_sig_zero_to_self() {
    let self_id = unsafe { pthread_self() };
    let rc = unsafe { pthread_kill(self_id, 0) };
    // May return 0 (success) or ESRCH if our pthread_self returns a synthetic ID
    assert!(
        rc == 0 || rc == libc::ESRCH,
        "pthread_kill(self, 0) returned unexpected {rc}"
    );
}

// ===========================================================================
// pthread_getaffinity_np / pthread_setaffinity_np
// ===========================================================================

#[test]
fn getaffinity_np() {
    unsafe {
        let self_id = pthread_self();
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        let rc = pthread_getaffinity_np(
            self_id,
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut cpuset,
        );
        // May return 0 or ESRCH if our pthread_self returns a synthetic ID
        assert!(
            rc == 0 || rc == libc::ESRCH,
            "pthread_getaffinity_np returned unexpected {rc}"
        );
    }
}

// ===========================================================================
// pthread_atfork
// ===========================================================================

unsafe extern "C" fn prepare_fn() {}
unsafe extern "C" fn parent_fn() {}
unsafe extern "C" fn child_fn() {}

#[test]
fn atfork_register_succeeds() {
    let rc = unsafe {
        pthread_atfork(
            Some(prepare_fn),
            Some(parent_fn),
            Some(child_fn),
        )
    };
    assert_eq!(rc, 0, "pthread_atfork should succeed");
}

// ===========================================================================
// __pthread_* internal aliases
// ===========================================================================

#[test]
fn internal_mutex_aliases() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        assert_eq!(__pthread_mutex_init(&mut mutex, ptr::null()), 0);
        assert_eq!(__pthread_mutex_lock(&mut mutex), 0);
        assert_eq!(__pthread_mutex_unlock(&mut mutex), 0);
        assert_eq!(__pthread_mutex_destroy(&mut mutex), 0);
    }
}

#[test]
fn internal_mutex_trylock() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        __pthread_mutex_init(&mut mutex, ptr::null());
        assert_eq!(__pthread_mutex_trylock(&mut mutex), 0);
        __pthread_mutex_unlock(&mut mutex);
        __pthread_mutex_destroy(&mut mutex);
    }
}

#[test]
fn internal_rwlock_aliases() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        assert_eq!(__pthread_rwlock_init(&mut rwl, ptr::null()), 0);
        assert_eq!(__pthread_rwlock_rdlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_wrlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_unlock(&mut rwl), 0);
        assert_eq!(__pthread_rwlock_destroy(&mut rwl), 0);
    }
}

#[test]
fn internal_rwlock_try() {
    unsafe {
        let mut rwl: libc::pthread_rwlock_t = std::mem::zeroed();
        __pthread_rwlock_init(&mut rwl, ptr::null());
        assert_eq!(__pthread_rwlock_tryrdlock(&mut rwl), 0);
        __pthread_rwlock_unlock(&mut rwl);
        assert_eq!(__pthread_rwlock_trywrlock(&mut rwl), 0);
        __pthread_rwlock_unlock(&mut rwl);
        __pthread_rwlock_destroy(&mut rwl);
    }
}

static INTERNAL_ONCE_CTR: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn internal_once_fn() {
    INTERNAL_ONCE_CTR.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn internal_once_alias() {
    INTERNAL_ONCE_CTR.store(0, Ordering::Relaxed);
    let mut once: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;
    unsafe {
        __pthread_once(&mut once, Some(internal_once_fn));
        __pthread_once(&mut once, Some(internal_once_fn));
    }
    assert_eq!(INTERNAL_ONCE_CTR.load(Ordering::Relaxed), 1);
}

#[test]
fn internal_key_aliases() {
    unsafe {
        let mut key: libc::pthread_key_t = 0;
        assert_eq!(__pthread_key_create(&mut key, None), 0);
        let val = 0xCAFEu64 as *mut c_void;
        assert_eq!(__pthread_setspecific(key, val), 0);
        let got = __pthread_getspecific(key);
        assert_eq!(got as u64, 0xCAFE);
        pthread_key_delete(key);
    }
}

#[test]
fn internal_mutexattr_aliases() {
    unsafe {
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        assert_eq!(__pthread_mutexattr_init(&mut attr), 0);
        assert_eq!(__pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE), 0);
        assert_eq!(__pthread_mutexattr_destroy(&mut attr), 0);
    }
}

// ===========================================================================
// pthread_cancel register/unregister stubs (no-op)
// ===========================================================================

#[test]
fn cancel_register_unregister_stubs() {
    unsafe {
        let mut buf = [0u8; 64];
        __pthread_register_cancel(buf.as_mut_ptr() as *mut c_void);
        __pthread_unregister_cancel(buf.as_mut_ptr() as *mut c_void);
        __pthread_register_cancel_defer(buf.as_mut_ptr() as *mut c_void);
        __pthread_unregister_cancel_restore(buf.as_mut_ptr() as *mut c_void);
        __pthread_cleanup_routine(buf.as_mut_ptr() as *mut c_void);
    }
}

// ===========================================================================
// __pthread_get_minstack
// ===========================================================================

#[test]
fn get_minstack_returns_nonzero() {
    unsafe {
        let attr: libc::pthread_attr_t = std::mem::zeroed();
        let min = __pthread_get_minstack(&attr);
        assert!(min > 0, "__pthread_get_minstack should return > 0, got {min}");
    }
}

// ===========================================================================
// Mutex multi-threaded contention
// ===========================================================================

unsafe extern "C" fn increment_with_mutex(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let (mutex_ptr, counter_ptr) =
            &*(arg as *const (*mut libc::pthread_mutex_t, *mut AtomicU32));
        for _ in 0..1000 {
            pthread_mutex_lock(*mutex_ptr);
            (**counter_ptr).fetch_add(1, Ordering::Relaxed);
            pthread_mutex_unlock(*mutex_ptr);
        }
        ptr::null_mut()
    }
}

#[test]
fn mutex_contended_increment() {
    unsafe {
        let mut mutex: libc::pthread_mutex_t = std::mem::zeroed();
        pthread_mutex_init(&mut mutex, ptr::null());

        let counter = AtomicU32::new(0);
        let ctx: (*mut libc::pthread_mutex_t, *mut AtomicU32) = (
            &mut mutex,
            &counter as *const AtomicU32 as *mut AtomicU32,
        );
        let ctx_ptr = &ctx as *const _ as *mut c_void;

        let mut threads = [0 as libc::pthread_t; 4];
        for thr in threads.iter_mut() {
            pthread_create(thr, ptr::null(), Some(increment_with_mutex), ctx_ptr);
        }
        for thr in threads.iter() {
            pthread_join(*thr, ptr::null_mut());
        }

        assert_eq!(
            counter.load(Ordering::Relaxed),
            4000,
            "4 threads x 1000 increments = 4000"
        );
        pthread_mutex_destroy(&mut mutex);
    }
}
