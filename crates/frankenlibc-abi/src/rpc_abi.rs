//! ABI layer for Sun RPC / XDR / SVC functions.
//!
//! These are legacy ONC RPC functions from glibc's `<rpc/rpc.h>`, `<rpc/xdr.h>`,
//! `<rpc/svc.h>`, `<rpc/clnt.h>`, `<rpc/auth.h>`, `<rpc/pmap_clnt.h>`, and
//! `<rpc/des_crypt.h>` families. All symbols are delegated to the host glibc
//! via `dlsym(RTLD_NEXT, ...)` since they interact with internal RPC runtime
//! state that cannot be faithfully reimplemented.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::ffi::{c_char, c_int, c_uint, c_void};

type c_ulong = u64;
#[allow(dead_code)]
type c_long = i64;

/// `struct timeval` for by-value parameters in clntudp_create / pmap_rmtcall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

// ---------------------------------------------------------------------------
// dlsym call-through macro
// ---------------------------------------------------------------------------

/// Resolve a glibc symbol via `dlsym(RTLD_NEXT, name)` and call through.
/// For functions returning c_int (bool_t): returns 0 (FALSE) on dlsym failure.
macro_rules! rpc_delegate {
    // Pattern 1: function returning c_int (most common — XDR bool_t, RPC status)
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> c_int) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> c_int {
            type F = unsafe extern "C" fn( $($pty),* ) -> c_int;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return 0; }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
    // Pattern 2: function returning *mut c_void (client/transport handle creation)
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> *mut c_void) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> *mut c_void {
            type F = unsafe extern "C" fn( $($pty),* ) -> *mut c_void;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return std::ptr::null_mut(); }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
    // Pattern 3: function returning ()
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> ()) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) {
            type F = unsafe extern "C" fn( $($pty),* );
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return; }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
    // Pattern 4: function returning c_ulong / usize
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> c_ulong) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> c_ulong {
            type F = unsafe extern "C" fn( $($pty),* ) -> c_ulong;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return 0; }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
    // Pattern 5: function returning *mut c_char (error string functions)
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> *mut c_char) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> *mut c_char {
            type F = unsafe extern "C" fn( $($pty),* ) -> *mut c_char;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return std::ptr::null_mut(); }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
    // Pattern 6: function returning u16 (pmap_getport)
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> u16) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname : $pty),* ) -> u16 {
            type F = unsafe extern "C" fn( $($pty),* ) -> u16;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() { return 0; }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($pname),* ) }
        }
    };
}

// ===========================================================================
// XDR core serialization (63 symbols)
// ===========================================================================

// --- Simple type serializers: (XDR*, T*) -> bool_t ---

rpc_delegate!(xdr_bool(xdrs: *mut c_void, bp: *mut c_int) -> c_int);
rpc_delegate!(xdr_char(xdrs: *mut c_void, cp: *mut c_char) -> c_int);
rpc_delegate!(xdr_double(xdrs: *mut c_void, dp: *mut f64) -> c_int);
rpc_delegate!(xdr_enum(xdrs: *mut c_void, ep: *mut c_int) -> c_int);
rpc_delegate!(xdr_float(xdrs: *mut c_void, fp: *mut f32) -> c_int);
rpc_delegate!(xdr_hyper(xdrs: *mut c_void, hp: *mut i64) -> c_int);
rpc_delegate!(xdr_int(xdrs: *mut c_void, ip: *mut c_int) -> c_int);
rpc_delegate!(xdr_long(xdrs: *mut c_void, lp: *mut c_long) -> c_int);
rpc_delegate!(xdr_longlong_t(xdrs: *mut c_void, lp: *mut i64) -> c_int);
rpc_delegate!(xdr_quad_t(xdrs: *mut c_void, qp: *mut i64) -> c_int);
rpc_delegate!(xdr_short(xdrs: *mut c_void, sp: *mut i16) -> c_int);
rpc_delegate!(xdr_u_char(xdrs: *mut c_void, cp: *mut u8) -> c_int);
rpc_delegate!(xdr_u_hyper(xdrs: *mut c_void, hp: *mut u64) -> c_int);
rpc_delegate!(xdr_u_int(xdrs: *mut c_void, ip: *mut c_uint) -> c_int);
rpc_delegate!(xdr_u_long(xdrs: *mut c_void, lp: *mut c_ulong) -> c_int);
rpc_delegate!(xdr_u_longlong_t(xdrs: *mut c_void, lp: *mut u64) -> c_int);
rpc_delegate!(xdr_u_quad_t(xdrs: *mut c_void, qp: *mut u64) -> c_int);
rpc_delegate!(xdr_u_short(xdrs: *mut c_void, sp: *mut u16) -> c_int);
rpc_delegate!(xdr_int8_t(xdrs: *mut c_void, ip: *mut i8) -> c_int);
rpc_delegate!(xdr_int16_t(xdrs: *mut c_void, ip: *mut i16) -> c_int);
rpc_delegate!(xdr_int32_t(xdrs: *mut c_void, ip: *mut i32) -> c_int);
rpc_delegate!(xdr_int64_t(xdrs: *mut c_void, ip: *mut i64) -> c_int);
rpc_delegate!(xdr_uint8_t(xdrs: *mut c_void, ip: *mut u8) -> c_int);
rpc_delegate!(xdr_uint16_t(xdrs: *mut c_void, ip: *mut u16) -> c_int);
rpc_delegate!(xdr_uint32_t(xdrs: *mut c_void, ip: *mut u32) -> c_int);
rpc_delegate!(xdr_uint64_t(xdrs: *mut c_void, ip: *mut u64) -> c_int);

// --- Void serializer (native: always succeeds) ---

/// XDR void serializer — always returns TRUE (1).
/// No data to serialize, so this is unconditionally successful.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_void() -> c_int {
    1 // TRUE
}

// --- Compound / aggregate serializers ---

rpc_delegate!(xdr_array(
    xdrs: *mut c_void,
    arrp: *mut *mut c_char,
    sizep: *mut c_uint,
    maxsize: c_uint,
    elsize: c_uint,
    elproc: *mut c_void
) -> c_int);

rpc_delegate!(xdr_vector(
    xdrs: *mut c_void,
    arrp: *mut c_char,
    size: c_uint,
    elsize: c_uint,
    elproc: *mut c_void
) -> c_int);

rpc_delegate!(xdr_bytes(
    xdrs: *mut c_void,
    sp: *mut *mut c_char,
    lp: *mut c_uint,
    maxsize: c_uint
) -> c_int);

rpc_delegate!(xdr_opaque(xdrs: *mut c_void, cp: *mut c_char, cnt: c_uint) -> c_int);

rpc_delegate!(xdr_string(
    xdrs: *mut c_void,
    sp: *mut *mut c_char,
    maxsize: c_uint
) -> c_int);

rpc_delegate!(xdr_wrapstring(xdrs: *mut c_void, sp: *mut *mut c_char) -> c_int);

rpc_delegate!(xdr_reference(
    xdrs: *mut c_void,
    pp: *mut *mut c_char,
    size: c_uint,
    proc_: *mut c_void
) -> c_int);

rpc_delegate!(xdr_pointer(
    xdrs: *mut c_void,
    pp: *mut *mut c_char,
    size: c_uint,
    proc_: *mut c_void
) -> c_int);

rpc_delegate!(xdr_union(
    xdrs: *mut c_void,
    dscmp: *mut c_int,
    unp: *mut c_char,
    choices: *const c_void,
    dfault: *mut c_void
) -> c_int);

rpc_delegate!(xdr_netobj(xdrs: *mut c_void, np: *mut c_void) -> c_int);

// --- xdr_free: void return ---

rpc_delegate!(xdr_free(proc_: *mut c_void, objp: *mut c_char) -> ());

// --- xdr_sizeof: returns unsigned long ---

rpc_delegate!(xdr_sizeof(func: *mut c_void, data: *mut c_void) -> c_ulong);

// --- RPC message / auth serializers ---

rpc_delegate!(xdr_accepted_reply(xdrs: *mut c_void, ar: *mut c_void) -> c_int);
rpc_delegate!(xdr_rejected_reply(xdrs: *mut c_void, rr: *mut c_void) -> c_int);
rpc_delegate!(xdr_replymsg(xdrs: *mut c_void, rmsg: *mut c_void) -> c_int);
rpc_delegate!(xdr_callhdr(xdrs: *mut c_void, cmsg: *mut c_void) -> c_int);
rpc_delegate!(xdr_callmsg(xdrs: *mut c_void, cmsg: *mut c_void) -> c_int);
rpc_delegate!(xdr_opaque_auth(xdrs: *mut c_void, ap: *mut c_void) -> c_int);
rpc_delegate!(xdr_authdes_cred(xdrs: *mut c_void, cred: *mut c_void) -> c_int);
rpc_delegate!(xdr_authdes_verf(xdrs: *mut c_void, verf: *mut c_void) -> c_int);
rpc_delegate!(xdr_authunix_parms(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_pmap(xdrs: *mut c_void, regs: *mut c_void) -> c_int);
rpc_delegate!(xdr_pmaplist(xdrs: *mut c_void, rp: *mut c_void) -> c_int);
rpc_delegate!(xdr_rmtcall_args(xdrs: *mut c_void, cap: *mut c_void) -> c_int);
rpc_delegate!(xdr_rmtcallres(xdrs: *mut c_void, crp: *mut c_void) -> c_int);
rpc_delegate!(xdr_des_block(xdrs: *mut c_void, blkp: *mut c_void) -> c_int);
rpc_delegate!(xdr_unixcred(xdrs: *mut c_void, ucp: *mut c_void) -> c_int);

// --- Key/crypt XDR serializers ---

rpc_delegate!(xdr_cryptkeyarg(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_cryptkeyarg2(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_cryptkeyres(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_getcredres(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_keybuf(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_keystatus(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_key_netstarg(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_key_netstres(xdrs: *mut c_void, p: *mut c_void) -> c_int);
rpc_delegate!(xdr_netnamestr(xdrs: *mut c_void, p: *mut c_void) -> c_int);

// ===========================================================================
// XDR stream constructors (6 symbols)
// ===========================================================================

rpc_delegate!(xdrmem_create(
    xdrs: *mut c_void,
    addr: *mut c_char,
    size: c_uint,
    op: c_int
) -> ());

rpc_delegate!(xdrstdio_create(xdrs: *mut c_void, file: *mut c_void, op: c_int) -> ());

rpc_delegate!(xdrrec_create(
    xdrs: *mut c_void,
    sendsize: c_uint,
    recvsize: c_uint,
    handle: *mut c_void,
    readit: *mut c_void,
    writeit: *mut c_void
) -> ());

rpc_delegate!(xdrrec_endofrecord(xdrs: *mut c_void, sendnow: c_int) -> c_int);
rpc_delegate!(xdrrec_eof(xdrs: *mut c_void) -> c_int);
rpc_delegate!(xdrrec_skiprecord(xdrs: *mut c_void) -> c_int);

// ===========================================================================
// RPC authentication (7 symbols)
// ===========================================================================

rpc_delegate!(authnone_create() -> *mut c_void);

rpc_delegate!(authunix_create(
    machname: *mut c_char,
    uid: c_int,
    gid: c_int,
    len: c_int,
    aup_gids: *mut c_int
) -> *mut c_void);

rpc_delegate!(authunix_create_default() -> *mut c_void);

rpc_delegate!(authdes_create(
    servername: *mut c_char,
    window: c_uint,
    syncaddr: *mut c_void,
    ckey: *mut c_void
) -> *mut c_void);

rpc_delegate!(authdes_pk_create(
    servername: *mut c_char,
    pkey: *mut c_void,
    window: c_uint,
    syncaddr: *mut c_void,
    ckey: *mut c_void
) -> *mut c_void);

rpc_delegate!(authdes_getucred(
    adc: *mut c_void,
    uid: *mut u32,
    gid: *mut u32,
    grouplen: *mut i16,
    groups: *mut c_int
) -> c_int);

rpc_delegate!(_authenticate(rqst: *mut c_void, msg: *mut c_void) -> c_int);

// ===========================================================================
// RPC client creation and error handling (14 symbols)
// ===========================================================================

rpc_delegate!(clnt_create(
    host: *const c_char,
    prog: c_ulong,
    vers: c_ulong,
    proto: *const c_char
) -> *mut c_void);

rpc_delegate!(clntraw_create(prog: c_ulong, vers: c_ulong) -> *mut c_void);

rpc_delegate!(clnttcp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_delegate!(clntudp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int
) -> *mut c_void);

rpc_delegate!(clntudp_bufcreate(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_delegate!(clntunix_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_delegate!(callrpc(
    host: *const c_char,
    prognum: c_ulong,
    versnum: c_ulong,
    procnum: c_ulong,
    inproc: *mut c_void,
    in_: *mut c_char,
    outproc: *mut c_void,
    out: *mut c_char
) -> c_int);

rpc_delegate!(clnt_broadcast(
    prog: c_ulong,
    vers: c_ulong,
    proc_: c_ulong,
    xargs: *mut c_void,
    argsp: *mut c_void,
    xresults: *mut c_void,
    resultsp: *mut c_void,
    eachresult: *mut c_void
) -> c_int);

/// Print RPC error number description to stderr. Native implementation.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perrno(stat: c_int) {
    let msg = rpc_errstr(stat);
    // Write to stderr: "RPC: <message>\n"
    let _ = unsafe { libc::write(2, b"RPC: ".as_ptr().cast(), 5) };
    let _ = unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
    let _ = unsafe { libc::write(2, b"\n".as_ptr().cast(), 1) };
}

rpc_delegate!(clnt_perror(clnt: *mut c_void, s: *const c_char) -> ());
rpc_delegate!(clnt_pcreateerror(s: *const c_char) -> ());

// Thread-local buffer for clnt_sperrno return value.
std::thread_local! {
    static SPERRNO_BUF: std::cell::UnsafeCell<[u8; 64]> =
        const { std::cell::UnsafeCell::new([0u8; 64]) };
}

/// Return a string describing an RPC error status code. Native implementation.
/// Uses RPC_* status codes from glibc's <rpc/clnt_stat.h>.
///
/// # Safety
/// ABI boundary function. Returns a pointer valid until the next call from the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperrno(stat: c_int) -> *mut c_char {
    let msg = rpc_errstr(stat);
    SPERRNO_BUF.with(|cell| {
        let buf = unsafe { &mut *cell.get() };
        let len = msg.len().min(63);
        buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
        buf[len] = 0;
        buf.as_mut_ptr().cast()
    })
}

rpc_delegate!(clnt_sperror(clnt: *mut c_void, s: *const c_char) -> *mut c_char);
rpc_delegate!(clnt_spcreateerror(s: *const c_char) -> *mut c_char);

/// Map RPC status codes to human-readable strings.
fn rpc_errstr(stat: c_int) -> &'static str {
    match stat {
        0 => "Success",
        1 => "Can't encode arguments",
        2 => "Can't decode results",
        3 => "Unable to send",
        4 => "Unable to receive",
        5 => "Timed out",
        6 => "Incompatible versions of RPC",
        7 => "Authentication error",
        8 => "Program unavailable",
        9 => "Program/version mismatch",
        10 => "Procedure unavailable",
        11 => "Server can't decode arguments",
        12 => "Remote system error",
        13 => "Unknown host",
        14 => "Port mapper failure",
        15 => "Program not registered",
        16 => "Failed (unspecified error)",
        17 => "Unknown protocol",
        _ => "Unknown error",
    }
}

// ===========================================================================
// RPC server / SVC (24 symbols)
// ===========================================================================

rpc_delegate!(svc_register(
    xprt: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    dispatch: *mut c_void,
    protocol: c_int
) -> c_int);

rpc_delegate!(svc_unregister(prog: c_ulong, vers: c_ulong) -> ());

rpc_delegate!(svc_sendreply(
    xprt: *mut c_void,
    xdr_results: *mut c_void,
    xdr_location: *mut c_void
) -> c_int);

rpc_delegate!(svc_run() -> ());
rpc_delegate!(svc_exit() -> ());

rpc_delegate!(svc_getreq(rdfds: c_int) -> ());
rpc_delegate!(svc_getreqset(readfds: *mut c_void) -> ());
rpc_delegate!(svc_getreq_common(fd: c_int) -> ());
rpc_delegate!(svc_getreq_poll(pfds: *mut c_void, nfds: c_int) -> ());

// --- SVC error replies ---

rpc_delegate!(svcerr_auth(xprt: *mut c_void, why: c_int) -> ());
rpc_delegate!(svcerr_decode(xprt: *mut c_void) -> ());
rpc_delegate!(svcerr_noproc(xprt: *mut c_void) -> ());
rpc_delegate!(svcerr_noprog(xprt: *mut c_void) -> ());
rpc_delegate!(svcerr_progvers(
    xprt: *mut c_void,
    low_vers: c_ulong,
    high_vers: c_ulong
) -> ());
rpc_delegate!(svcerr_systemerr(xprt: *mut c_void) -> ());
rpc_delegate!(svcerr_weakauth(xprt: *mut c_void) -> ());

// --- SVC transport creation ---

rpc_delegate!(svcraw_create() -> *mut c_void);
rpc_delegate!(svcfd_create(fd: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_delegate!(svctcp_create(sock: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_delegate!(svcudp_create(sock: c_int) -> *mut c_void);

rpc_delegate!(svcudp_bufcreate(
    sock: c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_delegate!(svcudp_enablecache(xprt: *mut c_void, cachesz: c_ulong) -> c_int);
rpc_delegate!(svcunix_create(sock: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_delegate!(svcunixfd_create(fd: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);

// ===========================================================================
// RPC misc: registerrpc, dtablesize, createerr thread locals (14+ symbols)
// ===========================================================================

rpc_delegate!(registerrpc(
    prognum: c_ulong,
    versnum: c_ulong,
    procnum: c_ulong,
    progname: *mut c_void,
    inproc: *mut c_void,
    outproc: *mut c_void
) -> c_int);

/// Returns the file descriptor table size (same as getdtablesize).
/// Uses getrlimit(RLIMIT_NOFILE) with a fallback to FD_SETSIZE (1024).
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _rpc_dtablesize() -> c_int {
    // SAFETY: zero-init rlimit struct, then getrlimit fills it.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc == 0 && rl.rlim_cur > 0 {
        // Clamp to FD_SETSIZE (1024) to match glibc _rpc_dtablesize behavior.
        let limit = rl.rlim_cur as c_int;
        if limit > 1024 { 1024 } else { limit }
    } else {
        1024 // FD_SETSIZE default
    }
}

// --- Thread-local RPC state accessors (native TLS) ---
//
// In glibc these return pointers to thread-local structs. We provide native
// TLS storage for the rpc_createerr, svc_fdset, svc_max_pollfd, and
// svc_pollfd thread-local variables. Programs that use these accessors will
// get per-thread storage without needing to call into glibc.

// rpc_createerr: struct rpc_createerr { enum clnt_stat cf_stat; struct rpc_err cf_error; }
// This is 24 bytes on x86_64 (4 + padding + 16 for rpc_err).
// We allocate 32 bytes to be safe for alignment.
std::thread_local! {
    static RPC_CREATEERR_TLS: std::cell::UnsafeCell<[u8; 32]> =
        const { std::cell::UnsafeCell::new([0u8; 32]) };
}

/// Returns pointer to thread-local rpc_createerr struct.
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_createerr() -> *mut c_void {
    RPC_CREATEERR_TLS.with(|cell| cell.get().cast())
}

// fd_set is 128 bytes on Linux (FD_SETSIZE=1024, 1024/8=128).
std::thread_local! {
    static RPC_SVC_FDSET_TLS: std::cell::UnsafeCell<[u8; 128]> =
        const { std::cell::UnsafeCell::new([0u8; 128]) };
}

/// Returns pointer to thread-local svc_fdset (fd_set).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_fdset() -> *mut c_void {
    RPC_SVC_FDSET_TLS.with(|cell| cell.get().cast())
}

std::thread_local! {
    static RPC_SVC_MAX_POLLFD_TLS: std::cell::UnsafeCell<c_int> =
        const { std::cell::UnsafeCell::new(0) };
}

/// Returns pointer to thread-local svc_max_pollfd (int).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_max_pollfd() -> *mut c_void {
    RPC_SVC_MAX_POLLFD_TLS.with(|cell| cell.get().cast())
}

std::thread_local! {
    static RPC_SVC_POLLFD_TLS: std::cell::UnsafeCell<*mut c_void> =
        const { std::cell::UnsafeCell::new(std::ptr::null_mut()) };
}

/// Returns pointer to thread-local svc_pollfd (struct pollfd *).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_pollfd() -> *mut c_void {
    RPC_SVC_POLLFD_TLS.with(|cell| cell.get().cast())
}

// --- _seterr_reply (native) ---

/// Extract error information from an RPC reply message into an rpc_err struct.
/// This parses msg->rm_reply.rp_stat to determine accept/reject status and
/// populates the error struct accordingly.
///
/// struct rpc_msg layout at field rm_reply (offset ~12):
///   rp_stat (enum reply_stat): 0=MSG_ACCEPTED, 1=MSG_DENIED
///
/// For MSG_ACCEPTED (rp_stat==0):
///   ar_stat (enum accept_stat): acceptance status at offset +4
///   ar_vers.low/high (u32,u32): if PROG_MISMATCH, at +8/+12
///
/// For MSG_DENIED (rp_stat==1):
///   rj_stat (enum reject_stat): 0=RPC_MISMATCH, 1=AUTH_ERROR
///   rj_vers.low/high or rj_why: at +4/+8/+12
///
/// rpc_err layout: re_status(enum, 4 bytes), then union (rpc_err_union).
///
/// Since the exact struct layouts are ABI-dependent and complex, we provide a
/// minimal implementation that just zeroes the error struct (success case).
/// Programs needing full RPC error parsing will work via host delegation for
/// the actual RPC calls themselves.
///
/// # Safety
/// ABI boundary function. Both pointers must be valid or null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _seterr_reply(msg: *mut c_void, error: *mut c_void) {
    if msg.is_null() || error.is_null() {
        return;
    }
    // Zero out the error struct (24 bytes for rpc_err on x86_64).
    // This is safe because rpc_err is a C struct with only integer/enum fields.
    unsafe {
        std::ptr::write_bytes(error.cast::<u8>(), 0, 24);
    }

    // Read reply stat from the message. The rm_reply union starts after
    // rm_xid(u32) + rm_direction(enum=4 bytes) = offset 8 in struct rpc_msg.
    // rm_reply.rp_stat is the first field.
    let msg_bytes = msg.cast::<u8>();
    let rp_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(8).cast::<u32>()) };

    // error->re_status: map RPC reply status
    let error_bytes = error.cast::<u8>();
    if rp_stat == 0 {
        // MSG_ACCEPTED — read ar_stat at offset +12 in rpc_msg
        let ar_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(12).cast::<u32>()) };
        // Map accept_stat to clnt_stat: SUCCESS=0, PROG_UNAVAIL=8, etc.
        let re_status: u32 = match ar_stat {
            0 => 0,  // SUCCESS
            1 => 8,  // PROG_UNAVAIL → RPC_PROGUNAVAIL
            2 => 9,  // PROG_MISMATCH → RPC_PROGVERSMISMATCH
            3 => 10, // PROC_UNAVAIL → RPC_PROCUNAVAIL
            4 => 11, // GARBAGE_ARGS → RPC_CANTDECODEARGS
            5 => 12, // SYSTEM_ERR → RPC_SYSTEMERROR
            _ => 16, // RPC_FAILED
        };
        unsafe {
            std::ptr::write_unaligned(error_bytes.cast::<u32>(), re_status);
        }
        // If PROG_MISMATCH, copy version range
        if ar_stat == 2 {
            let low = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            let high = unsafe { std::ptr::read_unaligned(msg_bytes.add(20).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), low);
                std::ptr::write_unaligned(error_bytes.add(8).cast::<u32>(), high);
            }
        }
    } else {
        // MSG_DENIED — read rj_stat at offset +12
        let rj_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(12).cast::<u32>()) };
        if rj_stat == 0 {
            // RPC_MISMATCH
            unsafe {
                std::ptr::write_unaligned(error_bytes.cast::<u32>(), 6); // RPC_VERSMISMATCH
            }
            let low = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            let high = unsafe { std::ptr::read_unaligned(msg_bytes.add(20).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), low);
                std::ptr::write_unaligned(error_bytes.add(8).cast::<u32>(), high);
            }
        } else {
            // AUTH_ERROR
            unsafe {
                std::ptr::write_unaligned(error_bytes.cast::<u32>(), 7); // RPC_AUTHERROR
            }
            let why = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), why);
            }
        }
    }
}

// --- _null_auth: this is a global variable in glibc, we export a function
//     that fetches its address from the host. Programs typically access it
//     directly; for LD_PRELOAD interposition we provide a function-based
//     accessor. The linker symbol is handled separately in the version script. ---

// ===========================================================================
// Key management / Secure RPC (16+ symbols)
// ===========================================================================

/// Decrypt a session key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession(
    _remotename: *const c_char,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Decrypt a session key with a public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession_pk(
    _remotename: *const c_char,
    _remotekey: *mut c_void,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Encrypt a session key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession(
    _remotename: *const c_char,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Encrypt a session key with a public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession_pk(
    _remotename: *const c_char,
    _remotekey: *mut c_void,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Generate a DES key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_gendes(_deskey: *mut c_void) -> c_int {
    -1 // No keyserver available
}

/// Get conversation key from public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_get_conv(_pkey: *mut c_char, _deskey: *mut c_void) -> c_int {
    -1 // No keyserver available
}
/// Check if the secret key has been set with the key server.
/// Returns 0 (FALSE) — no keyserv integration in FrankenLibC.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_secretkey_is_set() -> c_int {
    0 // No keyserv client installed
}

/// Set network key parameters. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_setnet(_arg: *mut c_void) -> c_int {
    -1 // No keyserver available
}

/// Set secret key with key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_setsecret(_secretkey: *const c_char) -> c_int {
    -1 // No keyserver available
}

// --- Internal key function pointer globals ---
// In glibc these are `int (*__key_*_LOCAL)(...)` global function pointers.
// We export them as mutable static AtomicPtrs so programs and libraries
// can read/write them. Initialized to null (no keyserv client installed).

use std::sync::atomic::AtomicPtr;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_decryptsession_pk_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_encryptsession_pk_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_gendes_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ===========================================================================
// Portmapper client (5 symbols)
// ===========================================================================

rpc_delegate!(pmap_getmaps(address: *mut c_void) -> *mut c_void);
rpc_delegate!(pmap_getport(
    address: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    proto: c_uint
) -> u16);

rpc_delegate!(pmap_rmtcall(
    addr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    proc_: c_ulong,
    xdrargs: *mut c_void,
    argsp: *mut c_void,
    xdrres: *mut c_void,
    resp: *mut c_void,
    tout: Timeval,
    portp: *mut c_ulong
) -> c_int);

rpc_delegate!(pmap_set(prog: c_ulong, vers: c_ulong, proto: c_int, port: u16) -> c_int);
rpc_delegate!(pmap_unset(prog: c_ulong, vers: c_ulong) -> c_int);

// ===========================================================================
// DES crypt helpers (6 symbols) — Native stubs
//
// DES is cryptographically broken (56-bit key). These functions are from
// <rpc/des_crypt.h> and are deprecated. We return DESERR_NOHWDEVICE (4)
// for cbc_crypt/ecb_crypt to indicate no DES hardware is available,
// and 0 (failure) for xencrypt/xdecrypt/passwd2des. des_setparity is
// a no-op since we don't use DES.
// ===========================================================================

/// DESERR_NOHWDEVICE — no DES hardware available (standard return code).
const DESERR_NOHWDEVICE: c_int = 4;

/// CBC-mode DES encryption/decryption. Returns DESERR_NOHWDEVICE.
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbc_crypt(
    _key: *mut c_char,
    _buf: *mut c_char,
    _len: c_uint,
    _mode: c_uint,
    _ivec: *mut c_char,
) -> c_int {
    DESERR_NOHWDEVICE
}

/// ECB-mode DES encryption/decryption. Returns DESERR_NOHWDEVICE.
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecb_crypt(
    _key: *mut c_char,
    _buf: *mut c_char,
    _len: c_uint,
    _mode: c_uint,
) -> c_int {
    DESERR_NOHWDEVICE
}

/// Set DES key parity bits. No-op since DES is not supported.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn des_setparity(_key: *mut c_char) {
    // No-op: DES parity is irrelevant without DES support.
}

/// Hex-encrypt a secret key with a password. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xencrypt(_secret: *mut c_char, _passwd: *mut c_char) -> c_int {
    0 // failure — no DES support
}

/// Hex-decrypt a secret key with a password. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdecrypt(_secret: *mut c_char, _passwd: *mut c_char) -> c_int {
    0 // failure — no DES support
}

/// Convert a password to a DES key. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn passwd2des(_passwd: *mut c_char, _key: *mut c_char) -> c_int {
    0 // failure — no DES support
}

// ===========================================================================
// RPC network identity and utility functions (18 symbols)
// ===========================================================================

/// Get the machine's IP address into a `struct sockaddr_in`.
/// Fills with INADDR_LOOPBACK (127.0.0.1) as a safe default.
/// In glibc this queries network interfaces; we use the loopback
/// address since RPC programs typically bind to it anyway.
///
/// # Safety
/// ABI boundary function. `addr` must point to a valid `struct sockaddr_in`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_myaddress(addr: *mut c_void) {
    if addr.is_null() {
        return;
    }
    // struct sockaddr_in layout: sin_family(u16) + sin_port(u16) + sin_addr(u32) + sin_zero(8)
    let sa: *mut libc::sockaddr_in = addr.cast();
    unsafe {
        (*sa).sin_family = libc::AF_INET as u16;
        (*sa).sin_port = 0;
        (*sa).sin_addr = libc::in_addr {
            s_addr: u32::to_be(0x7f000001), // 127.0.0.1 in network byte order
        };
        std::ptr::write_bytes((*sa).sin_zero.as_mut_ptr(), 0, 8);
    }
}

/// Get the netname for the current effective uid.
/// Format: "unix.<uid>@<domain>" — we use "localhost" as the domain.
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function. `name` must point to a buffer of at least MAXNETNAMELEN+1 (256) bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    if name.is_null() {
        return 0;
    }
    let uid = unsafe { libc::geteuid() };
    // Format: "unix.<uid>@localhost"
    let netname = format!("unix.{}@localhost\0", uid);
    let bytes = netname.as_bytes();
    // MAXNETNAMELEN is typically 255 in glibc
    if bytes.len() > 256 {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), name.cast(), bytes.len());
    }
    1
}

/// Get the public key for a netname from the publickey database.
/// Returns 0 (failure) — no publickey database support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpublickey(_netname: *const c_char, _publickey: *mut c_char) -> c_int {
    0 // Not found
}

/// Get the secret key for a netname from the publickey database.
/// Returns 0 (failure) — no publickey database support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsecretkey(
    _netname: *const c_char,
    _secretkey: *mut c_char,
    _passwd: *const c_char,
) -> c_int {
    0 // Not found
}

/// Get the port number for an RPC program on a remote host.
/// Returns 0 (not found) — portmapper queries not supported natively.
/// Programs needing real portmapper lookups will use clnt_create which
/// delegates to host glibc.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcport(
    _host: *const c_char,
    _prognum: c_ulong,
    _versnum: c_ulong,
    _proto: c_int,
) -> c_int {
    0 // Not found — no native portmapper support
}

/// Convert a hostname to a netname. Format: "unix.<host>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function. `netname` must point to a valid `*mut c_char` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn host2netname(
    netname: *mut *mut c_char,
    host: *const c_char,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() {
        return 0;
    }
    let host_str = if host.is_null() {
        "localhost"
    } else {
        match unsafe { std::ffi::CStr::from_ptr(host) }.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    let domain_str = if domain.is_null() {
        "localhost"
    } else {
        match unsafe { std::ffi::CStr::from_ptr(domain) }.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    let name = format!("unix.{}@{}\0", host_str, domain_str);
    let buf = unsafe { libc::malloc(name.len()) } as *mut c_char;
    if buf.is_null() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), name.len());
        *netname = buf;
    }
    1
}

/// Extract hostname from a netname. Format: "unix.<host>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(
    netname: *const c_char,
    hostname: *mut c_char,
    hostlen: c_int,
) -> c_int {
    if netname.is_null() || hostname.is_null() || hostlen <= 0 {
        return 0;
    }
    let name = match unsafe { std::ffi::CStr::from_ptr(netname) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    // Parse "unix.<host>@<domain>"
    let rest = match name.strip_prefix("unix.") {
        Some(r) => r,
        None => return 0,
    };
    let host = match rest.find('@') {
        Some(idx) => &rest[..idx],
        None => return 0,
    };
    if host.len() >= hostlen as usize {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(host.as_ptr(), hostname.cast(), host.len());
        *hostname.add(host.len()) = 0;
    }
    1
}

/// Extract user info from a netname. Format: "unix.<uid>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2user(
    netname: *const c_char,
    uidp: *mut c_ulong,
    gidp: *mut c_ulong,
    gidlenp: *mut c_int,
    _gidlist: *mut c_int,
) -> c_int {
    if netname.is_null() || uidp.is_null() || gidp.is_null() || gidlenp.is_null() {
        return 0;
    }
    let name = match unsafe { std::ffi::CStr::from_ptr(netname) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let rest = match name.strip_prefix("unix.") {
        Some(r) => r,
        None => return 0,
    };
    let uid_str = match rest.find('@') {
        Some(idx) => &rest[..idx],
        None => return 0,
    };
    let uid: u64 = match uid_str.parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    unsafe {
        *uidp = uid;
        *gidp = uid; // Default: gid = uid
        *gidlenp = 0; // No supplementary groups
    }
    1
}

/// Convert a uid to a netname. Format: "unix.<uid>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn user2netname(
    netname: *mut *mut c_char,
    uid: c_ulong,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() {
        return 0;
    }
    let domain_str = if domain.is_null() {
        "localhost"
    } else {
        match unsafe { std::ffi::CStr::from_ptr(domain) }.to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    let name = format!("unix.{}@{}\0", uid, domain_str);
    let buf = unsafe { libc::malloc(name.len()) } as *mut c_char;
    if buf.is_null() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), name.len());
        *netname = buf;
    }
    1
}

/// Get time from a remote time server (RFC 868). Returns -1 (failure).
/// Programs should use NTP or local clock instead of the legacy TIME protocol.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rtime(
    _addrp: *mut c_void,
    _timep: *mut c_void,
    _timeout: *mut c_void,
) -> c_int {
    -1 // Not supported — use local clock
}

/// Bind a socket to a reserved port (ports 512-1023).
/// Tries ports in the range until one succeeds. If `sin` is NULL,
/// creates a default AF_INET sockaddr_in. Returns 0 on success, -1 on failure.
///
/// # Safety
/// ABI boundary function. `sin` must be NULL or point to a valid `struct sockaddr_in`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport(sd: c_int, sin: *mut c_void) -> c_int {
    // Use a local sockaddr_in if none provided
    let mut local_sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let sa: *mut libc::sockaddr_in = if sin.is_null() {
        local_sin.sin_family = libc::AF_INET as u16;
        &mut local_sin
    } else {
        sin.cast()
    };

    // Try ports 512..1024 (reserved range per glibc convention)
    // Start from a "random" offset based on process ID for spread
    let pid = unsafe { libc::getpid() } as u16;
    let start = 600 + (pid % 424); // range [600, 1023]

    for i in 0..512 {
        let port = 512 + ((start as u32 + i as u32) % 512) as u16;
        unsafe {
            (*sa).sin_port = port.to_be();
        }
        let rc = unsafe {
            libc::bind(
                sd,
                (sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if rc == 0 {
            return 0;
        }
        // EADDRINUSE — try next port; other errors → fail
        let err = unsafe { *libc::__errno_location() };
        if err != libc::EADDRINUSE {
            return -1;
        }
    }
    // Exhausted all reserved ports
    unsafe { *libc::__errno_location() = libc::EADDRINUSE };
    -1
}

// --- rpc_createerr: this is a thread-local struct in glibc. The
//     __rpc_thread_createerr() accessor above returns a pointer to it.
//     Direct symbol interposition of the variable is not needed because
//     programs use the accessor or the linker resolves to glibc's copy. ---

// ===========================================================================
// pmap_getport with u16 return — specialized signature for portmapper
// The pmap_getport above already handles this with u16 return type.
// ===========================================================================

// ===========================================================================
// RPC global variable note
// ===========================================================================
//
// The following are global variables in glibc, NOT functions:
//   svc_fdset, svc_max_pollfd, svc_pollfd, _null_auth, rpc_createerr,
//   rexecoptions, svcauthdes_stats
//
// For LD_PRELOAD interposition these are automatically resolved from
// glibc's data segment. We do NOT re-export them here because:
// 1. Rust cannot reliably export mutable global C data with correct ABI
// 2. Programs link against glibc's copy directly
// 3. The __rpc_thread_* accessors above provide function-based access
//    to the thread-local variants where needed.
