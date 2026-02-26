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

// --- Void serializer ---

rpc_delegate!(xdr_void() -> c_int);

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

rpc_delegate!(clnt_perrno(stat: c_int) -> ());
rpc_delegate!(clnt_perror(clnt: *mut c_void, s: *const c_char) -> ());
rpc_delegate!(clnt_pcreateerror(s: *const c_char) -> ());
rpc_delegate!(clnt_sperrno(stat: c_int) -> *mut c_char);
rpc_delegate!(clnt_sperror(clnt: *mut c_void, s: *const c_char) -> *mut c_char);
rpc_delegate!(clnt_spcreateerror(s: *const c_char) -> *mut c_char);

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

rpc_delegate!(_rpc_dtablesize() -> c_int);

// --- Thread-local RPC state accessors ---

rpc_delegate!(__rpc_thread_createerr() -> *mut c_void);
rpc_delegate!(__rpc_thread_svc_fdset() -> *mut c_void);
rpc_delegate!(__rpc_thread_svc_max_pollfd() -> *mut c_void);
rpc_delegate!(__rpc_thread_svc_pollfd() -> *mut c_void);

// --- _seterr_reply ---

rpc_delegate!(_seterr_reply(msg: *mut c_void, error: *mut c_void) -> ());

// --- _null_auth: this is a global variable in glibc, we export a function
//     that fetches its address from the host. Programs typically access it
//     directly; for LD_PRELOAD interposition we provide a function-based
//     accessor. The linker symbol is handled separately in the version script. ---

// ===========================================================================
// Key management / Secure RPC (16+ symbols)
// ===========================================================================

rpc_delegate!(key_decryptsession(
    remotename: *const c_char,
    deskey: *mut c_void
) -> c_int);

rpc_delegate!(key_decryptsession_pk(
    remotename: *const c_char,
    remotekey: *mut c_void,
    deskey: *mut c_void
) -> c_int);

rpc_delegate!(key_encryptsession(
    remotename: *const c_char,
    deskey: *mut c_void
) -> c_int);

rpc_delegate!(key_encryptsession_pk(
    remotename: *const c_char,
    remotekey: *mut c_void,
    deskey: *mut c_void
) -> c_int);

rpc_delegate!(key_gendes(deskey: *mut c_void) -> c_int);
rpc_delegate!(key_get_conv(pkey: *mut c_char, deskey: *mut c_void) -> c_int);
rpc_delegate!(key_secretkey_is_set() -> c_int);

rpc_delegate!(key_setnet(
    arg: *mut c_void
) -> c_int);

rpc_delegate!(key_setsecret(secretkey: *const c_char) -> c_int);

// --- Internal key function pointer globals ---
// In glibc these are `int (*__key_*_LOCAL)(...)` global function pointers.
// We export them as mutable static AtomicPtrs so programs and libraries
// can read/write them. Initialized to null (no keyserv client installed).

use std::sync::atomic::AtomicPtr;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_decryptsession_pk_LOCAL: AtomicPtr<c_void> =
    AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_encryptsession_pk_LOCAL: AtomicPtr<c_void> =
    AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_gendes_LOCAL: AtomicPtr<c_void> =
    AtomicPtr::new(std::ptr::null_mut());

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
// DES crypt helpers (6 symbols)
// ===========================================================================

rpc_delegate!(cbc_crypt(
    key: *mut c_char,
    buf: *mut c_char,
    len: c_uint,
    mode: c_uint,
    ivec: *mut c_char
) -> c_int);

rpc_delegate!(ecb_crypt(
    key: *mut c_char,
    buf: *mut c_char,
    len: c_uint,
    mode: c_uint
) -> c_int);

rpc_delegate!(des_setparity(key: *mut c_char) -> ());

rpc_delegate!(xencrypt(secret: *mut c_char, passwd: *mut c_char) -> c_int);
rpc_delegate!(xdecrypt(secret: *mut c_char, passwd: *mut c_char) -> c_int);
rpc_delegate!(passwd2des(passwd: *mut c_char, key: *mut c_char) -> c_int);

// ===========================================================================
// RPC network identity and utility functions (18 symbols)
// ===========================================================================

rpc_delegate!(get_myaddress(addr: *mut c_void) -> ());

rpc_delegate!(getnetname(name: *mut c_char) -> c_int);

rpc_delegate!(getpublickey(
    netname: *const c_char,
    publickey: *mut c_char
) -> c_int);

rpc_delegate!(getsecretkey(
    netname: *const c_char,
    secretkey: *mut c_char,
    passwd: *const c_char
) -> c_int);

rpc_delegate!(getrpcport(
    host: *const c_char,
    prognum: c_ulong,
    versnum: c_ulong,
    proto: c_int
) -> c_int);

rpc_delegate!(host2netname(
    netname: *mut *mut c_char,
    host: *const c_char,
    domain: *const c_char
) -> c_int);

rpc_delegate!(netname2host(
    netname: *const c_char,
    hostname: *mut c_char,
    hostlen: c_int
) -> c_int);

rpc_delegate!(netname2user(
    netname: *const c_char,
    uidp: *mut c_ulong,
    gidp: *mut c_ulong,
    gidlenp: *mut c_int,
    gidlist: *mut c_int
) -> c_int);

rpc_delegate!(user2netname(
    netname: *mut *mut c_char,
    uid: c_ulong,
    domain: *const c_char
) -> c_int);

rpc_delegate!(rtime(
    addrp: *mut c_void,
    timep: *mut c_void,
    timeout: *mut c_void
) -> c_int);

rpc_delegate!(bindresvport(
    sd: c_int,
    sin: *mut c_void
) -> c_int);

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
