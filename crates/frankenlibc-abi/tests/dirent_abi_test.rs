#![cfg(target_os = "linux")]

//! Integration tests for `<dirent.h>` ABI entrypoints.
//!
//! Tests cover: opendir/readdir/closedir, seekdir/telldir/rewinddir,
//! readdir_r, readdir64, alphasort, versionsort, scandir,
//! fdopendir, dirfd.

use std::collections::HashSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicU32, Ordering};

use frankenlibc_abi::dirent_abi::*;

// ===========================================================================
// Helpers
// ===========================================================================

static TEST_DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Create a unique temporary directory with known files.
fn make_test_dir() -> (CString, String) {
    let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base = format!("/tmp/franken_dirent_{}_{}", pid, id);
    let path = CString::new(base.as_str()).unwrap();
    unsafe {
        libc::mkdir(path.as_ptr(), 0o755);
    }
    for name in &["aaa.txt", "bbb.txt", "ccc.txt"] {
        let full = format!("{}/{}\0", base, name);
        let fd =
            unsafe { libc::open(full.as_ptr().cast(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    (path, base)
}

fn cleanup_test_dir(base: &str) {
    for name in &["aaa.txt", "bbb.txt", "ccc.txt"] {
        let full = format!("{}/{}\0", base, name);
        unsafe { libc::unlink(full.as_ptr().cast()) };
    }
    let path = CString::new(base).unwrap();
    unsafe { libc::rmdir(path.as_ptr()) };
}

/// Read all entry names from a DIR stream.
unsafe fn collect_names(dirp: *mut DIR) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        names.push(name.to_str().unwrap().to_string());
    }
    names
}

// ===========================================================================
// opendir / readdir / closedir
// ===========================================================================

#[test]
fn opendir_readdir_closedir_basic() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null(), "opendir should succeed");

    let names = unsafe { collect_names(dirp) };
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"aaa.txt".to_string()));
    assert!(names.contains(&"bbb.txt".to_string()));
    assert!(names.contains(&"ccc.txt".to_string()));

    let rc = unsafe { closedir(dirp) };
    assert_eq!(rc, 0);
    cleanup_test_dir(&base);
}

#[test]
fn opendir_null_returns_null() {
    let dirp = unsafe { opendir(std::ptr::null()) };
    assert!(dirp.is_null());
}

#[test]
fn opendir_nonexistent_returns_null() {
    let path = CString::new("/tmp/nonexistent_dir_12345").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(dirp.is_null());
}

#[test]
fn readdir_returns_null_after_exhaustion() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    loop {
        let ent = unsafe { readdir(dirp) };
        if ent.is_null() {
            break;
        }
    }
    let ent = unsafe { readdir(dirp) };
    assert!(ent.is_null());

    unsafe { closedir(dirp) };
}

// ===========================================================================
// seekdir / telldir / rewinddir
// ===========================================================================

#[test]
fn telldir_and_seekdir_roundtrip() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let ent1 = unsafe { readdir(dirp) };
    assert!(!ent1.is_null());
    let pos = unsafe { telldir(dirp) };

    let ent2 = unsafe { readdir(dirp) };
    assert!(!ent2.is_null());
    let name2 = unsafe { CStr::from_ptr((*ent2).d_name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string();

    unsafe { seekdir(dirp, pos) };

    let ent_after_seek = unsafe { readdir(dirp) };
    assert!(!ent_after_seek.is_null());
    let name_after = unsafe { CStr::from_ptr((*ent_after_seek).d_name.as_ptr()) }
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(name2, name_after, "seekdir should restore position");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

#[test]
fn rewinddir_restarts() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let names1 = unsafe { collect_names(dirp) };
    assert!(!names1.is_empty());

    unsafe { rewinddir(dirp) };
    let names2 = unsafe { collect_names(dirp) };

    let set1: HashSet<_> = names1.into_iter().collect();
    let set2: HashSet<_> = names2.into_iter().collect();
    assert_eq!(set1, set2, "rewinddir should produce same entries");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// readdir_r (reentrant)
// ===========================================================================

#[test]
fn readdir_r_basic() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::dirent = std::ptr::null_mut();

    let rc = unsafe { readdir_r(dirp, &mut entry, &mut result) };
    assert_eq!(rc, 0, "readdir_r should succeed");
    assert!(!result.is_null(), "result should be set");

    let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
    assert!(!name.to_str().unwrap().is_empty());

    unsafe { closedir(dirp) };
}

#[test]
fn readdir_r_exhaustion() {
    let (path, base) = make_test_dir();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let mut count = 0;
    loop {
        let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::dirent = std::ptr::null_mut();
        let rc = unsafe { readdir_r(dirp, &mut entry, &mut result) };
        if rc != 0 || result.is_null() {
            break;
        }
        count += 1;
    }
    assert!(count >= 5, "should read at least 5 entries, got {count}");

    unsafe { closedir(dirp) };
    cleanup_test_dir(&base);
}

// ===========================================================================
// readdir64
// ===========================================================================

#[test]
fn readdir64_basic() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let ent = unsafe { readdir64(dirp) };
    assert!(!ent.is_null(), "readdir64 should return an entry");

    unsafe { closedir(dirp) };
}

// ===========================================================================
// alphasort / versionsort
// ===========================================================================

#[test]
fn alphasort_ordering() {
    let mut a: libc::dirent = unsafe { std::mem::zeroed() };
    let mut b: libc::dirent = unsafe { std::mem::zeroed() };

    let name_a = b"apple\0";
    let name_b = b"banana\0";
    a.d_name[..name_a.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_a.as_ptr().cast(), name_a.len())
    });
    b.d_name[..name_b.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_b.as_ptr().cast(), name_b.len())
    });

    let mut pa: *const c_void = (&a as *const libc::dirent).cast();
    let mut pb: *const c_void = (&b as *const libc::dirent).cast();

    let cmp = unsafe {
        alphasort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pb as *mut *const c_void).cast(),
        )
    };
    assert!(cmp < 0, "apple should sort before banana");

    let cmp2 = unsafe {
        alphasort(
            (&mut pb as *mut *const c_void).cast(),
            (&mut pa as *mut *const c_void).cast(),
        )
    };
    assert!(cmp2 > 0, "banana should sort after apple");

    let cmp3 = unsafe {
        alphasort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pa as *mut *const c_void).cast(),
        )
    };
    assert_eq!(cmp3, 0, "same name should compare equal");
}

#[test]
fn versionsort_ordering() {
    let mut a: libc::dirent = unsafe { std::mem::zeroed() };
    let mut b: libc::dirent = unsafe { std::mem::zeroed() };

    let name_a = b"file2\0";
    let name_b = b"file10\0";
    a.d_name[..name_a.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_a.as_ptr().cast(), name_a.len())
    });
    b.d_name[..name_b.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_b.as_ptr().cast(), name_b.len())
    });

    let mut pa: *const c_void = (&a as *const libc::dirent).cast();
    let mut pb: *const c_void = (&b as *const libc::dirent).cast();

    let cmp = unsafe {
        versionsort(
            (&mut pa as *mut *const c_void).cast(),
            (&mut pb as *mut *const c_void).cast(),
        )
    };
    assert!(cmp < 0, "file2 should sort before file10 in version sort");
}

// ===========================================================================
// scandir — allocates with our malloc_abi, so call count only (no free)
// ===========================================================================

#[test]
fn scandir_returns_entries() {
    let (path, base) = make_test_dir();
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();

    let n = unsafe { scandir(path.as_ptr(), &mut namelist, None, None) };
    assert!(n >= 5, "scandir should find at least 5 entries (got {n})");
    assert!(!namelist.is_null());

    // Note: entries allocated with our malloc_abi; just leak in test to avoid
    // allocator mismatch issues. The OS reclaims on process exit.
    cleanup_test_dir(&base);
}

#[test]
fn scandir_nonexistent_fails() {
    let path = CString::new("/tmp/no_such_scandir_dir_99999").unwrap();
    let mut namelist: *mut *mut libc::dirent = std::ptr::null_mut();
    let n = unsafe { scandir(path.as_ptr(), &mut namelist, None, None) };
    assert_eq!(n, -1, "scandir on nonexistent dir should return -1");
}

// ===========================================================================
// fdopendir / dirfd
// ===========================================================================

#[test]
fn fdopendir_and_dirfd() {
    let (path, base) = make_test_dir();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0, "open directory should succeed");

    let dirp = unsafe { fdopendir(fd) };
    assert!(!dirp.is_null(), "fdopendir should succeed");

    let got_fd = unsafe { dirfd(dirp.cast()) };
    assert!(got_fd >= 0, "dirfd should return valid fd");

    // Use our closedir (not libc::closedir) since fdopendir returns our handle
    unsafe { closedir(dirp.cast()) };
    cleanup_test_dir(&base);
}

#[test]
fn dirfd_from_opendir() {
    let path = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { opendir(path.as_ptr()) };
    assert!(!dirp.is_null());

    let fd = unsafe { dirfd(dirp.cast()) };
    assert!(fd >= 0, "dirfd should return non-negative fd");

    unsafe { closedir(dirp) };
}

// ===========================================================================
// Null safety
// ===========================================================================

#[test]
fn closedir_null_returns_error() {
    let rc = unsafe { closedir(std::ptr::null_mut()) };
    assert_eq!(rc, -1);
}

#[test]
fn readdir_null_returns_null() {
    let ent = unsafe { readdir(std::ptr::null_mut()) };
    assert!(ent.is_null());
}
