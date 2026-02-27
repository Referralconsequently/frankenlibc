#![cfg(target_os = "linux")]

//! Integration tests for `<search.h>` ABI entrypoints.
//!
//! Tests cover: hash tables (hcreate/hsearch/hdestroy + reentrant),
//! binary trees (tsearch/tfind/tdelete/twalk), linear search (lfind/lsearch),
//! and linked lists (insque/remque).

use std::ffi::{CString, c_int, c_void};

use frankenlibc_abi::search_abi::*;

// ===========================================================================
// Hash table: hcreate / hsearch / hdestroy
// ===========================================================================

#[test]
fn hash_create_and_destroy() {
    let rc = unsafe { hcreate(16) };
    assert_eq!(rc, 1, "hcreate should succeed");
    unsafe { hdestroy() };
}

#[test]
fn hash_insert_and_find() {
    unsafe { hcreate(16) };

    let key = CString::new("testkey").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: 42usize as *mut c_void,
    };

    let result = unsafe { hsearch(item, Action::ENTER) };
    assert!(!result.is_null(), "ENTER should succeed");

    let found = unsafe { hsearch(item, Action::FIND) };
    assert!(!found.is_null(), "FIND should locate inserted key");
    assert_eq!(unsafe { (*found).data } as usize, 42);

    unsafe { hdestroy() };
}

#[test]
fn hash_find_nonexistent_returns_null() {
    unsafe { hcreate(16) };

    let key = CString::new("missing").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: std::ptr::null_mut(),
    };

    let found = unsafe { hsearch(item, Action::FIND) };
    assert!(found.is_null(), "FIND on missing key should return null");

    unsafe { hdestroy() };
}

#[test]
fn hash_multiple_entries() {
    unsafe { hcreate(64) };

    let keys: Vec<CString> = (0..10)
        .map(|i| CString::new(format!("key{i}")).unwrap())
        .collect();

    for (i, key) in keys.iter().enumerate() {
        let item = Entry {
            key: key.as_ptr() as *mut _,
            data: (i + 100) as *mut c_void,
        };
        let result = unsafe { hsearch(item, Action::ENTER) };
        assert!(!result.is_null(), "ENTER key{i} should succeed");
    }

    for (i, key) in keys.iter().enumerate() {
        let item = Entry {
            key: key.as_ptr() as *mut _,
            data: std::ptr::null_mut(),
        };
        let found = unsafe { hsearch(item, Action::FIND) };
        assert!(!found.is_null(), "FIND key{i} should succeed");
        assert_eq!(unsafe { (*found).data } as usize, i + 100);
    }

    unsafe { hdestroy() };
}

// ===========================================================================
// Reentrant hash table: hcreate_r / hsearch_r / hdestroy_r
// ===========================================================================

#[test]
fn hash_reentrant_lifecycle() {
    // POSIX: callers zero-initialize hsearch_data before hcreate_r
    let mut htab: HsearchData = unsafe { std::mem::zeroed() };

    let rc = unsafe { hcreate_r(16, &mut htab) };
    assert_eq!(rc, 1, "hcreate_r should succeed");

    let key = CString::new("rkey").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: 99usize as *mut c_void,
    };

    let mut result: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::ENTER, &mut result, &mut htab) };
    assert_eq!(rc, 1);
    assert!(!result.is_null());

    let mut found: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::FIND, &mut found, &mut htab) };
    assert_eq!(rc, 1);
    assert!(!found.is_null());
    assert_eq!(unsafe { (*found).data } as usize, 99);

    unsafe { hdestroy_r(&mut htab) };
}

#[test]
fn hash_reentrant_null_safety() {
    let rc = unsafe { hcreate_r(16, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "hcreate_r with null htab should fail");

    unsafe { hdestroy_r(std::ptr::null_mut()) };
    // Should not crash
}

// ===========================================================================
// Binary tree: tsearch / tfind / tdelete / twalk
// ===========================================================================

/// Integer comparison function for tree operations.
unsafe extern "C" fn int_compare(a: *const c_void, b: *const c_void) -> c_int {
    let va = a as usize as i64;
    let vb = b as usize as i64;
    if va < vb {
        -1
    } else if va > vb {
        1
    } else {
        0
    }
}

#[test]
fn tree_insert_and_find() {
    let mut root: *mut c_void = std::ptr::null_mut();

    // Insert values 5, 3, 7
    let r1 = unsafe { tsearch(5usize as *const c_void, &mut root, int_compare) };
    assert!(!r1.is_null(), "tsearch(5) should succeed");
    assert!(!root.is_null(), "root should be set after insert");

    let r2 = unsafe { tsearch(3usize as *const c_void, &mut root, int_compare) };
    assert!(!r2.is_null(), "tsearch(3) should succeed");

    let r3 = unsafe { tsearch(7usize as *const c_void, &mut root, int_compare) };
    assert!(!r3.is_null(), "tsearch(7) should succeed");

    // Find existing
    let found = unsafe { tfind(5usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found.is_null(), "tfind(5) should find it");

    let found3 = unsafe { tfind(3usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found3.is_null(), "tfind(3) should find it");

    // Find non-existing
    let missing = unsafe { tfind(99usize as *const c_void, &root as *const _, int_compare) };
    assert!(missing.is_null(), "tfind(99) should return null");

    // Cleanup: delete all nodes
    unsafe {
        tdelete(5usize as *const c_void, &mut root, int_compare);
        tdelete(3usize as *const c_void, &mut root, int_compare);
        tdelete(7usize as *const c_void, &mut root, int_compare);
    }
}

#[test]
fn tree_delete() {
    let mut root: *mut c_void = std::ptr::null_mut();

    unsafe {
        tsearch(10usize as *const c_void, &mut root, int_compare);
        tsearch(5usize as *const c_void, &mut root, int_compare);
        tsearch(15usize as *const c_void, &mut root, int_compare);
    }

    // Delete leaf node
    let result = unsafe { tdelete(5usize as *const c_void, &mut root, int_compare) };
    assert!(!result.is_null(), "tdelete(5) should succeed");

    let missing = unsafe { tfind(5usize as *const c_void, &root as *const _, int_compare) };
    assert!(missing.is_null(), "5 should be gone after delete");

    // 10 and 15 still there
    let found10 = unsafe { tfind(10usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found10.is_null(), "10 should still exist");

    // Cleanup
    unsafe {
        tdelete(15usize as *const c_void, &mut root, int_compare);
        tdelete(10usize as *const c_void, &mut root, int_compare);
    }
}

#[test]
fn tree_null_safety() {
    let key = std::ptr::dangling::<c_void>();
    let result = unsafe { tsearch(key, std::ptr::null_mut(), int_compare) };
    assert!(
        result.is_null(),
        "tsearch with null rootp should return null"
    );

    let result = unsafe { tfind(key, std::ptr::null(), int_compare) };
    assert!(result.is_null(), "tfind with null rootp should return null");
}

use std::sync::atomic::{AtomicU32, Ordering};

static WALK_COUNT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn walk_counter(_node: *const c_void, _visit: Visit, _level: c_int) {
    WALK_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn tree_walk() {
    let mut root: *mut c_void = std::ptr::null_mut();

    unsafe {
        tsearch(10usize as *const c_void, &mut root, int_compare);
        tsearch(5usize as *const c_void, &mut root, int_compare);
        tsearch(15usize as *const c_void, &mut root, int_compare);
    }

    WALK_COUNT.store(0, Ordering::Relaxed);
    unsafe { twalk(root, walk_counter) };

    let count = WALK_COUNT.load(Ordering::Relaxed);
    // Root (10) has two children: preorder + postorder + endorder = 3
    // Left (5) is leaf = 1
    // Right (15) is leaf = 1
    // Total = 5
    assert_eq!(count, 5, "walk should visit root 3 times + 2 leaves");

    // Cleanup
    unsafe {
        tdelete(5usize as *const c_void, &mut root, int_compare);
        tdelete(15usize as *const c_void, &mut root, int_compare);
        tdelete(10usize as *const c_void, &mut root, int_compare);
    }
}

// ===========================================================================
// Linear search: lfind / lsearch
// ===========================================================================

unsafe extern "C" fn int_array_compare(a: *const c_void, b: *const c_void) -> c_int {
    let va = unsafe { *(a as *const i32) };
    let vb = unsafe { *(b as *const i32) };
    if va == vb { 0 } else { 1 }
}

#[test]
fn lfind_existing() {
    let arr: [i32; 5] = [10, 20, 30, 40, 50];
    let mut nel: usize = 5;
    let key: i32 = 30;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lfind should find 30");
    assert_eq!(unsafe { *(result as *const i32) }, 30);
}

#[test]
fn lfind_missing() {
    let arr: [i32; 5] = [10, 20, 30, 40, 50];
    let mut nel: usize = 5;
    let key: i32 = 99;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(result.is_null(), "lfind should not find 99");
}

#[test]
fn lsearch_inserts_missing() {
    let mut arr: [i32; 8] = [10, 20, 30, 0, 0, 0, 0, 0];
    let mut nel: usize = 3;
    let key: i32 = 25;

    let result = unsafe {
        lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lsearch should return new element");
    assert_eq!(nel, 4, "count should increase");
    assert_eq!(arr[3], 25, "new element should be appended");
}

#[test]
fn lsearch_finds_existing() {
    let mut arr: [i32; 8] = [10, 20, 30, 0, 0, 0, 0, 0];
    let mut nel: usize = 3;
    let key: i32 = 20;

    let result = unsafe {
        lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lsearch should find existing");
    assert_eq!(nel, 3, "count should NOT increase");
    assert_eq!(unsafe { *(result as *const i32) }, 20);
}

#[test]
fn lfind_null_safety() {
    let mut nel: usize = 0;
    let result = unsafe {
        lfind(
            std::ptr::null(),
            std::ptr::null(),
            &mut nel,
            4,
            int_array_compare,
        )
    };
    assert!(result.is_null());
}

// ===========================================================================
// Linked list: insque / remque
// ===========================================================================

#[repr(C)]
struct QueueNode {
    next: *mut QueueNode,
    prev: *mut QueueNode,
    value: i32,
}

impl QueueNode {
    fn new(value: i32) -> Self {
        QueueNode {
            next: std::ptr::null_mut(),
            prev: std::ptr::null_mut(),
            value,
        }
    }
}

#[test]
fn insque_single_element() {
    let mut node = QueueNode::new(1);
    unsafe {
        insque(
            &mut node as *mut QueueNode as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    assert!(node.next.is_null());
    assert!(node.prev.is_null());
}

#[test]
fn insque_chain() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);
    let mut c = QueueNode::new(3);

    // Build chain: a -> b -> c
    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
        insque(
            &mut c as *mut _ as *mut c_void,
            &mut b as *mut _ as *mut c_void,
        );
    }

    assert_eq!(a.next, &mut b as *mut _);
    assert_eq!(b.prev, &mut a as *mut _);
    assert_eq!(b.next, &mut c as *mut _);
    assert_eq!(c.prev, &mut b as *mut _);
    assert!(c.next.is_null());
}

#[test]
fn remque_middle() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);
    let mut c = QueueNode::new(3);

    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
        insque(
            &mut c as *mut _ as *mut c_void,
            &mut b as *mut _ as *mut c_void,
        );
    }

    // Remove b from the middle
    unsafe { remque(&mut b as *mut _ as *mut c_void) };

    assert_eq!(a.next, &mut c as *mut _);
    assert_eq!(c.prev, &mut a as *mut _);
    assert!(b.next.is_null());
    assert!(b.prev.is_null());
}

#[test]
fn remque_null_safety() {
    unsafe { remque(std::ptr::null_mut()) };
    // Should not crash
}
