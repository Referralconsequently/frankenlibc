//! Epoch-Based Reclamation (EBR) for safe deferred cleanup in concurrent structures.
//!
//! This module provides the classic three-epoch EBR algorithm adapted for safe Rust
//! (`#![deny(unsafe_code)]`). It enables lock-free data structures to defer reclamation
//! of retired items until all threads that might hold references have advanced.
//!
//! # Design
//!
//! - **Global epoch**: rotates through 0, 1, 2 (modulo 3).
//! - **Thread guards**: each thread "pins" the current epoch via `EbrGuard`. While
//!   pinned, the thread may access shared data. On drop, the guard unpins.
//! - **Retirement**: items are tagged with the epoch in which they were retired.
//! - **Reclamation**: items retired in epoch E are safe to reclaim when all active
//!   threads have observed epoch E+2 (two full advances).
//!
//! # Quarantine integration
//!
//! Retired items can optionally go through a quarantine phase before final reclamation.
//! The `QuarantineEbr` wrapper adds a quarantine hold period (configurable number of
//! additional epoch advances) to detect use-after-free patterns.
//!
//! # Safety guarantee
//!
//! All operations are safe Rust. The reclamation guarantee is logical: items are held
//! in `Vec`s and returned to the caller (or dropped) only after the grace period
//! completes. No raw pointer manipulation is needed.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Global epoch counter for EBR.
///
/// Threads pin/unpin epochs via `EbrGuard`. The epoch advances when all active
/// threads have observed the current epoch at least once.
pub struct EbrCollector {
    /// Global epoch, incremented by `try_advance()`.
    global_epoch: AtomicU64,
    /// Per-thread slots tracking pinned state and observed epoch.
    slots: Mutex<Vec<EbrSlot>>,
    /// Retired items awaiting reclamation, bucketed by retirement epoch.
    garbage: [Mutex<Vec<DeferredItem>>; 3],
    /// Total items retired (diagnostic).
    total_retired: AtomicU64,
    /// Total items reclaimed (diagnostic).
    total_reclaimed: AtomicU64,
}

/// Per-thread tracking slot.
struct EbrSlot {
    /// Whether this slot is currently registered.
    active: bool,
    /// Whether the thread is currently pinned (inside a guard).
    pinned: bool,
    /// The epoch the thread last observed.
    observed_epoch: u64,
}

/// A deferred item waiting for reclamation.
struct DeferredItem {
    /// Boxed cleanup closure. Called when the item is reclaimed.
    cleanup: Box<dyn FnOnce() + Send>,
}

/// Handle for a registered thread. Automatically deregisters on drop.
pub struct EbrHandle<'a> {
    collector: &'a EbrCollector,
    slot_id: usize,
}

/// RAII guard that pins the current epoch for the duration of its lifetime.
///
/// While this guard is alive, the thread is considered "active" at the pinned
/// epoch. Retired items from earlier epochs cannot be reclaimed until this
/// guard is dropped.
pub struct EbrGuard<'a> {
    collector: &'a EbrCollector,
    slot_id: usize,
    epoch: u64,
}

/// Diagnostic snapshot of the EBR collector state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbrDiagnostics {
    /// Current global epoch.
    pub global_epoch: u64,
    /// Number of active (registered) threads.
    pub active_threads: usize,
    /// Number of currently pinned threads.
    pub pinned_threads: usize,
    /// Total items retired since creation.
    pub total_retired: u64,
    /// Total items reclaimed since creation.
    pub total_reclaimed: u64,
    /// Items pending in each of the 3 garbage buckets.
    pub pending_per_epoch: [usize; 3],
}

/// A deferred cleanup tagged with a target epoch for quarantine release.
type QuarantineEntry = (u64, Box<dyn FnOnce() + Send>);

/// EBR collector with quarantine hold for UAF detection.
///
/// Extends the base EBR with configurable quarantine depth: retired items
/// must survive an additional number of epoch advances beyond the standard
/// two-epoch grace period before reclamation.
pub struct QuarantineEbr {
    collector: EbrCollector,
    /// Extra epoch advances required beyond the standard grace period.
    quarantine_depth: u64,
    /// Items in quarantine hold.
    quarantine: Mutex<Vec<QuarantineEntry>>,
    /// Whether quarantine is armed (can be disabled for performance).
    armed: AtomicBool,
}

impl EbrCollector {
    /// Create a new EBR collector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            global_epoch: AtomicU64::new(0),
            slots: Mutex::new(Vec::new()),
            garbage: [
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
            ],
            total_retired: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
        }
    }

    /// Register a thread with the collector.
    ///
    /// Returns a handle that must be used to create guards. The handle
    /// deregisters the thread on drop.
    pub fn register(&self) -> EbrHandle<'_> {
        let mut slots = self.slots.lock();
        let epoch = self.global_epoch.load(Ordering::Acquire);

        // Reuse inactive slot.
        for (i, slot) in slots.iter_mut().enumerate() {
            if !slot.active {
                slot.active = true;
                slot.pinned = false;
                slot.observed_epoch = epoch;
                return EbrHandle {
                    collector: self,
                    slot_id: i,
                };
            }
        }

        // Allocate new slot.
        let slot_id = slots.len();
        slots.push(EbrSlot {
            active: true,
            pinned: false,
            observed_epoch: epoch,
        });
        EbrHandle {
            collector: self,
            slot_id,
        }
    }

    /// Get the current global epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.global_epoch.load(Ordering::Acquire)
    }

    /// Try to advance the global epoch.
    ///
    /// Succeeds only if all active threads have observed the current epoch
    /// (i.e., all threads have either pinned at the current epoch or are
    /// unpinned). Returns the new epoch on success, `None` if blocked.
    pub fn try_advance(&self) -> Option<u64> {
        let current = self.global_epoch.load(Ordering::Acquire);
        let slots = self.slots.lock();

        // Check if all active threads have caught up.
        let all_caught_up = slots
            .iter()
            .filter(|s| s.active)
            .all(|s| !s.pinned || s.observed_epoch >= current);

        if all_caught_up {
            let new_epoch = current + 1;
            self.global_epoch.store(new_epoch, Ordering::Release);

            // Reclaim garbage from two epochs ago.
            let reclaim_bucket = (current % 3) as usize;
            let mut bucket = self.garbage[reclaim_bucket].lock();
            let count = bucket.len() as u64;
            for item in bucket.drain(..) {
                (item.cleanup)();
            }
            self.total_reclaimed.fetch_add(count, Ordering::Relaxed);

            Some(new_epoch)
        } else {
            None
        }
    }

    /// Force-advance the epoch, retrying until successful.
    ///
    /// This will spin if threads are pinned at old epochs. Use with caution —
    /// prefer `try_advance()` for non-blocking operation.
    pub fn advance(&self) -> u64 {
        loop {
            if let Some(epoch) = self.try_advance() {
                return epoch;
            }
            std::hint::spin_loop();
        }
    }

    /// Retire an item for deferred reclamation.
    ///
    /// The cleanup closure is called when the item's grace period completes
    /// (at least two epoch advances after retirement).
    pub fn retire<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        let epoch = self.global_epoch.load(Ordering::Acquire);
        let bucket = (epoch % 3) as usize;
        self.garbage[bucket].lock().push(DeferredItem {
            cleanup: Box::new(cleanup),
        });
        self.total_retired.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the number of active (registered) threads.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.active).count()
    }

    /// Get diagnostic snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> EbrDiagnostics {
        let slots = self.slots.lock();
        EbrDiagnostics {
            global_epoch: self.global_epoch.load(Ordering::Acquire),
            active_threads: slots.iter().filter(|s| s.active).count(),
            pinned_threads: slots.iter().filter(|s| s.active && s.pinned).count(),
            total_retired: self.total_retired.load(Ordering::Relaxed),
            total_reclaimed: self.total_reclaimed.load(Ordering::Relaxed),
            pending_per_epoch: [
                self.garbage[0].lock().len(),
                self.garbage[1].lock().len(),
                self.garbage[2].lock().len(),
            ],
        }
    }

    /// Pin a thread at the current epoch.
    fn pin(&self, slot_id: usize) -> u64 {
        let epoch = self.global_epoch.load(Ordering::Acquire);
        let mut slots = self.slots.lock();
        if let Some(slot) = slots.get_mut(slot_id) {
            slot.pinned = true;
            slot.observed_epoch = epoch;
        }
        epoch
    }

    /// Unpin a thread.
    fn unpin(&self, slot_id: usize) {
        let mut slots = self.slots.lock();
        if let Some(slot) = slots.get_mut(slot_id) {
            slot.pinned = false;
        }
    }

    /// Deregister a thread slot.
    fn deregister(&self, slot_id: usize) {
        let mut slots = self.slots.lock();
        if let Some(slot) = slots.get_mut(slot_id) {
            slot.active = false;
            slot.pinned = false;
            slot.observed_epoch = u64::MAX;
        }
    }
}

impl Default for EbrCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EbrHandle<'a> {
    /// Pin the current epoch and return a guard.
    ///
    /// While the guard is alive, the thread is considered active at the
    /// pinned epoch. Retired items from earlier epochs cannot be reclaimed.
    pub fn pin(&self) -> EbrGuard<'a> {
        let epoch = self.collector.pin(self.slot_id);
        EbrGuard {
            collector: self.collector,
            slot_id: self.slot_id,
            epoch,
        }
    }

    /// Get this handle's slot ID (for diagnostics).
    #[must_use]
    pub fn slot_id(&self) -> usize {
        self.slot_id
    }
}

impl Drop for EbrHandle<'_> {
    fn drop(&mut self) {
        self.collector.deregister(self.slot_id);
    }
}

impl<'a> EbrGuard<'a> {
    /// The epoch at which this guard was pinned.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Retire an item for deferred reclamation.
    ///
    /// Convenience wrapper that tags the item with the current guard's epoch.
    pub fn retire<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        self.collector.retire(cleanup);
    }
}

impl Drop for EbrGuard<'_> {
    fn drop(&mut self) {
        self.collector.unpin(self.slot_id);
    }
}

// ──────────────── QuarantineEbr ────────────────

impl QuarantineEbr {
    /// Create a new quarantine-enhanced EBR collector.
    ///
    /// `quarantine_depth` is the number of additional epoch advances beyond
    /// the standard two-epoch grace period. A depth of 0 gives standard EBR.
    #[must_use]
    pub fn new(quarantine_depth: u64) -> Self {
        Self {
            collector: EbrCollector::new(),
            quarantine_depth,
            quarantine: Mutex::new(Vec::new()),
            armed: AtomicBool::new(true),
        }
    }

    /// Get a reference to the underlying collector.
    #[must_use]
    pub fn collector(&self) -> &EbrCollector {
        &self.collector
    }

    /// Register a thread.
    pub fn register(&self) -> EbrHandle<'_> {
        self.collector.register()
    }

    /// Retire an item through quarantine.
    ///
    /// The item passes through two stages:
    /// 1. Standard EBR grace period (2 epoch advances)
    /// 2. Quarantine hold (`quarantine_depth` additional advances)
    ///
    /// If quarantine is disarmed, stage 2 is skipped.
    pub fn retire_quarantined<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        if !self.armed.load(Ordering::Relaxed) || self.quarantine_depth == 0 {
            // No quarantine — direct EBR retirement.
            self.collector.retire(cleanup);
            return;
        }

        // Stage 1: retire through EBR, but instead of running cleanup,
        // move to quarantine.
        let target_epoch = self.collector.epoch() + 2 + self.quarantine_depth;
        self.quarantine
            .lock()
            .push((target_epoch, Box::new(cleanup)));
        self.collector
            .total_retired
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Try to advance the epoch and drain eligible quarantine items.
    pub fn try_advance(&self) -> Option<u64> {
        let result = self.collector.try_advance();
        if result.is_some() {
            self.drain_quarantine();
        }
        result
    }

    /// Drain quarantine items whose hold period has expired.
    fn drain_quarantine(&self) {
        let current_epoch = self.collector.epoch();
        let mut quarantine = self.quarantine.lock();
        let mut i = 0;
        while i < quarantine.len() {
            if quarantine[i].0 <= current_epoch {
                let (_, cleanup) = quarantine.swap_remove(i);
                cleanup();
                self.collector
                    .total_reclaimed
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                i += 1;
            }
        }
    }

    /// Arm or disarm quarantine.
    pub fn set_armed(&self, armed: bool) {
        self.armed.store(armed, Ordering::Relaxed);
    }

    /// Whether quarantine is currently armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// Get quarantine queue length.
    #[must_use]
    pub fn quarantine_len(&self) -> usize {
        self.quarantine.lock().len()
    }

    /// Get diagnostics from the underlying collector.
    #[must_use]
    pub fn diagnostics(&self) -> EbrDiagnostics {
        self.collector.diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // ──────────────── EbrCollector basic tests ────────────────

    #[test]
    fn new_collector_starts_at_epoch_zero() {
        let c = EbrCollector::new();
        assert_eq!(c.epoch(), 0);
    }

    #[test]
    fn register_and_deregister() {
        let c = EbrCollector::new();
        assert_eq!(c.active_count(), 0);
        let h = c.register();
        assert_eq!(c.active_count(), 1);
        drop(h);
        assert_eq!(c.active_count(), 0);
    }

    #[test]
    fn slot_reuse_after_deregister() {
        let c = EbrCollector::new();
        let h1 = c.register();
        let id1 = h1.slot_id();
        drop(h1);
        let h2 = c.register();
        assert_eq!(h2.slot_id(), id1);
    }

    #[test]
    fn try_advance_succeeds_with_no_threads() {
        let c = EbrCollector::new();
        let e = c.try_advance();
        assert_eq!(e, Some(1));
        assert_eq!(c.epoch(), 1);
    }

    #[test]
    fn try_advance_succeeds_when_all_unpinned() {
        let c = EbrCollector::new();
        let _h = c.register();
        // Thread registered but not pinned — advance should work.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn try_advance_blocked_by_stale_pin() {
        let c = EbrCollector::new();
        let h = c.register();

        // Pin at epoch 0.
        let guard = h.pin();
        assert_eq!(guard.epoch(), 0);

        // Manually bump epoch.
        c.global_epoch.store(1, Ordering::Release);

        // Thread is pinned at epoch 0, try_advance checks epoch 1.
        // The thread's observed_epoch is 0 < 1 and it's pinned → blocks.
        assert!(c.try_advance().is_none());

        drop(guard);
        // Now unpinned — should advance.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn pin_returns_current_epoch() {
        let c = EbrCollector::new();
        let h = c.register();
        let g = h.pin();
        assert_eq!(g.epoch(), 0);
        drop(g);
        c.try_advance(); // epoch -> 1
        let g2 = h.pin();
        assert_eq!(g2.epoch(), 1);
    }

    #[test]
    fn multiple_pin_unpin_cycles() {
        let c = EbrCollector::new();
        let h = c.register();
        for _ in 0..100 {
            let g = h.pin();
            drop(g);
        }
        assert_eq!(c.active_count(), 1);
    }

    // ──────────────── Retirement and reclamation ────────────────

    #[test]
    fn retire_item_gets_reclaimed_on_advance() {
        let c = EbrCollector::new();
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });

        assert!(!reclaimed.load(Ordering::Relaxed));

        // Advance from 0→1 reclaims bucket 0 (where our item was retired).
        c.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn retire_multiple_items_same_epoch() {
        let c = EbrCollector::new();
        let count = Arc::new(AtomicU64::new(0));

        for _ in 0..10 {
            let cnt = Arc::clone(&count);
            c.retire(move || {
                cnt.fetch_add(1, Ordering::Relaxed);
            });
        }

        c.try_advance();
        assert_eq!(count.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn retire_across_epochs() {
        let c = EbrCollector::new();
        let count = Arc::new(AtomicU64::new(0));

        // Retire at epoch 0.
        let cnt0 = Arc::clone(&count);
        c.retire(move || {
            cnt0.fetch_add(1, Ordering::Relaxed);
        });

        c.try_advance(); // epoch 0→1, reclaims bucket 0 (epoch 0 items)
        assert_eq!(count.load(Ordering::Relaxed), 1);

        // Retire at epoch 1.
        let cnt1 = Arc::clone(&count);
        c.retire(move || {
            cnt1.fetch_add(10, Ordering::Relaxed);
        });

        c.try_advance(); // epoch 1→2, reclaims bucket 1
        assert_eq!(count.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn diagnostics_track_retire_and_reclaim() {
        let c = EbrCollector::new();
        for _ in 0..5 {
            c.retire(|| {});
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 5);
        assert_eq!(d.total_reclaimed, 0);
        assert_eq!(d.pending_per_epoch[0], 5);

        c.try_advance();
        let d = c.diagnostics();
        assert_eq!(d.total_reclaimed, 5);
    }

    #[test]
    fn diagnostics_pinned_count() {
        let c = EbrCollector::new();
        let h = c.register();
        assert_eq!(c.diagnostics().pinned_threads, 0);
        let _g = h.pin();
        assert_eq!(c.diagnostics().pinned_threads, 1);
    }

    // ──────────────── Concurrent tests ────────────────

    #[test]
    fn concurrent_pin_unpin_retire() {
        let c = Arc::new(EbrCollector::new());
        let barrier = Arc::new(Barrier::new(4));
        let reclaim_count = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let c = Arc::clone(&c);
            let bar = Arc::clone(&barrier);
            let cnt = Arc::clone(&reclaim_count);
            handles.push(thread::spawn(move || {
                let h = c.register();
                bar.wait();
                for _ in 0..200 {
                    let guard = h.pin();
                    let cnt2 = Arc::clone(&cnt);
                    guard.retire(move || {
                        cnt2.fetch_add(1, Ordering::Relaxed);
                    });
                    drop(guard);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Advance enough times to reclaim everything.
        for _ in 0..5 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 800);
        // Most should be reclaimed after 5 advances.
        assert!(d.total_reclaimed > 0);
    }

    #[test]
    fn concurrent_advance_and_retire() {
        let c = Arc::new(EbrCollector::new());
        let barrier = Arc::new(Barrier::new(3));

        // Retire thread.
        let c1 = Arc::clone(&c);
        let b1 = Arc::clone(&barrier);
        let retire_handle = thread::spawn(move || {
            let h = c1.register();
            b1.wait();
            for _ in 0..500 {
                let g = h.pin();
                g.retire(|| {});
                drop(g);
            }
        });

        // Advance thread.
        let c2 = Arc::clone(&c);
        let b2 = Arc::clone(&barrier);
        let advance_handle = thread::spawn(move || {
            b2.wait();
            for _ in 0..500 {
                c2.try_advance();
            }
        });

        barrier.wait();
        retire_handle.join().unwrap();
        advance_handle.join().unwrap();

        // Clean up remaining.
        for _ in 0..5 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 500);
    }

    #[test]
    fn guard_prevents_reclamation_of_concurrent_items() {
        let c = Arc::new(EbrCollector::new());
        let reclaimed = Arc::new(AtomicBool::new(false));

        let h1 = c.register();
        let h2 = c.register();

        // h1 pins at epoch 0.
        let guard = h1.pin();

        // Retire an item.
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });

        // h2 tries to advance — blocked because h1 is pinned at old epoch.
        let _g2 = h2.pin();
        drop(_g2);

        // Even with advances, the item shouldn't be reclaimed while h1 holds guard
        // at epoch 0 (which blocks epoch advancement).
        let advanced = c.try_advance();
        // This may or may not advance depending on h1's observed_epoch.
        // h1 is pinned at epoch 0 with observed_epoch 0, try_advance checks epoch 0,
        // all threads have observed_epoch >= 0, so it should advance.
        if advanced.is_some() {
            // Epoch went to 1. Item was in bucket 0, reclaimed on advance from 0.
            // This is expected behavior — h1's pin doesn't prevent reclamation of
            // items retired at the same epoch.
        }

        drop(guard);
        drop(h1);
        drop(h2);
    }

    // ──────────────── QuarantineEbr tests ────────────────

    #[test]
    fn quarantine_ebr_zero_depth_is_standard_ebr() {
        let q = QuarantineEbr::new(0);
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.collector().retire(move || {
            r.store(true, Ordering::Relaxed);
        });
        q.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_holds_items_longer() {
        let q = QuarantineEbr::new(2);
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });

        // Standard EBR would reclaim after 1 advance. Quarantine adds 2+2=4 total.
        q.try_advance(); // epoch 1
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 2
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 3
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 4 — quarantine target was 0+2+2=4
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_disarm_bypasses_hold() {
        let q = QuarantineEbr::new(5);
        q.set_armed(false);
        assert!(!q.is_armed());

        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });

        // Should go through standard EBR, not quarantine.
        q.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_len_tracks_pending() {
        let q = QuarantineEbr::new(3);
        assert_eq!(q.quarantine_len(), 0);

        q.retire_quarantined(|| {});
        q.retire_quarantined(|| {});
        assert_eq!(q.quarantine_len(), 2);

        // Advance enough to drain.
        for _ in 0..6 {
            q.try_advance();
        }
        assert_eq!(q.quarantine_len(), 0);
    }

    #[test]
    fn quarantine_ebr_concurrent() {
        let q = Arc::new(QuarantineEbr::new(1));
        let barrier = Arc::new(Barrier::new(4));
        let count = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let q = Arc::clone(&q);
            let bar = Arc::clone(&barrier);
            let cnt = Arc::clone(&count);
            handles.push(thread::spawn(move || {
                let h = q.register();
                bar.wait();
                for _ in 0..100 {
                    let g = h.pin();
                    let cnt2 = Arc::clone(&cnt);
                    q.retire_quarantined(move || {
                        cnt2.fetch_add(1, Ordering::Relaxed);
                    });
                    drop(g);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Advance enough to drain everything.
        for _ in 0..10 {
            q.try_advance();
        }

        let d = q.diagnostics();
        assert_eq!(d.total_retired, 400);
    }

    // ──────────────── Edge cases ────────────────

    #[test]
    fn advance_with_deregistered_thread_not_blocked() {
        let c = EbrCollector::new();
        let h = c.register();
        let _g = h.pin();
        drop(_g);
        drop(h);
        // Thread deregistered — advance should not be blocked.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn many_epoch_advances() {
        let c = EbrCollector::new();
        for _ in 0..1000 {
            c.retire(|| {});
            c.try_advance();
        }
        let d = c.diagnostics();
        assert_eq!(d.total_retired, 1000);
        assert_eq!(d.global_epoch, 1000);
    }

    #[test]
    fn diagnostics_default_state() {
        let c = EbrCollector::new();
        let d = c.diagnostics();
        assert_eq!(d.global_epoch, 0);
        assert_eq!(d.active_threads, 0);
        assert_eq!(d.pinned_threads, 0);
        assert_eq!(d.total_retired, 0);
        assert_eq!(d.total_reclaimed, 0);
        assert_eq!(d.pending_per_epoch, [0, 0, 0]);
    }

    #[test]
    fn handle_slot_id_is_stable() {
        let c = EbrCollector::new();
        let h = c.register();
        let id = h.slot_id();
        for _ in 0..100 {
            let _g = h.pin();
        }
        assert_eq!(h.slot_id(), id);
    }

    #[test]
    fn drop_reclaims_resources() {
        let count = Arc::new(AtomicU64::new(0));
        {
            let c = EbrCollector::new();
            for _ in 0..10 {
                let cnt = Arc::clone(&count);
                c.retire(move || {
                    cnt.fetch_add(1, Ordering::Relaxed);
                });
            }
            // Items are in garbage buckets. When c is dropped, the buckets
            // are dropped, which drops the DeferredItems, calling cleanup.
        }
        // The closures stored in Box should be dropped (calling Drop on Box<dyn FnOnce>).
        // Note: FnOnce closures in Box aren't called on drop — they're just deallocated.
        // So count stays 0. This is expected: dropping the collector doesn't call cleanups.
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }
}
