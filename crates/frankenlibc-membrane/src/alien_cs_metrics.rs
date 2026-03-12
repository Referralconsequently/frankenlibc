//! Unified metrics and observation for Alien CS concurrency primitives.
//!
//! Aggregates diagnostics from RCU, SeqLock, EBR, and Flat Combining into
//! a single snapshot for observability. Provides contention tracking and
//! structured metric emission without requiring an external logging framework.
//!
//! # Design rationale
//!
//! The membrane crate operates at `#![deny(unsafe_code)]` and has no logging
//! dependency. Instead of adding one, this module provides a structured
//! `AlienCsSnapshot` that callers can serialize, log, or forward to OTLP
//! as appropriate for their context.

use crate::ebr::EbrDiagnostics;
use crate::flat_combining::FlatCombinerDiagnostics;
use crate::seqlock::SeqLockDiagnostics;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Unified diagnostics snapshot across all four Alien CS concepts.
#[derive(Debug, Clone)]
pub struct AlienCsSnapshot {
    /// Timestamp when this snapshot was captured (monotonic).
    pub captured_at_ns: u64,
    /// SeqLock metrics (if a SeqLock is being observed).
    pub seqlock: Option<SeqLockDiagnostics>,
    /// EBR metrics (if an EbrCollector is being observed).
    pub ebr: Option<EbrDiagnostics>,
    /// Flat Combining metrics (if a FlatCombiner is being observed).
    pub flat_combining: Option<FlatCombinerDiagnostics>,
    /// RCU metrics.
    pub rcu: Option<RcuMetrics>,
    /// Aggregate contention score (higher = more contention observed).
    pub contention_score: f64,
}

/// RCU-specific metrics (RcuCell doesn't have built-in diagnostics).
#[derive(Debug, Clone)]
pub struct RcuMetrics {
    /// Current epoch.
    pub epoch: u64,
    /// Number of readers currently active.
    pub reader_count: usize,
}

/// Metric event kinds for structured emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricEventKind {
    /// SeqLock cache miss (reader had to refresh).
    SeqLockCacheMiss,
    /// SeqLock write contention (writer waited for lock).
    SeqLockContention,
    /// EBR epoch advanced.
    EbrEpochAdvance,
    /// EBR items reclaimed.
    EbrReclaim,
    /// EBR grace period delayed (pinned threads blocking advance).
    EbrGracePeriodDelay,
    /// Flat Combining pass executed.
    FcCombiningPass,
    /// RCU update applied.
    RcuUpdate,
    /// RCU reader refreshed.
    RcuReaderRefresh,
}

/// A single metric event with structured fields.
#[derive(Debug, Clone)]
pub struct MetricEvent {
    /// What kind of event occurred.
    pub kind: MetricEventKind,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Optional numeric value (e.g., items reclaimed, batch size).
    pub value: u64,
    /// Optional concept identifier (e.g., "seqlock", "ebr").
    pub concept: &'static str,
}

/// Ring buffer for metric events (fixed capacity, overwrites oldest).
pub struct MetricRing {
    events: parking_lot::Mutex<Vec<MetricEvent>>,
    capacity: usize,
    total_emitted: AtomicU64,
    epoch_start: Instant,
}

impl MetricRing {
    /// Create a new metric ring with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            events: parking_lot::Mutex::new(Vec::with_capacity(capacity.min(4096))),
            capacity,
            total_emitted: AtomicU64::new(0),
            epoch_start: Instant::now(),
        }
    }

    /// Record a metric event.
    pub fn emit(&self, kind: MetricEventKind, value: u64, concept: &'static str) {
        let event = MetricEvent {
            kind,
            timestamp_ns: self.epoch_start.elapsed().as_nanos() as u64,
            value,
            concept,
        };

        let mut events = self.events.lock();
        if events.len() >= self.capacity {
            events.remove(0);
        }
        events.push(event);
        self.total_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Drain all events from the ring, returning them.
    pub fn drain(&self) -> Vec<MetricEvent> {
        let mut events = self.events.lock();
        events.drain(..).collect()
    }

    /// Get the current number of buffered events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Check if the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Total events ever emitted (including those overwritten).
    #[must_use]
    pub fn total_emitted(&self) -> u64 {
        self.total_emitted.load(Ordering::Relaxed)
    }

    /// Snapshot the current events without draining.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MetricEvent> {
        self.events.lock().clone()
    }

    /// Count events of a specific kind.
    #[must_use]
    pub fn count_by_kind(&self, kind: MetricEventKind) -> usize {
        self.events.lock().iter().filter(|e| e.kind == kind).count()
    }

    /// Count events for a specific concept.
    #[must_use]
    pub fn count_by_concept(&self, concept: &str) -> usize {
        self.events
            .lock()
            .iter()
            .filter(|e| e.concept == concept)
            .count()
    }
}

/// Compute a contention score from diagnostics.
///
/// Higher score means more contention was observed:
/// - SeqLock: ratio of cache misses to total reads
/// - EBR: pinned threads as fraction of active threads
/// - FC: inverse of batching efficiency (ops per pass)
pub fn compute_contention_score(
    seqlock: Option<&SeqLockDiagnostics>,
    ebr: Option<&EbrDiagnostics>,
    fc: Option<&FlatCombinerDiagnostics>,
) -> f64 {
    let mut score = 0.0;
    let mut components = 0;

    if let Some(sl) = seqlock {
        if sl.reads > 0 {
            // Cache miss ratio: 0.0 = no contention, 1.0 = every read missed.
            let miss_ratio = sl.cache_misses as f64 / sl.reads as f64;
            score += miss_ratio;
            components += 1;
        }
        if sl.writes > 0 {
            // Contention events per write.
            let contention_per_write = sl.contention_events as f64 / sl.writes as f64;
            score += contention_per_write.min(1.0);
            components += 1;
        }
    }

    if let Some(e) = ebr
        && e.active_threads > 0
    {
        let pinned_fraction = e.pinned_threads as f64 / e.active_threads as f64;
        score += pinned_fraction;
        components += 1;
    }

    if let Some(f) = fc
        && f.total_passes > 0
    {
        let ops_per_pass = f.total_ops as f64 / f.total_passes as f64;
        let efficiency_loss = 1.0 / ops_per_pass.max(1.0);
        score += efficiency_loss;
        components += 1;
    }

    if components > 0 {
        score / components as f64
    } else {
        0.0
    }
}

/// Build a unified snapshot from individual diagnostics.
pub fn build_snapshot(
    seqlock: Option<SeqLockDiagnostics>,
    ebr: Option<EbrDiagnostics>,
    fc: Option<FlatCombinerDiagnostics>,
    rcu: Option<RcuMetrics>,
    epoch_start: Instant,
) -> AlienCsSnapshot {
    let contention = compute_contention_score(
        seqlock.as_ref(),
        ebr.as_ref(),
        fc.as_ref(),
    );
    AlienCsSnapshot {
        captured_at_ns: epoch_start.elapsed().as_nanos() as u64,
        seqlock,
        ebr,
        flat_combining: fc,
        rcu,
        contention_score: contention,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebr::EbrCollector;
    use crate::flat_combining::FlatCombiner;
    use crate::rcu::RcuCell;
    use crate::seqlock::SeqLock;

    #[test]
    fn metric_ring_basic_lifecycle() {
        let ring = MetricRing::new(10);
        assert!(ring.is_empty());
        assert_eq!(ring.total_emitted(), 0);

        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 5, "ebr");

        assert_eq!(ring.len(), 2);
        assert_eq!(ring.total_emitted(), 2);
    }

    #[test]
    fn metric_ring_capacity_overflow() {
        let ring = MetricRing::new(3);

        for i in 0..5u64 {
            ring.emit(MetricEventKind::FcCombiningPass, i, "fc");
        }

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.total_emitted(), 5);

        // Oldest events should be evicted.
        let events = ring.snapshot();
        assert_eq!(events[0].value, 2); // 0 and 1 were evicted
        assert_eq!(events[1].value, 3);
        assert_eq!(events[2].value, 4);
    }

    #[test]
    fn metric_ring_drain() {
        let ring = MetricRing::new(10);
        ring.emit(MetricEventKind::RcuUpdate, 1, "rcu");
        ring.emit(MetricEventKind::RcuReaderRefresh, 2, "rcu");

        let drained = ring.drain();
        assert_eq!(drained.len(), 2);
        assert!(ring.is_empty());
        assert_eq!(ring.total_emitted(), 2); // total preserved
    }

    #[test]
    fn metric_ring_count_by_kind() {
        let ring = MetricRing::new(100);
        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 2, "ebr");
        ring.emit(MetricEventKind::SeqLockCacheMiss, 3, "seqlock");

        assert_eq!(ring.count_by_kind(MetricEventKind::SeqLockCacheMiss), 2);
        assert_eq!(ring.count_by_kind(MetricEventKind::EbrEpochAdvance), 1);
        assert_eq!(ring.count_by_kind(MetricEventKind::RcuUpdate), 0);
    }

    #[test]
    fn metric_ring_count_by_concept() {
        let ring = MetricRing::new(100);
        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 2, "ebr");
        ring.emit(MetricEventKind::SeqLockContention, 3, "seqlock");

        assert_eq!(ring.count_by_concept("seqlock"), 2);
        assert_eq!(ring.count_by_concept("ebr"), 1);
        assert_eq!(ring.count_by_concept("rcu"), 0);
    }

    #[test]
    fn contention_score_zero_when_no_data() {
        let score = compute_contention_score(None, None, None);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn contention_score_low_for_cached_reads() {
        let sl = SeqLock::new(42u64);
        let mut reader = crate::seqlock::SeqLockReader::new(&sl);
        // Read many times without writing → all cache hits.
        for _ in 0..100 {
            let _ = reader.read();
        }
        let diag = sl.diagnostics();
        let score = compute_contention_score(Some(&diag), None, None);
        // With 100 reads, 99 cache hits, 1 miss → low contention.
        assert!(score < 0.1, "expected low contention, got {}", score);
    }

    #[test]
    fn contention_score_higher_with_writes() {
        let sl = SeqLock::new(0u64);
        let mut reader = crate::seqlock::SeqLockReader::new(&sl);

        // Alternate read-write: every read misses cache.
        for i in 0..50u64 {
            sl.write_with(|d| *d = i);
            let _ = reader.read();
        }

        let diag = sl.diagnostics();
        let score = compute_contention_score(Some(&diag), None, None);
        // High miss ratio → higher contention score.
        assert!(score > 0.3, "expected moderate contention, got {}", score);
    }

    #[test]
    fn build_snapshot_aggregates_all_concepts() {
        let sl = SeqLock::new(0u64);
        sl.write_with(|d| *d = 1);
        let sl_diag = sl.diagnostics();

        let collector = EbrCollector::new();
        collector.retire(|| {});
        collector.try_advance();
        let ebr_diag = collector.diagnostics();

        let fc = FlatCombiner::new(0u64, 4);
        fc.execute(1u64, |s, o| {
            *s += o;
            *s
        });
        let fc_diag = fc.diagnostics();

        let cell = RcuCell::new(0u64);
        cell.update(1);
        let rcu = RcuMetrics {
            epoch: cell.epoch(),
            reader_count: cell.reader_count(),
        };

        let snap = build_snapshot(
            Some(sl_diag),
            Some(ebr_diag),
            Some(fc_diag),
            Some(rcu),
            Instant::now(),
        );

        assert!(snap.seqlock.is_some());
        assert!(snap.ebr.is_some());
        assert!(snap.flat_combining.is_some());
        assert!(snap.rcu.is_some());
        assert!(snap.contention_score >= 0.0);
    }

    #[test]
    fn metric_event_timestamps_monotonic() {
        let ring = MetricRing::new(100);
        for i in 0..20u64 {
            ring.emit(MetricEventKind::RcuUpdate, i, "rcu");
        }
        let events = ring.snapshot();
        for window in events.windows(2) {
            assert!(
                window[1].timestamp_ns >= window[0].timestamp_ns,
                "timestamps must be monotonic"
            );
        }
    }

    #[test]
    fn contention_score_fc_high_passes_low_batching() {
        // Simulate poor batching: many passes, few ops per pass.
        let fc_diag = FlatCombinerDiagnostics {
            total_ops: 100,
            total_passes: 100, // 1 op per pass = worst batching
            max_batch_size: 1,
            avg_batch_size: 1.0,
            active_slots: 1,
            total_slots: 4,
        };
        let score = compute_contention_score(None, None, Some(&fc_diag));
        // 1/1 = 1.0 efficiency loss → high contention.
        assert!(score > 0.5, "expected high contention, got {}", score);
    }
}
