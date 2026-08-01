//! Anti-replay: a per-sender sliding window over authenticated counters.
//!
//! ## Why the msg_id dedup cache is not enough
//!
//! `MeshCore` keeps a 4096-entry LRU of recently seen message ids. That stops
//! flood loops — the same frame arriving from three neighbours at once — but it
//! is bounded, so an attacker who captures a frame and replays it after 4096
//! other messages have gone by gets a second delivery. In a busy room that is
//! seconds, not days.
//!
//! This window closes that: every sender stamps each frame with a monotonic
//! `counter` inside a `epoch`, both **inside the AEAD's AAD**. A forged or
//! rewritten counter fails authentication, so by the time we consult the window
//! the numbers are known to be the sender's own.
//!
//! ## Ordering matters
//!
//! The window must be consulted **after** the AEAD verifies, never before.
//! Checking first would let an attacker spray forged high counters and poison
//! the window, locking out the real sender — turning a replay defence into a
//! denial of service.
//!
//! ## Epochs, and the caveat
//!
//! BLE is lossy and unordered, so a strict `counter > last` rule would drop
//! legitimately reordered frames. Instead we keep the highest counter seen plus
//! a 64-bit bitmap of the window below it — the same shape as IPsec's
//! anti-replay window (RFC 4303 §3.4.3).
//!
//! A restarting node resets its counter to zero, which would look exactly like
//! a replay. `epoch` disambiguates: it is the sender's session identifier, and
//! a higher epoch resets the window. We derive it from the wall clock at core
//! creation, so it increases across restarts *provided the clock does not go
//! backwards*. That is the known weakness — a device whose clock rolls back
//! (manual change, RTC reset on a dead battery) emits frames its peers reject
//! until it restarts with a good clock. The proper fix is a boot counter
//! persisted alongside the identity seed, which is one `u64` in the same
//! Keychain/Keystore blob; see ARCHITECTURE.md §9.

/// Width of the reorder tolerance, in frames. 64 is one `u64` of bitmap and
/// comfortably more than BLE reordering produces in practice.
pub const WINDOW: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Fresh. The window has been advanced to include this counter.
    Fresh,
    /// From a session older than the one we have seen from this sender.
    StaleEpoch,
    /// Older than the window can vouch for; indistinguishable from a replay.
    TooOld,
    /// Already delivered in this session.
    Duplicate,
}

/// One sender's replay state. 24 bytes, so a thousand peers cost ~24 KB.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    epoch: u64,
    /// Highest counter accepted so far; the top edge of the window.
    highest: u64,
    /// Bit `i` set means `highest - i` has been seen. Bit 0 is `highest`.
    bitmap: u64,
}

impl ReplayWindow {
    /// Open a window on the first frame seen from a sender. That frame is
    /// implicitly accepted — there is nothing to compare it against.
    pub fn new(epoch: u64, counter: u64) -> Self {
        Self {
            epoch,
            highest: counter,
            bitmap: 1,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Check a frame and, if fresh, record it.
    ///
    /// Call only on frames whose AEAD has already verified.
    pub fn admit(&mut self, epoch: u64, counter: u64) -> ReplayVerdict {
        if epoch < self.epoch {
            return ReplayVerdict::StaleEpoch;
        }
        if epoch > self.epoch {
            // The sender restarted. Everything we knew about their counters is
            // meaningless now, so start a fresh window rather than trying to
            // reconcile two numbering schemes.
            *self = Self::new(epoch, counter);
            return ReplayVerdict::Fresh;
        }

        if counter > self.highest {
            let shift = counter - self.highest;
            // A jump of >= 64 leaves nothing of the old window worth keeping.
            self.bitmap = if shift >= WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest = counter;
            return ReplayVerdict::Fresh;
        }

        let age = self.highest - counter;
        if age >= WINDOW {
            return ReplayVerdict::TooOld;
        }
        let bit = 1u64 << age;
        if self.bitmap & bit != 0 {
            return ReplayVerdict::Duplicate;
        }
        self.bitmap |= bit;
        ReplayVerdict::Fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_traffic_is_always_fresh() {
        let mut w = ReplayWindow::new(1, 0);
        for c in 1..1000 {
            assert_eq!(w.admit(1, c), ReplayVerdict::Fresh, "counter {c}");
        }
        assert_eq!(w.highest(), 999);
    }

    #[test]
    fn an_exact_replay_is_caught() {
        let mut w = ReplayWindow::new(1, 10);
        assert_eq!(w.admit(1, 11), ReplayVerdict::Fresh);
        assert_eq!(w.admit(1, 11), ReplayVerdict::Duplicate);
        assert_eq!(w.admit(1, 10), ReplayVerdict::Duplicate);
    }

    #[test]
    fn reordering_inside_the_window_is_tolerated() {
        let mut w = ReplayWindow::new(1, 100);
        // Arrive out of order, as a lossy radio delivers them.
        for c in [105, 103, 101, 104, 102] {
            assert_eq!(w.admit(1, c), ReplayVerdict::Fresh, "counter {c}");
        }
        // ...but each only once.
        for c in [101, 102, 103, 104, 105] {
            assert_eq!(w.admit(1, c), ReplayVerdict::Duplicate, "counter {c}");
        }
    }

    #[test]
    fn frames_older_than_the_window_are_refused() {
        let mut w = ReplayWindow::new(1, 0);
        assert_eq!(w.admit(1, WINDOW), ReplayVerdict::Fresh);
        // counter 0 is now exactly WINDOW behind: out of reach.
        assert_eq!(w.admit(1, 0), ReplayVerdict::TooOld);
        // One inside the edge is still admissible.
        assert_eq!(w.admit(1, 1), ReplayVerdict::Fresh);
    }

    #[test]
    fn a_large_jump_clears_the_window_without_overflowing() {
        let mut w = ReplayWindow::new(1, 0);
        // A shift of >= 64 would be UB as `<<`; assert we handle it.
        assert_eq!(w.admit(1, 10_000), ReplayVerdict::Fresh);
        assert_eq!(w.admit(1, 10_000), ReplayVerdict::Duplicate);
        assert_eq!(w.admit(1, 9_999), ReplayVerdict::Fresh);
        assert_eq!(w.admit(1, 0), ReplayVerdict::TooOld);
    }

    #[test]
    fn a_restart_resets_the_window() {
        let mut w = ReplayWindow::new(1, 500);
        assert_eq!(
            w.admit(2, 0),
            ReplayVerdict::Fresh,
            "new epoch, counter restarts"
        );
        assert_eq!(w.admit(2, 1), ReplayVerdict::Fresh);
        assert_eq!(w.epoch(), 2);
    }

    #[test]
    fn replaying_a_whole_old_session_is_refused() {
        // The attack the epoch check exists for: capture session 1's traffic,
        // wait for the peer to restart into session 2, then re-inject session 1.
        let mut w = ReplayWindow::new(1, 10);
        assert_eq!(w.admit(2, 0), ReplayVerdict::Fresh);
        assert_eq!(w.admit(1, 11), ReplayVerdict::StaleEpoch);
        assert_eq!(w.admit(1, 999), ReplayVerdict::StaleEpoch);
    }

    #[test]
    fn counter_saturation_does_not_panic() {
        let mut w = ReplayWindow::new(1, u64::MAX - 1);
        assert_eq!(w.admit(1, u64::MAX), ReplayVerdict::Fresh);
        assert_eq!(w.admit(1, u64::MAX), ReplayVerdict::Duplicate);
    }
}
