//! JIT trace recording buffer.
//!
//! Records executed instructions for hot loop detection.
//! When a backward branch target exceeds the hot threshold,
//! recording starts. When the loop head is revisited,
//! the trace is ready for JIT compilation.

pub const TRACE_MAX_ENTRIES: usize = 128;
pub const HOT_THRESHOLD: u8 = 8;
pub const HOT_TABLE_SIZE: usize = 1024;

/// A single recorded trace entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceEntry {
    pub pc: u64,
    pub raw_insn: u32,
    pub step: u32,
}

/// Trace recording state, embedded in ThreadState.
#[repr(C)]
pub struct TraceBuffer {
    /// 0 = not recording, 1 = recording
    pub recording: u32,
    /// Loop head PC (the backward branch target)
    pub start_pc: u64,
    /// Number of recorded entries
    pub count: u32,
    /// Recorded entries
    pub entries: [TraceEntry; TRACE_MAX_ENTRIES],
}

impl TraceBuffer {
    pub const fn new() -> Self {
        Self {
            recording: 0,
            start_pc: 0,
            count: 0,
            entries: [TraceEntry {
                pc: 0,
                raw_insn: 0,
                step: 0,
            }; TRACE_MAX_ENTRIES],
        }
    }

    /// Start recording a trace for the given loop head.
    #[inline(always)]
    pub fn start(&mut self, loop_pc: u64) {
        self.recording = 1;
        self.start_pc = loop_pc;
        self.count = 0;
    }

    /// Record one instruction. Returns true if buffer is full.
    #[inline(always)]
    pub fn record(&mut self, pc: u64, raw: u32, step: u32) -> bool {
        if (self.count as usize) < TRACE_MAX_ENTRIES {
            self.entries[self.count as usize] = TraceEntry {
                pc,
                raw_insn: raw,
                step,
            };
            self.count += 1;
        }
        self.count as usize >= TRACE_MAX_ENTRIES
    }

    /// Stop recording.
    #[inline(always)]
    pub fn stop(&mut self) {
        self.recording = 0;
    }
}

/// Hot count table for backward branch targets.
/// Indexed by (pc >> 1) & (HOT_TABLE_SIZE - 1).
pub struct HotCounts {
    counts: [u8; HOT_TABLE_SIZE],
}

impl HotCounts {
    pub const fn new() -> Self {
        Self {
            counts: [0; HOT_TABLE_SIZE],
        }
    }

    /// Increment hot count for a backward branch target.
    /// Returns true exactly once when the threshold is reached.
    #[inline(always)]
    pub fn increment(&mut self, target_pc: u64) -> bool {
        let idx = (target_pc >> 1) as usize & (HOT_TABLE_SIZE - 1);
        let c = self.counts[idx];
        if c >= HOT_THRESHOLD {
            return false;
        }
        self.counts[idx] = c + 1;
        c + 1 == HOT_THRESHOLD
    }

    /// Check if a PC has reached the hot threshold.
    #[inline(always)]
    pub fn is_hot(&self, pc: u64) -> bool {
        let idx = (pc >> 1) as usize & (HOT_TABLE_SIZE - 1);
        self.counts[idx] >= HOT_THRESHOLD
    }

    pub fn clear(&mut self) {
        self.counts = [0; HOT_TABLE_SIZE];
    }
}

/// JIT readiness bitmap. Set by JS when a compiled module is available.
pub struct JitBitmap {
    bits: [u8; HOT_TABLE_SIZE / 8],
}

impl JitBitmap {
    pub const fn new() -> Self {
        Self {
            bits: [0; HOT_TABLE_SIZE / 8],
        }
    }

    #[inline(always)]
    pub fn is_ready(&self, pc: u64) -> bool {
        let idx = (pc >> 1) as usize & (HOT_TABLE_SIZE - 1);
        self.bits[idx / 8] & (1 << (idx % 8)) != 0
    }

    pub fn mark_ready(&mut self, pc: u64) {
        let idx = (pc >> 1) as usize & (HOT_TABLE_SIZE - 1);
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    pub fn clear(&mut self) {
        self.bits = [0; HOT_TABLE_SIZE / 8];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_count_threshold() {
        let mut hc = HotCounts::new();
        for i in 0..HOT_THRESHOLD - 1 {
            assert!(!hc.increment(0x1000), "should not fire at count {}", i);
        }
        assert!(hc.increment(0x1000), "should fire at threshold");
        assert!(!hc.increment(0x1000), "should not fire again");
    }

    #[test]
    fn trace_buffer_record() {
        let mut tb = TraceBuffer::new();
        tb.start(0x1000);
        assert_eq!(tb.recording, 1);
        assert!(!tb.record(0x1000, 0x00000013, 4));
        assert_eq!(tb.count, 1);
        assert_eq!(tb.entries[0].pc, 0x1000);
    }

    #[test]
    fn jit_bitmap() {
        let mut bm = JitBitmap::new();
        assert!(!bm.is_ready(0x2000));
        bm.mark_ready(0x2000);
        assert!(bm.is_ready(0x2000));
    }
}
