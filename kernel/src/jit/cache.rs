//! Metadata cache for dynamically instantiated JIT regions.

use alloc_crate::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn new(start: u64, end: u64) -> Option<Self> {
        (start < end).then_some(Self { start, end })
    }

    pub(crate) fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRegion {
    /// Runtime-owned compiled module identifier.
    pub id: u32,
    /// PC accepted by the module's `run` entry point.
    pub entry_pc: u64,
    /// Kernel VMA permit generation captured when this module was emitted.
    pub permit_generation: u32,
    /// Guest executable byte ranges represented by this module.
    pub code_ranges: Vec<AddressRange>,
}

#[derive(Default)]
pub struct RegionCache {
    regions: Vec<CompiledRegion>,
}

impl RegionCache {
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn insert(&mut self, region: CompiledRegion) -> Option<CompiledRegion> {
        if let Some(index) = self
            .regions
            .iter()
            .position(|cached| cached.entry_pc == region.entry_pc)
        {
            return Some(core::mem::replace(&mut self.regions[index], region));
        }
        self.regions.push(region);
        None
    }

    pub fn get(&self, pc: u64) -> Option<&CompiledRegion> {
        self.regions.iter().find(|region| region.entry_pc == pc)
    }

    /// Remove regions whose executable bytes overlap an address-space rewrite.
    pub fn invalidate_range(&mut self, range: AddressRange) -> Vec<CompiledRegion> {
        let mut invalidated = Vec::new();
        let mut index = 0;
        while index < self.regions.len() {
            if self.regions[index]
                .code_ranges
                .iter()
                .any(|cached| cached.overlaps(range))
            {
                invalidated.push(self.regions.remove(index));
            } else {
                index += 1;
            }
        }
        invalidated
    }

    /// Remove every region after an address-space replacement such as execve.
    pub fn clear(&mut self) -> Vec<CompiledRegion> {
        core::mem::take(&mut self.regions)
    }

    pub fn len(&self) -> usize {
        self.regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}
