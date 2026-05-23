use tidemark_kernel::cpu::block_cache::{BlockCache, BlockEntry, PackedOp};
use tidemark_kernel::harness::TestVm;

#[test]
fn packed_op_round_trip() {
    let op = PackedOp::new(5, 10, 15, 20, 3, true, 4, -42);
    assert_eq!(op.op_id(), 5);
    assert_eq!(op.rd(), 10);
    assert_eq!(op.rs1(), 15);
    assert_eq!(op.rs2(), 20);
    assert_eq!(op.f3(), 3);
    assert!(op.f7b5());
    assert_eq!(op.step(), 4);
    assert_eq!(op.imm(), -42);
}

#[test]
fn packed_op_step2() {
    let op = PackedOp::new(1, 0, 0, 0, 0, false, 2, 0);
    assert_eq!(op.step(), 2);
}

#[test]
fn block_entry_size() {
    let size = BlockCache::allocation_size();
    assert!(size > 0);
    assert!(size < 16 * 1024 * 1024);
}

#[test]
fn block_cache_populate_and_get() {
    let t = TestVm::new();
    let code_addr: u64 = t.scratch;
    let addi_x1_x0_42: u32 = 0x02A00093;
    let ecall: u32 = 0x00000073;

    unsafe {
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr, addi_x1_x0_42);
        tidemark_kernel::guest_mem::write_u32(t.base, code_addr + 4, ecall);
    }

    let alloc_size = BlockCache::allocation_size();
    let cache_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(alloc_size as u32, 8) };
    assert!(cache_ptr != 0);

    let mut cache = unsafe { BlockCache::from_ptr(cache_ptr as *mut BlockEntry) };
    assert!(cache.get(code_addr).is_none());

    let block = unsafe { cache.build_block(code_addr, t.base) };
    assert!(block.is_some());

    let blk = block.unwrap();
    assert_eq!(blk.start_pc, code_addr);
    assert_eq!(blk.len, 2);

    let op0 = blk.ops[0];
    assert_eq!(op0.op_id(), 1);
    assert_eq!(op0.rd(), 1);
    assert_eq!(op0.rs1(), 0);
    assert_eq!(op0.imm(), 42);

    let cached = cache.get(code_addr);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().start_pc, code_addr);
    assert_eq!(cached.unwrap().len, 2);
}
