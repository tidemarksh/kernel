use tidemark_kernel::harness::TestVm;
use tidemark_kernel::net::ring_buffer::{self, BUF_SIZE};

#[test]
fn write_read_roundtrip() {
    let _t = TestVm::new();
    let idx = ring_buffer::alloc_buffer().unwrap();
    let written = ring_buffer::write(idx, b"hello network");
    assert_eq!(written, 13);
    let mut buf = [0u8; 32];
    let n = ring_buffer::read(idx, &mut buf);
    assert_eq!(n, 13);
    assert_eq!(&buf[..13], b"hello network");
    ring_buffer::free_buffer(idx);
}

#[test]
fn buffer_full_returns_zero() {
    let _t = TestVm::new();
    let idx = ring_buffer::alloc_buffer().unwrap();

    let max_usable = BUF_SIZE as usize - 1;
    let chunk = [0xAAu8; 4096];
    let mut total_written = 0usize;
    while total_written < max_usable {
        let remain = max_usable - total_written;
        let to_write = remain.min(chunk.len());
        let w = ring_buffer::write(idx, &chunk[..to_write]);
        assert!(w > 0);
        total_written += w;
    }
    assert_eq!(ring_buffer::available(idx), max_usable);
    assert_eq!(ring_buffer::space(idx), 0);
    assert_eq!(ring_buffer::write(idx, b"more"), 0);

    ring_buffer::free_buffer(idx);
}

#[test]
fn circular_wrap_around() {
    let _t = TestVm::new();
    let idx = ring_buffer::alloc_buffer().unwrap();

    let cap = BUF_SIZE as usize;
    let first_write_len = cap - 512;
    let first_read_len = cap - 1024;
    let wrap_write_len = 2048;
    let remaining_first = first_write_len - first_read_len;

    let big = vec![0xBBu8; first_write_len];
    let w1 = ring_buffer::write(idx, &big);
    assert_eq!(w1, first_write_len);

    let mut tmp = vec![0u8; first_read_len];
    let r1 = ring_buffer::read(idx, &mut tmp);
    assert_eq!(r1, first_read_len);

    let wrap_data = vec![0xCCu8; wrap_write_len];
    let w2 = ring_buffer::write(idx, &wrap_data);
    assert_eq!(w2, wrap_write_len);

    let mut out = vec![0u8; remaining_first + wrap_write_len];
    let r2 = ring_buffer::read(idx, &mut out);
    assert_eq!(r2, out.len());
    for b in &out[..remaining_first] {
        assert_eq!(*b, 0xBB);
    }
    for b in &out[remaining_first..] {
        assert_eq!(*b, 0xCC);
    }

    ring_buffer::free_buffer(idx);
}
