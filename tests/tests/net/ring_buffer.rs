const BUF_SIZE: usize = 8192;
use tidemark_kernel::harness::TestVm;

#[test]
fn write_read_roundtrip() {
    let _t = TestVm::new();
    let idx = tidemark_kernel::net::ring_buffer::alloc_buffer().unwrap();
    let written = tidemark_kernel::net::ring_buffer::write(idx, b"hello network");
    assert_eq!(written, 13);
    let mut buf = [0u8; 32];
    let n = tidemark_kernel::net::ring_buffer::read(idx, &mut buf);
    assert_eq!(n, 13);
    assert_eq!(&buf[..13], b"hello network");
    tidemark_kernel::net::ring_buffer::free_buffer(idx);
}

#[test]
fn buffer_full_returns_zero() {
    let _t = TestVm::new();
    let idx = tidemark_kernel::net::ring_buffer::alloc_buffer().unwrap();

    let max_usable = BUF_SIZE - 1;
    let chunk = [0xAAu8; 4096];
    let mut total_written = 0usize;
    while total_written < max_usable {
        let remain = max_usable - total_written;
        let to_write = remain.min(chunk.len());
        let w = tidemark_kernel::net::ring_buffer::write(idx, &chunk[..to_write]);
        assert!(w > 0);
        total_written += w;
    }
    assert_eq!(
        tidemark_kernel::net::ring_buffer::available(idx),
        max_usable
    );
    assert_eq!(tidemark_kernel::net::ring_buffer::space(idx), 0);
    assert_eq!(tidemark_kernel::net::ring_buffer::write(idx, b"more"), 0);

    tidemark_kernel::net::ring_buffer::free_buffer(idx);
}

#[test]
fn circular_wrap_around() {
    let _t = TestVm::new();
    let idx = tidemark_kernel::net::ring_buffer::alloc_buffer().unwrap();

    let big = [0xBBu8; 7000];
    let w1 = tidemark_kernel::net::ring_buffer::write(idx, &big);
    assert_eq!(w1, 7000);

    let mut tmp = [0u8; 6000];
    let r1 = tidemark_kernel::net::ring_buffer::read(idx, &mut tmp);
    assert_eq!(r1, 6000);

    let wrap_data = [0xCCu8; 7000];
    let w2 = tidemark_kernel::net::ring_buffer::write(idx, &wrap_data);
    assert_eq!(w2, 7000);

    let mut out = [0u8; 8000];
    let r2 = tidemark_kernel::net::ring_buffer::read(idx, &mut out);
    assert_eq!(r2, 8000);
    for b in &out[..1000] {
        assert_eq!(*b, 0xBB);
    }
    for b in &out[1000..8000] {
        assert_eq!(*b, 0xCC);
    }

    tidemark_kernel::net::ring_buffer::free_buffer(idx);
}
