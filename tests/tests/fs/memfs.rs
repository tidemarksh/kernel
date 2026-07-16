use tidemark_kernel::abi::EOPNOTSUPP;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::harness::TestVm;

#[test]
fn create_and_read() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"hello.txt", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, b"Hello, world!"), 13);

    let mut buf = [0u8; 32];
    let n = memfs::read_file(ino, 0, &mut buf);
    assert_eq!(n, 13);
    assert_eq!(&buf[..13], b"Hello, world!");
}

#[test]
fn directory_tree() {
    let _t = TestVm::new();
    let dir = memfs::create_dir(1, b"src", 0o755);
    assert!(dir > 0);
    let file = memfs::create_file(dir, b"main.rs", 0o644);
    assert!(file > 0);

    assert_eq!(memfs::resolve_path(b"/src/main.rs"), file);
    assert_eq!(memfs::resolve_path(b"/src"), dir);
    assert_eq!(memfs::resolve_path(b"/nonexistent"), 0);
}

#[test]
fn unlink_file() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"tmp.txt", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::resolve_path(b"/tmp.txt"), ino);
    assert_eq!(memfs::unlink(1, b"tmp.txt"), 0);
    assert_eq!(memfs::resolve_path(b"/tmp.txt"), 0);
}

#[test]
fn lookup_cache_invalidates_after_unlink_and_recreate() {
    let _t = TestVm::new();
    let dir = memfs::create_dir(1, b"cache-dir", 0o755);
    assert!(dir > 0);
    let first = memfs::create_file(dir, b"target.rb", 0o644);
    assert!(first > 0);

    assert_eq!(memfs::lookup(dir, b"target.rb"), first);
    assert_eq!(memfs::lookup(dir, b"target.rb"), first);
    assert_eq!(memfs::unlink(dir, b"target.rb"), 0);
    assert_eq!(memfs::lookup(dir, b"target.rb"), 0);

    let second = memfs::create_file(dir, b"target.rb", 0o644);
    assert!(second > first);
    assert_eq!(memfs::lookup(dir, b"target.rb"), second);
}

#[test]
fn lookup_cache_invalidates_negative_entry_after_create() {
    let _t = TestVm::new();
    let dir = memfs::create_dir(1, b"negative-cache", 0o755);
    assert!(dir > 0);

    assert_eq!(memfs::lookup(dir, b"later.rb"), 0);
    assert_eq!(memfs::lookup(dir, b"later.rb"), 0);
    let ino = memfs::create_file(dir, b"later.rb", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::lookup(dir, b"later.rb"), ino);
}

#[test]
fn lookup_cache_invalidates_after_rename_replace() {
    let _t = TestVm::new();
    let dir = memfs::create_dir(1, b"rename-cache", 0o755);
    assert!(dir > 0);
    let old = memfs::create_file(dir, b"old.rb", 0o644);
    let replacement = memfs::create_file(dir, b"replacement.rb", 0o644);
    assert!(old > 0);
    assert!(replacement > 0);

    assert_eq!(memfs::lookup(dir, b"old.rb"), old);
    assert_eq!(memfs::lookup(dir, b"replacement.rb"), replacement);
    assert_eq!(memfs::rename(dir, b"old.rb", dir, b"replacement.rb"), 0);

    assert_eq!(memfs::lookup(dir, b"old.rb"), 0);
    assert_eq!(memfs::lookup(dir, b"replacement.rb"), old);
}

#[test]
fn stat_file() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"data.bin", 0o644);
    memfs::write_file(ino, 0, &[0u8; 1024]);
    let st = memfs::stat(ino).unwrap();
    assert_eq!(st.size, 1024);
    assert_eq!(st.mode & memfs::S_IFREG, memfs::S_IFREG);
}

#[test]
fn readdir_entries() {
    let _t = TestVm::new();
    memfs::create_file(1, b"a.txt", 0o644);
    memfs::create_file(1, b"b.txt", 0o644);
    memfs::create_dir(1, b"sub", 0o755);
    let mut count = 0;
    memfs::readdir(1, |_name, _ino| {
        count += 1;
    });
    assert_eq!(count, 3);
}

#[test]
fn truncate_file() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"f.txt", 0o644);
    memfs::write_file(ino, 0, b"Hello, world!");
    assert_eq!(memfs::stat(ino).unwrap().size, 13);
    memfs::truncate(ino, 5);
    assert_eq!(memfs::stat(ino).unwrap().size, 5);
    let mut buf = [0u8; 16];
    let n = memfs::read_file(ino, 0, &mut buf);
    assert_eq!(n, 5);
    assert_eq!(&buf[..5], b"Hello");
}

#[test]
fn write_at_offset() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"sparse.bin", 0o644);
    memfs::write_file(ino, 100, b"data");
    assert_eq!(memfs::stat(ino).unwrap().size, 104);
    let mut buf = [0u8; 4];
    memfs::read_file(ino, 100, &mut buf);
    assert_eq!(&buf, b"data");
}

#[test]
fn repeated_page_sized_appends_survive_reallocation() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"append.bin", 0o644);
    let mut chunk = [0u8; 4096];
    let chunk_len = chunk.len();
    for block in 0..32usize {
        for (index, byte) in chunk.iter_mut().enumerate() {
            *byte = b'A' + (((block * chunk_len + index) % 23) as u8);
        }
        assert_eq!(
            memfs::write_file(ino, (block * chunk_len) as u64, &chunk),
            chunk_len as i64,
        );
    }

    let mut buf = [0u8; 4096];
    let buf_len = buf.len();
    for block in 0..32usize {
        assert_eq!(
            memfs::read_file(ino, (block * buf_len) as u64, &mut buf),
            buf_len as i64,
        );
        for (index, byte) in buf.iter().enumerate() {
            assert_eq!(
                *byte,
                b'A' + (((block * buf_len + index) % 23) as u8),
                "mismatch at {}",
                block * buf_len + index,
            );
        }
    }
}

#[test]
fn symlink_create_and_read() {
    let _t = TestVm::new();
    let ino = memfs::create_symlink(1, b"mylink", b"/target/path");
    assert!(ino > 0);

    let st = memfs::stat(ino).unwrap();
    assert_eq!(st.mode & memfs::S_IFMT, memfs::S_IFLNK);
    assert_eq!(st.size, 12);

    let mut buf = [0u8; 64];
    let n = memfs::read_link(ino, &mut buf);
    assert_eq!(n, 12);
    assert_eq!(&buf[..12], b"/target/path");
}

#[test]
fn symlink_resolve_and_readlinkat() {
    let _t = TestVm::new();
    let proc_dir = memfs::create_dir(1, b"proc", 0o755);
    assert!(proc_dir > 0);
    let self_dir = memfs::create_dir(proc_dir, b"self", 0o755);
    assert!(self_dir > 0);
    let exe_ino = memfs::create_symlink(self_dir, b"exe", b"/init");
    assert!(exe_ino > 0);

    assert_eq!(memfs::resolve_path(b"/proc/self/exe"), exe_ino);

    let mut buf = [0u8; 64];
    let n = memfs::read_link(exe_ino, &mut buf);
    assert_eq!(&buf[..n], b"/init");
}

#[test]
fn resolve_dotdot_components() {
    let _t = TestVm::new();
    let tmp = memfs::create_dir(1, b"tmp", 0o755);
    let hello = memfs::create_dir(tmp, b"hello", 0o755);
    let file = memfs::create_file(tmp, b"module.txt", 0o644);
    assert!(hello > 0);
    assert!(file > 0);

    assert_eq!(memfs::resolve_path(b"/tmp/hello/.."), tmp);
    assert_eq!(memfs::resolve_path_from(hello, b".."), tmp);
    assert_eq!(memfs::resolve_path_from(hello, b"../module.txt"), file);
}

#[test]
fn file_and_symlink_do_not_change_parent_nlink() {
    let _t = TestVm::new();
    let root_before = memfs::stat(1).unwrap().nlink;

    let file_ino = memfs::create_file(1, b"tmp.txt", 0o644);
    assert!(file_ino > 0);
    assert_eq!(memfs::stat(1).unwrap().nlink, root_before);

    let link_ino = memfs::create_symlink(1, b"tmp.link", b"/tmp.txt");
    assert!(link_ino > 0);
    assert_eq!(memfs::stat(1).unwrap().nlink, root_before);

    assert_eq!(memfs::unlink(1, b"tmp.txt"), 0);
    assert_eq!(memfs::unlink(1, b"tmp.link"), 0);
    assert_eq!(memfs::stat(1).unwrap().nlink, root_before);
}

#[test]
fn set_file_external_keeps_external_marker_and_size() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"external.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, b"payload"), 7);
    assert!(memfs::file_data_ptr(ino).is_none());

    let mut before = [0; 7];
    assert_eq!(memfs::read_file(ino, 0, &mut before), 7);
    assert_eq!(&before, b"payload");

    assert_eq!(memfs::set_file_external(ino, 3), 0);

    let st = memfs::stat(ino).unwrap();
    assert_eq!(st.size, 3);
    assert_eq!(st.mode & memfs::S_IFMT, memfs::S_IFREG);
    assert!(memfs::file_data_ptr(ino).is_none());

    let mut after = [0; 7];
    assert_eq!(memfs::read_file(ino, 0, &mut after), 3);
    assert_eq!(&after[..3], b"pay");
}

#[test]
fn page_cache_shim_requires_harness_opt_in() {
    let _t = TestVm::new();
    memfs::init();

    let ino = memfs::create_file(1, b"external.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, b"payload"), EOPNOTSUPP);
    assert_eq!(memfs::truncate(ino, 7), EOPNOTSUPP);
    assert_eq!(memfs::fsync(ino), EOPNOTSUPP);

    assert_eq!(memfs::set_file_external(ino, 7), 0);
    let mut buf = [0u8; 7];
    assert_eq!(memfs::read_file(ino, 0, &mut buf), 0);
    assert_eq!(memfs::set_file_size_shallow(ino, 3), 0);
    assert_eq!(memfs::stat(ino).unwrap().size, 3);
}

#[test]
fn page_cache_refresh_preserves_chmod_mode() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"generated", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, b"payload"), 7);

    assert_eq!(memfs::set_mode(ino, 0o755), 0);
    assert_eq!(memfs::set_file_size_shallow(ino, 7), 0);

    let st = memfs::stat(ino).unwrap();
    assert_eq!(st.mode & 0o7777, 0o755);
    assert_eq!(st.size, 7);
}

#[test]
fn truncate_zero_external_file_keeps_data_external() {
    let _t = TestVm::new();
    let ino = memfs::create_file(1, b"external-truncate.bin", 0o644);
    assert!(ino > 0);
    assert_eq!(memfs::write_file(ino, 0, b"payload"), 7);
    assert!(memfs::file_data_ptr(ino).is_none());

    assert_eq!(memfs::set_file_external(ino, 7), 0);
    assert!(memfs::file_data_ptr(ino).is_none());

    assert_eq!(memfs::truncate(ino, 0), 0);

    let st = memfs::stat(ino).unwrap();
    assert_eq!(st.size, 0);
    assert_eq!(st.mode & memfs::S_IFMT, memfs::S_IFREG);
    assert!(memfs::file_data_ptr(ino).is_none());
    assert_eq!(memfs::debug_file_data_layout(ino) >> 32, 0);
}
