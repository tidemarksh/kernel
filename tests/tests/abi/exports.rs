use std::vec;
use tidemark_kernel::abi::*;
use tidemark_kernel::fs::memfs;
use tidemark_kernel::harness::TestVm;

fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    let ino = memfs::lookup(parent, name);
    if ino != 0 {
        ino
    } else {
        memfs::create_dir(parent, name, 0o755)
    }
}

fn install_file_at(path: &[u8], bytes: &[u8], mode: u32) -> u32 {
    let trimmed = path.strip_prefix(b"/").unwrap_or(path);
    let mut parts = trimmed.split(|b| *b == b'/').peekable();
    let mut parent = 1u32;
    let mut final_name = b"".as_slice();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            parent = ensure_dir(parent, part);
        } else {
            final_name = part;
        }
    }
    let ino = match memfs::lookup(parent, final_name) {
        0 => memfs::create_file(parent, final_name, mode),
        ino => ino,
    };
    assert_ne!(ino, 0);
    assert_eq!(memfs::truncate(ino, 0), 0);
    assert_eq!(memfs::write_file(ino, 0, bytes), bytes.len() as i64);
    ino
}

fn build_test_elf(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_with_tls(code: &[u8], tls_init: &[u8], tls_memsz: u64) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let data_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_filesz = (code_off + code.len()) as u64;
    let data_vaddr = 0x3000u64;
    let data_filesz = tls_init.len() as u64;
    let data_memsz = tls_memsz.max(data_filesz);
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code_filesz);
    put_u64(&mut elf, 104, code_filesz);
    put_u64(&mut elf, 112, 0x1000);

    put_u32(&mut elf, 120, 1);
    put_u32(&mut elf, 124, 6);
    put_u64(&mut elf, 128, data_off as u64);
    put_u64(&mut elf, 136, data_vaddr);
    put_u64(&mut elf, 152, data_filesz);
    put_u64(&mut elf, 160, data_memsz);
    put_u64(&mut elf, 168, 0x1000);

    put_u32(&mut elf, 176, 7);
    put_u32(&mut elf, 180, 4);
    put_u64(&mut elf, 184, data_off as u64);
    put_u64(&mut elf, 192, data_vaddr);
    put_u64(&mut elf, 208, data_filesz);
    put_u64(&mut elf, 216, tls_memsz);
    put_u64(&mut elf, 224, 8);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

fn build_test_elf_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let ph_num = 2usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let entry = 0x1000u64 + code_off as u64;
    let code_end = code_off + code.len();
    let total_len = code_end.max(interp_off + interp_path.len() + 1);
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, ph_num as u16);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let load_off = ph_off + 56;
    put_u32(&mut elf, load_off, 1);
    put_u32(&mut elf, load_off + 4, 5);
    put_u64(&mut elf, load_off + 8, 0);
    put_u64(&mut elf, load_off + 16, 0x1000);
    put_u64(&mut elf, load_off + 32, code_end as u64);
    put_u64(&mut elf, load_off + 40, code_end as u64);
    put_u64(&mut elf, load_off + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x200usize;
    let code_off = 0x300usize;
    let data_off = 0x400usize;
    let entry = 0x1000u64 + code_off as u64;
    let total_len = data_off + tls_init.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, data_ph + 40, tls_memsz);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let tls_ph = ph_off + 168;
    put_u32(&mut elf, tls_ph, 7);
    put_u32(&mut elf, tls_ph + 4, 4);
    put_u64(&mut elf, tls_ph + 8, data_off as u64);
    put_u64(&mut elf, tls_ph + 16, 0x3000);
    put_u64(&mut elf, tls_ph + 32, tls_init.len() as u64);
    put_u64(&mut elf, tls_ph + 40, tls_memsz);
    put_u64(&mut elf, tls_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + tls_init.len()].copy_from_slice(tls_init);
    elf
}

fn build_test_elf_dyn_with_interp(code: &[u8], interp_path: &[u8]) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp(code, interp_path);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf
}

fn build_test_elf_dyn_with_interp_and_tls(
    code: &[u8],
    interp_path: &[u8],
    tls_init: &[u8],
    tls_memsz: u64,
) -> Vec<u8> {
    let mut elf = build_test_elf_with_interp_and_tls(code, interp_path, tls_init, tls_memsz);
    elf[16..18].copy_from_slice(&3u16.to_le_bytes());
    elf
}

fn build_test_elf_dyn(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let mut elf = vec![0u8; 0x100 + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x1000);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, 0x100);
    put_u64(&mut elf, 80, 0x1000);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[0x100..0x100 + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_dyn_low(code: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let code_off = 0x100usize;
    let mut elf = vec![0u8; code_off + code.len()];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, 0x40);
    put_u64(&mut elf, 32, 64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 1);

    put_u32(&mut elf, 64, 1);
    put_u32(&mut elf, 68, 5);
    put_u64(&mut elf, 72, code_off as u64);
    put_u64(&mut elf, 80, 0);
    put_u64(&mut elf, 96, code.len() as u64);
    put_u64(&mut elf, 104, code.len() as u64);
    put_u64(&mut elf, 112, 0x1000);
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf
}

fn build_test_elf_dyn_two_loads(code: &[u8], data: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let code_off = 0x100usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64;
    let total_len = data_off + data.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 2);

    put_u32(&mut elf, ph_off, 1);
    put_u32(&mut elf, ph_off + 4, 5);
    put_u64(&mut elf, ph_off + 8, code_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1000);
    put_u64(&mut elf, ph_off + 32, code.len() as u64);
    put_u64(&mut elf, ph_off + 40, code.len() as u64);
    put_u64(&mut elf, ph_off + 48, 0x1000);

    let data_ph = ph_off + 56;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

fn build_test_elf_dyn_with_interp_two_loads(
    code: &[u8],
    data: &[u8],
    interp_path: &[u8],
) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let entry = 0x1000u64 + code_off as u64;
    let total_len = data_off + data.len();
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 3);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, data.len() as u64);
    put_u64(&mut elf, data_ph + 40, data.len() as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    elf
}

fn build_test_elf_dyn_with_interp_dynamic(code: &[u8], data: &[u8], interp_path: &[u8]) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    let ph_off = 64usize;
    let interp_off = 0x100usize;
    let code_off = 0x200usize;
    let data_off = 0x300usize;
    let dynamic_off = 0x320usize;
    let dynamic_vaddr = 0x3020u64;
    let entry = 0x1000u64 + code_off as u64;
    let second_filesz = (dynamic_off + 64 - data_off).max(data.len());
    let total_len = data_off + second_filesz;
    let mut elf = vec![0u8; total_len];
    elf[0] = 0x7f;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    put_u16(&mut elf, 16, 3);
    put_u16(&mut elf, 18, 243);
    put_u32(&mut elf, 20, 1);
    put_u64(&mut elf, 24, entry);
    put_u64(&mut elf, 32, ph_off as u64);
    put_u16(&mut elf, 52, 64);
    put_u16(&mut elf, 54, 56);
    put_u16(&mut elf, 56, 4);

    put_u32(&mut elf, ph_off, 3);
    put_u32(&mut elf, ph_off + 4, 4);
    put_u64(&mut elf, ph_off + 8, interp_off as u64);
    put_u64(&mut elf, ph_off + 16, 0x1100);
    put_u64(&mut elf, ph_off + 32, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 40, (interp_path.len() + 1) as u64);
    put_u64(&mut elf, ph_off + 48, 1);

    let code_ph = ph_off + 56;
    put_u32(&mut elf, code_ph, 1);
    put_u32(&mut elf, code_ph + 4, 5);
    put_u64(&mut elf, code_ph + 8, 0);
    put_u64(&mut elf, code_ph + 16, 0x1000);
    put_u64(&mut elf, code_ph + 32, data_off as u64);
    put_u64(&mut elf, code_ph + 40, data_off as u64);
    put_u64(&mut elf, code_ph + 48, 0x1000);

    let data_ph = ph_off + 112;
    put_u32(&mut elf, data_ph, 1);
    put_u32(&mut elf, data_ph + 4, 6);
    put_u64(&mut elf, data_ph + 8, data_off as u64);
    put_u64(&mut elf, data_ph + 16, 0x3000);
    put_u64(&mut elf, data_ph + 32, second_filesz as u64);
    put_u64(&mut elf, data_ph + 40, second_filesz as u64 + 0x100);
    put_u64(&mut elf, data_ph + 48, 0x1000);

    let dynamic_ph = ph_off + 168;
    put_u32(&mut elf, dynamic_ph, 2);
    put_u32(&mut elf, dynamic_ph + 4, 6);
    put_u64(&mut elf, dynamic_ph + 8, dynamic_off as u64);
    put_u64(&mut elf, dynamic_ph + 16, dynamic_vaddr);
    put_u64(&mut elf, dynamic_ph + 32, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 40, 4 * 16);
    put_u64(&mut elf, dynamic_ph + 48, 8);

    elf[interp_off..interp_off + interp_path.len()].copy_from_slice(interp_path);
    elf[interp_off + interp_path.len()] = 0;
    elf[code_off..code_off + code.len()].copy_from_slice(code);
    elf[data_off..data_off + data.len()].copy_from_slice(data);
    put_u64(&mut elf, dynamic_off, 7);
    put_u64(&mut elf, dynamic_off + 8, 0x3300);
    put_u64(&mut elf, dynamic_off + 16, 8);
    put_u64(&mut elf, dynamic_off + 24, 24);
    put_u64(&mut elf, dynamic_off + 32, 0x6fff_ffff);
    put_u64(&mut elf, dynamic_off + 40, 5);
    put_u64(&mut elf, dynamic_off + 48, 0);
    put_u64(&mut elf, dynamic_off + 56, 0);
    elf
}

fn find_auxv_value(base: u32, sp: u64, tag: u64) -> Option<u64> {
    let argc = unsafe { tidemark_kernel::guest_mem::read_u64(base, sp) };
    let mut cursor = sp + 8;
    cursor += argc * 8 + 8;
    while unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor) } != 0 {
        cursor += 8;
    }
    cursor += 8;
    for _ in 0..32 {
        let aux_tag = unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor) };
        let aux_val = unsafe { tidemark_kernel::guest_mem::read_u64(base, cursor + 8) };
        if aux_tag == tidemark_kernel::elf::AT_NULL {
            return None;
        }
        if aux_tag == tag {
            return Some(aux_val);
        }
        cursor += 16;
    }
    None
}

#[test]
fn status_codes_are_distinct() {
    let codes = [
        STATUS_OK,
        STATUS_FAULT,
        STATUS_FS,
        STATUS_FUTEX_WAIT,
        STATUS_PIPE_WAIT,
        STATUS_EPOLL_WAIT,
        STATUS_VFORK_WAIT,
        STATUS_EXECVE_SPAWN,
        STATUS_CLONE_SPAWN,
        STATUS_SLEEP,
        STATUS_JIT_READY,
        STATUS_CONNECT,
        STATUS_SOCKET_SEND,
        STATUS_SOCKET_RECV,
        STATUS_WAIT4,
        STATUS_FLOCK_WAIT,
    ];
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(codes[i], codes[j]);
        }
    }
}

#[test]
fn spawn_handoff_exports_round_trip() {
    let mut t = TestVm::new();
    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let ino = tidemark_kernel::fs::memfs::create_file(1, b"test", 0o755);
    assert_ne!(ino, 0);
    assert_eq!(
        tidemark_kernel::fs::memfs::write_file(ino, 0, &elf),
        elf.len() as i64
    );
    let path_addr = t.scratch;
    t.write_mem(path_addr, b"/test\0");

    tidemark_kernel::syscall::process::sys_vfork(&mut t.vm, t.base);
    let ret =
        tidemark_kernel::syscall::process::sys_execve(&mut t.vm, t.base, path_addr, 0x1111, 0x2222);
    assert!(ret > 0);

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
    assert_eq!(thread_spawn_child_pid(vm_ptr), ret as i32);
    assert_eq!(thread_spawn_path(vm_ptr), path_addr);
    assert_eq!(thread_spawn_argv(vm_ptr), 0x1111);
    assert_eq!(thread_spawn_envp(vm_ptr), 0x2222);

    thread_set_guest_ram_limit(vm_ptr, 0x12345678);
    assert_eq!(thread_guest_ram_limit(vm_ptr), 0x12345678);

    thread_set_execve_handoff(vm_ptr, 0x4444, 0xAAAA, 0xBBBB, 0xCCCC, 0x3333);
    assert_eq!(thread_process_ptr(vm_ptr), 0x4444);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_EXECVE);
    assert_eq!(thread_spawn_path(vm_ptr), 0xAAAA);
    assert_eq!(thread_spawn_argv(vm_ptr), 0xBBBB);
    assert_eq!(thread_spawn_envp(vm_ptr), 0xCCCC);
    assert_eq!(thread_spawn_ram_size(vm_ptr), 0x3333);

    thread_clear_spawn_handoff(vm_ptr);
    assert_eq!(thread_spawn_kind(vm_ptr), SPAWN_KIND_NONE);
    assert_eq!(thread_spawn_child_pid(vm_ptr), 0);
    assert_eq!(thread_spawn_path(vm_ptr), 0);
}

#[test]
fn resume_vfork_parent_export_restores_parent_view() {
    let mut t = TestVm::new();
    t.vm.x[1] = 0x1234;
    t.vm.pc = 0x4000;
    tidemark_kernel::syscall::process::sys_vfork(&mut t.vm, t.base);
    t.vm.x[1] = 0xFFFF;
    t.vm.pc = 0x9000;

    let vm_ptr = &mut t.vm as *mut tidemark_kernel::types::ThreadState as u32;
    thread_resume_vfork_parent(vm_ptr, 55);
    assert_eq!(t.vm.x[1], 0x1234);
    assert_eq!(t.vm.pc, 0x4000);
    assert_eq!(t.vm.x[10], 55);
    assert_eq!(t.vm.status, STATUS_OK);
}

#[test]
fn process_create_populates_initial_stack_contract() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    assert_ne!(guest_base, 0);

    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x420, b"hello\0");
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x440, b"FOO=bar\0");
    }

    let arg0_ptr = elf_ptr + 0x400;
    let arg1_ptr = elf_ptr + 0x420;
    let env0_ptr = elf_ptr + 0x440;

    process_clear_args();
    process_push_arg(arg0_ptr);
    process_push_arg(arg1_ptr);
    process_push_env(env0_ptr);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, stack_size);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    let sp = vm.x[2];
    assert_eq!(sp & 0xf, 0, "initial sp must stay 16-byte aligned");

    let argc = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp) };
    assert_eq!(argc, 2);

    let argv0 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 8) };
    let argv1 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 16) };
    let argv_null = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 24) };
    let env0 = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 32) };
    let env_null = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, sp + 40) };

    assert_ne!(argv0, 0);
    assert_ne!(argv1, 0);
    assert_eq!(argv_null, 0);
    assert_ne!(env0, 0);
    assert_eq!(env_null, 0);

    let mut buf = [0u8; 32];
    let argv0_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, argv0, &mut buf) };
    assert_eq!(&buf[..argv0_len], b"/bin/test");
    let argv1_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, argv1, &mut buf) };
    assert_eq!(&buf[..argv1_len], b"hello");
    let env0_len = unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, env0, &mut buf) };
    assert_eq!(&buf[..env0_len], b"FOO=bar");

    let auxv_start = sp + 48;
    let aux_pagesz_tag = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, auxv_start) };
    let aux_pagesz_val =
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, auxv_start + 8) };
    assert_eq!(aux_pagesz_tag, tidemark_kernel::elf::AT_PAGESZ);
    assert_eq!(aux_pagesz_val, 4096);

    let mut found_random = false;
    let mut found_execfn = false;
    let mut found_hwcap = false;
    let mut found_clktck = false;
    let mut cursor = auxv_start;
    for _ in 0..16 {
        let tag = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor) };
        let val = unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, cursor + 8) };
        if tag == tidemark_kernel::elf::AT_NULL {
            break;
        }
        if tag == tidemark_kernel::elf::AT_RANDOM {
            found_random = true;
            assert_ne!(val, 0);
        }
        if tag == tidemark_kernel::elf::AT_EXECFN {
            found_execfn = true;
            let mut execfn = [0u8; 32];
            let execfn_len =
                unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, val, &mut execfn) };
            assert_eq!(&execfn[..execfn_len], b"/bin/test");
        }
        if tag == tidemark_kernel::elf::AT_HWCAP {
            found_hwcap = true;
            assert_eq!(val, 0x112D);
        }
        if tag == tidemark_kernel::elf::AT_CLKTCK {
            found_clktck = true;
            assert_eq!(val, 100);
        }
        cursor += 16;
    }
    assert!(found_random, "AT_RANDOM must be present in auxv");
    assert!(found_execfn, "AT_EXECFN must be present in auxv");
    assert!(found_hwcap, "AT_HWCAP must be present in auxv");
    assert!(found_clktck, "AT_CLKTCK must be present in auxv");
}

#[test]
fn process_guest_base_reserves_exec_scratch_headroom() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    assert_ne!(guest_base, 0);

    let expected_floor =
        (((kernel_heap_ptr() as u64) + 4 * 1024 * 1024 + 256 * 1024 * 1024 + 0xF_FFFF) & !0xF_FFFF)
            as u32;
    assert_eq!(guest_base, expected_floor);
}

#[test]
fn process_create_rebases_user_brk_after_hidden_process_state() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let stack_size = 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    assert_ne!(guest_base, 0);

    let mut elf = vec![0u8; 0x104];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&4u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[0x100..0x104].copy_from_slice(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);
    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, stack_size);
    assert_ne!(vm_ptr, 0);

    let process_ptr = thread_process_ptr(vm_ptr) as u64;
    let ps_size = core::mem::size_of::<tidemark_kernel::types::ProcessState>() as u64;
    let hidden_end = process_ptr + ps_size;
    let public_brk =
        (hidden_end + tidemark_kernel::abi::PAGE_SIZE - 1) & !(tidemark_kernel::abi::PAGE_SIZE - 1);
    assert_eq!(tidemark_kernel::syscall::memory::current_brk(), public_brk);
    assert_eq!(
        tidemark_kernel::harness::memory::debug_brk_base(),
        public_brk
    );
}

#[test]
fn process_create_initializes_tp_from_pt_tls() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_with_tls(&[0x13, 0x05, 0x70, 0x00], &[0x41, 0x42, 0x43, 0x44], 0x20);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.tls_base, 0x3000);
    assert_eq!(vm.x[4], 0x3000);
}

#[test]
fn process_create_with_pt_interp_preserves_executable_entry_in_auxv() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-interp\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    assert!(find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR).is_some());
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_HWCAP),
        Some(0x112D)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_CLKTCK),
        Some(100)
    );
}

#[test]
fn process_create_with_pt_interp_follows_symlink_path() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/usr/lib/ld-test.so", &interp, 0o755);
    assert_ne!(memfs::create_symlink(1, b"lib", b"usr/lib"), 0);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-interp\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);
    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
}

#[test]
fn process_create_with_pt_interp_preserves_executable_tls_base() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x800,
            b"/bin/test-interp-tls\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x800);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x5000);
    assert_eq!(vm.tls_base, 0x3000);
    assert_eq!(vm.x[4], 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1300)
    );
}

#[test]
fn process_create_with_pt_interp_preserves_biased_dynamic_tls_base() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_dyn_with_interp_and_tls(
        &[0x13, 0x05, 0x70, 0x00],
        b"/lib/ld-test.so",
        &[0x41, 0x42, 0x43, 0x44],
        0x20,
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x800,
            b"/bin/test-dyn-interp-tls\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x800);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(vm.tls_base, 0x4000);
    assert_eq!(vm.x[4], 0x4000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2300)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );
}

#[test]
fn process_inspect_elf_brk_accepts_et_dyn() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let elf = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
    }

    assert_eq!(
        process_inspect_elf_brk(elf_ptr, elf.len() as u32, ram_size),
        0x2000
    );
}

#[test]
fn process_create_with_pt_interp_accepts_et_dyn_interpreter() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf_dyn(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-interp\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, vm.pc, &mut code);
    }
    assert_eq!(code, [0x13, 0x05, 0x70, 0x00]);
}

#[test]
fn process_create_with_pt_interp_accepts_et_dyn_two_load_interpreter() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_with_interp(&[0x13, 0x05, 0x70, 0x00], b"/lib/ld-test.so");
    let interp = build_test_elf_dyn_two_loads(&[0x13, 0x05, 0x70, 0x00], &[0xaa, 0xbb, 0xcc, 0xdd]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-two-load-interp\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x3000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );
}

#[test]
fn process_create_with_pt_interp_biases_et_dyn_main_executable() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let elf = build_test_elf_dyn_with_interp(&main_code, b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-dyn-main\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x4000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x3000)
    );

    let mut interp = [0u8; 32];
    let interp_len =
        unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, 0x2100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x2200, &mut code);
    }
    assert_eq!(code, main_code);
}

#[test]
fn process_create_with_pt_interp_biases_et_dyn_two_load_main_executable() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_data = [0xaa, 0xbb, 0xcc, 0xdd];
    let elf = build_test_elf_dyn_with_interp_two_loads(&main_code, &main_data, b"/lib/ld-test.so");
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-two-load-main\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let mut data = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x4000, &mut data);
    }
    assert_eq!(data, main_data);
}

#[test]
fn process_create_with_pt_interp_preserves_biased_main_dynamic_section() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let elf = build_test_elf_dyn_with_interp_dynamic(
        &[0x13, 0x05, 0x70, 0x00],
        &[0xaa, 0xbb, 0xcc, 0xdd],
        b"/lib/ld-test.so",
    );
    let interp = build_test_elf(&[0x13, 0x05, 0x70, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-dyn-dynamic\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x6000);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x2200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_PHDR),
        Some(0x2040)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x5000)
    );

    let dyn_base = 0x4020u64;
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base) },
        7
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 8) },
        0x3300
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 16) },
        8
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 24) },
        24
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 32) },
        0x6fff_ffff
    );
    assert_eq!(
        unsafe { tidemark_kernel::guest_mem::read_u64(guest_base, dyn_base + 40) },
        5
    );
}

#[test]
fn process_create_with_pt_interp_zero_fills_interpreter_brk_padding() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp_elf, 0o755);

    let dirty_addr = 0x2ff0u64;
    assert!(unsafe {
        tidemark_kernel::syscall::memory::ensure_guest_memory_capacity(guest_base, dirty_addr + 16)
    });
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(guest_base, dirty_addr, &[0xa5; 16]);
    }

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &main_elf);
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64 + 0x400, b"/bin/test-pad\0");
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, main_elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let mut padding = [0u8; 16];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, dirty_addr, &mut padding);
    }
    assert_eq!(padding, [0u8; 16]);
}

#[test]
fn process_create_with_pt_interp_maps_main_executable_image() {
    let _t = TestVm::new();
    let ram_size = 64 * 1024 * 1024;
    let guest_base = process_guest_base(ram_size);
    let main_code = [0x13, 0x05, 0x70, 0x00];
    let main_elf = build_test_elf_with_interp(&main_code, b"/lib/ld-test.so");
    let interp_elf = build_test_elf_dyn_low(&[0x13, 0x06, 0x80, 0x00]);
    install_file_at(b"/lib/ld-test.so", &interp_elf, 0o755);

    let elf_ptr = unsafe { tidemark_kernel::alloc::alloc_zeroed(0x1000, 16) };
    assert_ne!(elf_ptr, 0);
    unsafe {
        tidemark_kernel::guest_mem::write_bytes(0, elf_ptr as u64, &main_elf);
        tidemark_kernel::guest_mem::write_bytes(
            0,
            elf_ptr as u64 + 0x400,
            b"/bin/test-main-mapped\0",
        );
    }

    process_clear_args();
    process_push_arg(elf_ptr + 0x400);

    let vm_ptr = process_create(elf_ptr, main_elf.len() as u32, ram_size, 1024 * 1024);
    assert_ne!(vm_ptr, 0);

    let vm = unsafe { &*(vm_ptr as *const tidemark_kernel::types::ThreadState) };
    assert_eq!(vm.pc, 0x2040);
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_ENTRY),
        Some(0x1200)
    );
    assert_eq!(
        find_auxv_value(guest_base, vm.x[2], tidemark_kernel::elf::AT_BASE),
        Some(0x2000)
    );

    let mut interp = [0u8; 32];
    let interp_len =
        unsafe { tidemark_kernel::guest_mem::read_cstr(guest_base, 0x1100, &mut interp) };
    assert_eq!(&interp[..interp_len], b"/lib/ld-test.so");

    let mut code = [0u8; 4];
    unsafe {
        tidemark_kernel::guest_mem::read_bytes(guest_base, 0x1200, &mut code);
    }
    assert_eq!(code, main_code);
}

#[test]
fn fd_types_are_distinct() {
    let types = [
        FD_TYPE_NONE,
        FD_TYPE_STDOUT,
        FD_TYPE_STDERR,
        FD_TYPE_FILE,
        FD_TYPE_DIR,
        FD_TYPE_DEVNULL,
        FD_TYPE_PIPE,
        FD_TYPE_EPOLL,
        FD_TYPE_SOCKET,
        FD_TYPE_EVENTFD,
        FD_TYPE_TIMERFD,
        FD_TYPE_PTY_MASTER,
        FD_TYPE_PTY_SLAVE,
        FD_TYPE_INOTIFY,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn error_codes_are_negative() {
    assert!(ENOENT < 0);
    assert!(EBADF < 0);
    assert!(EINVAL < 0);
    assert!(ENOMEM < 0);
    assert!(ENOSYS < 0);
}

#[test]
fn clone_flags_no_overlap() {
    assert_eq!(CLONE_VM & CLONE_THREAD, 0);
    assert_eq!(CLONE_VM & CLONE_VFORK, 0);
    assert_eq!(CLONE_THREAD & CLONE_VFORK, 0);
}
