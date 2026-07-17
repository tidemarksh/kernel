use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use wasmtime::{Config, Engine, Instance, Linker, Module, SharedMemory, Store, TypedFunc, Val};

const ELF_STAGING_HEADROOM: usize = 256 * 1024;
const GUEST_STACK_BYTES: i32 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramOutcome {
    pub vm_ptr: i32,
    pub requested_budget: i32,
    pub remaining_budget: i32,
    pub status: i32,
    pub pc: i64,
    pub registers: [i64; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedProgram {
    pub vm_ptr: i32,
    pub entry: i64,
}

impl ProgramOutcome {
    pub fn consumed_budget(&self) -> i32 {
        self.requested_budget - self.remaining_budget
    }
}

pub struct KernelInstance {
    store: Store<()>,
    instance: Instance,
    memory: SharedMemory,
}

impl KernelInstance {
    pub fn load(artifact: &Path) -> Result<Self, String> {
        let mut config = Config::new();
        config.wasm_memory64(true).wasm_threads(true);
        let engine = Engine::new(&config).map_err(|error| error.to_string())?;
        let module = Module::from_file(&engine, artifact).map_err(|error| error.to_string())?;
        let memory_type = module
            .imports()
            .find(|import| import.module() == "env" && import.name() == "memory")
            .and_then(|import| import.ty().memory().cloned())
            .ok_or_else(|| "Kernel artifact does not import env.memory".to_string())?;
        if !memory_type.is_64() || !memory_type.is_shared() {
            return Err("Kernel artifact env.memory must be shared Memory64".into());
        }

        let memory = SharedMemory::new(&engine, memory_type).map_err(|error| error.to_string())?;
        let mut store = Store::new(&engine, ());
        let mut linker = Linker::new(&engine);
        linker
            .define(&store, "env", "memory", memory.clone())
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_page_cache_read",
                |_ino: i32, _offset: i64, _dst: i64, _len: i32| -> i64 { -38 },
            )
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap("env", "tidemark_page_cache_flush", |_ino: i32| -> i32 {
                -38
            })
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_page_cache_truncate",
                |_ino: i32, _len: i64| -> i32 { -38 },
            )
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_page_cache_write",
                |_ino: i32, _offset: i64, _src: i64, _len: i32| -> i64 { -38 },
            )
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_page_cache_stat",
                |_ino: i32, _stat: i64| -> i32 { -38 },
            )
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_page_cache_set_mode",
                |_ino: i32, _mode: i32| -> i32 { -38 },
            )
            .map_err(|error| error.to_string())?;
        linker
            .func_wrap(
                "env",
                "tidemark_memory_atomic_notify",
                |_address: i64, _count: i32| -> i32 { 0 },
            )
            .map_err(|error| error.to_string())?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            store,
            instance,
            memory,
        })
    }

    pub fn typed_func<Params, Results>(
        &mut self,
        name: &str,
    ) -> Result<TypedFunc<Params, Results>, String>
    where
        Params: wasmtime::WasmParams,
        Results: wasmtime::WasmResults,
    {
        self.instance
            .get_typed_func(&mut self.store, name)
            .map_err(|error| error.to_string())
    }

    pub fn call<Params, Results>(
        &mut self,
        function: &TypedFunc<Params, Results>,
        params: Params,
    ) -> Result<Results, String>
    where
        Params: wasmtime::WasmParams,
        Results: wasmtime::WasmResults,
    {
        function
            .call(&mut self.store, params)
            .map_err(|error| error.to_string())
    }

    pub fn write_memory(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or_else(|| "memory write overflow".to_string())?;
        let data = self.memory.data();
        let destination = data
            .get(offset..end)
            .ok_or_else(|| "memory write out of bounds".to_string())?;
        for (cell, byte) in destination.iter().zip(bytes) {
            unsafe { AtomicU8::from_ptr(cell.get()) }.store(*byte, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn read_memory(&self, offset: usize, length: usize) -> Result<Vec<u8>, String> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| "memory read overflow".to_string())?;
        let data = self.memory.data();
        let source = data
            .get(offset..end)
            .ok_or_else(|| "memory read out of bounds".to_string())?;
        Ok(source
            .iter()
            .map(|cell| unsafe { AtomicU8::from_ptr(cell.get()) }.load(Ordering::Relaxed))
            .collect())
    }

    pub fn prepare_program(&mut self, code: &[u8]) -> Result<PreparedProgram, String> {
        if code.is_empty() {
            return Err("program must contain at least one instruction".into());
        }
        let elf = riscv_elf_bytes(code)?;
        let memory_size = self.memory.data_size();
        let elf_offset = memory_size
            .checked_sub(ELF_STAGING_HEADROOM)
            .ok_or_else(|| "Kernel memory is too small for ELF staging".to_string())?;
        if elf.len() > ELF_STAGING_HEADROOM {
            return Err("ELF exceeds staging headroom".into());
        }
        self.write_memory(elf_offset, &elf)?;

        let heap_base = match self
            .instance
            .get_global(&mut self.store, "__heap_base")
            .ok_or_else(|| "Kernel artifact is missing __heap_base".to_string())?
            .get(&mut self.store)
        {
            Val::I64(value) => value,
            other => return Err(format!("unexpected __heap_base value: {other:?}")),
        };
        let kernel_init = self.typed_func::<i32, ()>("kernel_init")?;
        self.call(&kernel_init, heap_base as i32)?;
        let address_profile = self.typed_func::<(), i32>("abi_guest_address_profile_target")?;
        let address_profile = self.call(&address_profile, ())?;
        let create = self.typed_func::<(i32, i32, i32, i64, i32, i32), i32>(
            "process_create_with_memory_policy",
        )?;
        let vm_ptr = self.call(
            &create,
            (
                i32::try_from(elf_offset).map_err(|_| "ELF offset does not fit i32")?,
                i32::try_from(elf.len()).map_err(|_| "ELF length does not fit i32")?,
                address_profile,
                i64::try_from(memory_size).map_err(|_| "memory size does not fit i64")?,
                0,
                GUEST_STACK_BYTES,
            ),
        )?;
        if vm_ptr == 0 {
            let last_error = self.typed_func::<(), i32>("process_create_last_error")?;
            let last_error = self.call(&last_error, ())?;
            return Err(format!("process creation failed with code {last_error}"));
        }

        Ok(PreparedProgram {
            vm_ptr,
            entry: 0x1_0000,
        })
    }

    pub fn step_program(&mut self, prepared: PreparedProgram, budget: i32) -> Result<i32, String> {
        if budget <= 0 {
            return Err("program budget must be positive".into());
        }
        let step = self.typed_func::<(i32, i32), i32>("thread_step")?;
        self.call(&step, (prepared.vm_ptr, budget))
    }

    pub fn observe_program(
        &mut self,
        prepared: PreparedProgram,
        budget: i32,
        remaining_budget: i32,
    ) -> Result<ProgramOutcome, String> {
        let status = self.typed_func::<i32, i32>("thread_status")?;
        let status = self.call(&status, prepared.vm_ptr)?;
        let pc = self.typed_func::<i32, i64>("thread_pc")?;
        let pc = self.call(&pc, prepared.vm_ptr)?;
        let register = self.typed_func::<(i32, i32), i64>("thread_reg")?;
        let mut registers = [0; 32];
        for (index, value) in registers.iter_mut().enumerate() {
            *value = self.call(&register, (prepared.vm_ptr, index as i32))?;
        }
        Ok(ProgramOutcome {
            vm_ptr: prepared.vm_ptr,
            requested_budget: budget,
            remaining_budget,
            status,
            pc,
            registers,
        })
    }

    pub fn scalar_i32(&mut self, name: &str, argument: i32) -> Result<i32, String> {
        let function = self.typed_func::<i32, i32>(name)?;
        self.call(&function, argument)
    }

    pub fn counter(&mut self, name: &str) -> Result<u64, String> {
        let function = self.typed_func::<(), i64>(name)?;
        Ok(self.call(&function, ())? as u64)
    }

    pub fn run_program(&mut self, words: &[u32], budget: i32) -> Result<ProgramOutcome, String> {
        let mut code = Vec::with_capacity(words.len() * 4);
        for word in words {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let prepared = self.prepare_program(&code)?;
        let remaining = self.step_program(prepared, budget)?;
        self.observe_program(prepared, budget, remaining)
    }
}

pub fn riscv_elf(words: &[u32]) -> Result<Vec<u8>, String> {
    let mut code = Vec::with_capacity(words.len() * 4);
    for word in words {
        code.extend_from_slice(&word.to_le_bytes());
    }
    riscv_elf_bytes(&code)
}

pub fn riscv_elf_bytes(code: &[u8]) -> Result<Vec<u8>, String> {
    const ELF_HEADER_BYTES: usize = 64;
    const PROGRAM_HEADER_BYTES: usize = 56;
    const SEGMENT_OFFSET: usize = 4096;
    const ENTRY_ADDRESS: u64 = 0x1_0000;

    let code_bytes = code.len();
    let mut elf = vec![0; SEGMENT_OFFSET + code_bytes];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    write_u16(&mut elf, 16, 2);
    write_u16(&mut elf, 18, 243);
    write_u32(&mut elf, 20, 1);
    write_u64(&mut elf, 24, ENTRY_ADDRESS);
    write_u64(&mut elf, 32, ELF_HEADER_BYTES as u64);
    write_u16(&mut elf, 52, ELF_HEADER_BYTES as u16);
    write_u16(&mut elf, 54, PROGRAM_HEADER_BYTES as u16);
    write_u16(&mut elf, 56, 1);

    let program_header = ELF_HEADER_BYTES;
    write_u32(&mut elf, program_header, 1);
    write_u32(&mut elf, program_header + 4, 5);
    write_u64(&mut elf, program_header + 8, SEGMENT_OFFSET as u64);
    write_u64(&mut elf, program_header + 16, ENTRY_ADDRESS);
    write_u64(&mut elf, program_header + 24, ENTRY_ADDRESS);
    write_u64(&mut elf, program_header + 32, code_bytes as u64);
    write_u64(&mut elf, program_header + 40, code_bytes as u64);
    write_u64(&mut elf, program_header + 48, 4096);
    elf[SEGMENT_OFFSET..SEGMENT_OFFSET + code_bytes].copy_from_slice(code);
    Ok(elf)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
