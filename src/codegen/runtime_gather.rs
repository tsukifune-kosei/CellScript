use super::*;

// Private descriptors are (pointer-or-offset, length, kind), with kind 0
// meaning local memory and kind 1 meaning a prevalidated transaction span.
// No user-supplied machine pointer crosses either public interface.
impl CodeGenerator {
    /// Exact, unhashed bytes: a0=view, a1=offset, a3=out[32]; a0=status.
    pub(super) fn emit_runtime_witness_bytes32(&mut self, enabled: bool) {
        self.emit_global("__ckb_witness_bytes32");
        self.emit_label("__ckb_witness_bytes32");
        if !enabled {
            self.emit_fail(CellScriptRuntimeError::SyscallFailed);
            return;
        }
        let failed = self.fresh_label("witness_bytes32_failed");
        let invalid = self.fresh_label("witness_bytes32_invalid");
        let ready = self.fresh_label("witness_bytes32_ready");
        let done = self.fresh_label("witness_bytes32_done");
        self.emit_large_addi("sp", "sp", -32);
        self.emit_stack_store("a1", 0);
        self.emit_stack_store("a3", 8);
        self.emit_stack_store("ra", 24);
        self.emit_decode_source_view_to_t1_t2(&invalid);
        for source in
            [CKB_SOURCE_INPUT, CKB_SOURCE_OUTPUT, CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_INPUT, CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_OUTPUT]
        {
            self.emit(format!("li t0, {source}"));
            self.emit(format!("beq t0, t2, {ready}"));
        }
        self.emit(format!("j {invalid}"));
        self.emit_label(&ready);
        self.emit("li t0, 32");
        self.emit_stack_store("t0", 16);
        self.emit_stack_load("a0", 8);
        self.emit_sp_addi("a1", 16);
        self.emit_stack_load("a2", 0);
        self.emit("mv a3, t1");
        self.emit("mv a4, t2");
        self.emit(format!("li a7, {}", self.runtime_abi().load_witness));
        self.emit("ecall");
        self.emit(format!("bnez a0, {failed}"));
        self.emit_stack_load("t0", 16);
        self.emit("li t1, 32");
        self.emit(format!("bltu t0, t1, {failed}"));
        self.emit("li a0, 0");
        self.emit(format!("j {done}"));
        self.emit_label(&invalid);
        self.emit(format!("li a0, {}", CellScriptRuntimeError::CkbSourceViewInvalid.code()));
        self.emit(format!("j {done}"));
        self.emit_label(&failed);
        self.emit(format!("li a0, {}", CellScriptRuntimeError::SyscallFailed.code()));
        self.emit_label(&done);
        self.emit_stack_load("ra", 24);
        self.emit_large_addi("sp", "sp", 32);
        self.emit("ret");
    }

    /// Fill one 128-byte block in the existing BLAKE2b frame. The descriptor
    /// cursor persists between blocks. All working registers are caller-saved;
    /// syscalls cannot invalidate the saved cursor or requested read length.
    pub(super) fn emit_runtime_blake2b_segment_block(&mut self) {
        const M: usize = 192;
        const PTR: usize = 320;
        const CHUNK: usize = 352;
        const INDEX: usize = 360;
        const SOURCE: usize = 368;
        const SIZE: usize = 376;
        const SYSCALL: usize = 384;
        const SEGMENT: usize = 392;
        const OFFSET: usize = 400;
        const FILLED: usize = 408;
        const COUNT: usize = 416;
        const READ: usize = 424;
        let scan = self.fresh_label("gather_block_scan");
        let advance = self.fresh_label("gather_segment_advance");
        let amount_ready = self.fresh_label("gather_amount_ready");
        let memory = self.fresh_label("gather_memory");
        let copy = self.fresh_label("gather_copy");
        let copied = self.fresh_label("gather_copied");
        let failed = self.fresh_label("gather_block_failed");
        let done = self.fresh_label("gather_block_done");
        self.emit_stack_store("zero", FILLED);
        self.emit_label(&scan);
        self.emit_stack_load("t0", FILLED);
        self.emit_stack_load("t1", CHUNK);
        self.emit(format!("beq t0, t1, {done}"));
        self.emit("sub t1, t1, t0"); // remaining block bytes
        self.emit_stack_load("t2", SEGMENT);
        self.emit_stack_load("t3", COUNT);
        self.emit(format!("bgeu t2, t3, {failed}"));
        self.emit("li t3, 24");
        self.emit("mul t2, t2, t3");
        self.emit_stack_load("t3", PTR);
        self.emit("add t2, t2, t3");
        self.emit("ld t3, 8(t2)"); // descriptor length
        self.emit_stack_load("t4", OFFSET);
        self.emit(format!("beq t3, t4, {advance}"));
        self.emit(format!("bltu t3, t4, {failed}"));
        self.emit("sub t3, t3, t4");
        self.emit(format!("bgeu t3, t1, {amount_ready}"));
        self.emit("mv t1, t3");
        self.emit_label(&amount_ready);
        self.emit_stack_store("t1", READ);
        self.emit_stack_store("t1", SIZE);
        self.emit("ld t3, 0(t2)");
        self.emit("add t3, t3, t4"); // pointer/offset plus segment cursor
        self.emit("ld t4, 16(t2)");
        self.emit(format!("beqz t4, {memory}"));
        self.emit_sp_addi("a0", M);
        self.emit("add a0, a0, t0");
        self.emit_sp_addi("a1", SIZE);
        self.emit("mv a2, t3");
        self.emit_stack_load("a3", INDEX);
        self.emit_stack_load("a4", SOURCE);
        self.emit_stack_load("a7", SYSCALL);
        self.emit("ecall");
        self.emit(format!("bnez a0, {failed}"));
        self.emit_stack_load("t0", SIZE);
        self.emit_stack_load("t1", READ);
        self.emit(format!("bltu t0, t1, {failed}"));
        self.emit(format!("j {copied}"));
        self.emit_label(&memory);
        self.emit_sp_addi("t2", M);
        self.emit("add t2, t2, t0");
        self.emit_label(&copy);
        self.emit(format!("beqz t1, {copied}"));
        self.emit("lbu t4, 0(t3)");
        self.emit("sb t4, 0(t2)");
        self.emit("addi t2, t2, 1");
        self.emit("addi t3, t3, 1");
        self.emit("addi t1, t1, -1");
        self.emit(format!("j {copy}"));
        self.emit_label(&copied);
        self.emit_stack_load("t0", READ);
        for slot in [FILLED, OFFSET] {
            self.emit_stack_load("t1", slot);
            self.emit("add t1, t1, t0");
            self.emit_stack_store("t1", slot);
        }
        self.emit(format!("j {scan}"));
        self.emit_label(&advance);
        self.emit_stack_load("t0", SEGMENT);
        self.emit("addi t0, t0, 1");
        self.emit_stack_store("t0", SEGMENT);
        self.emit_stack_store("zero", OFFSET);
        self.emit(format!("j {scan}"));
        self.emit_label(&failed);
        self.emit_large_addi("sp", "sp", 432);
        self.emit(format!("li a0, {}", CellScriptRuntimeError::SyscallFailed.code()));
        self.emit("ret");
        self.emit_label(&done);
    }

    /// t0=pointer/offset, t1=length, t2=kind. Clobbers t3..t6, preserves
    /// t0..t2. Only checked wrapper code can append these descriptors.
    fn emit_gather_descriptor(&mut self, failed: &str) {
        self.emit_stack_load("t3", 104);
        self.emit("li t4, 258");
        self.emit(format!("bgeu t3, t4, {failed}"));
        self.emit("li t4, 24");
        self.emit("mul t4, t3, t4");
        self.emit("add t4, sp, t4");
        self.emit("addi t4, t4, 128");
        self.emit("sd t0, 0(t4)");
        self.emit("sd t1, 8(t4)");
        self.emit("sd t2, 16(t4)");
        self.emit("addi t3, t3, 1");
        self.emit_stack_store("t3", 104);
        self.emit_stack_load("t5", 112);
        self.emit("add t6, t5, t1");
        self.emit(format!("bltu t6, t5, {failed}"));
        self.emit_stack_store("t6", 112);
    }

    /// Transaction gather ABI: a0=offset Vec<u64>, a1=length Vec<u64>,
    /// a2=prefix Vec<u8>, a3=suffix Vec<u8>, a4=out[32].
    /// Witness selection ABI: a0=view, a1=start, a2=stride, a3=selection
    /// Vec<u8>, a4=prefix Vec<u8>, a5=suffix Vec<u8>, a6=out[32].
    pub(super) fn emit_runtime_gather_hash(&mut self, enabled: bool, select: bool) {
        const FRAME: i64 = 6320; // 128 header + 258 descriptors * 24
        let symbol = if select { "__ckb_witness_blake2b_select_chunks" } else { "__ckb_transaction_blake2b_gather" };
        self.emit_global(symbol);
        self.emit_label(symbol);
        if !enabled {
            self.emit_fail(CellScriptRuntimeError::SyscallFailed);
            return;
        }
        let failed = self.fresh_label("gather_prepare_failed");
        let invalid = self.fresh_label("gather_invalid_source");
        let source_ready = self.fresh_label("gather_source_ready");
        let scan = self.fresh_label("gather_prepare_scan");
        let skip = self.fresh_label("gather_prepare_skip");
        let scanned = self.fresh_label("gather_prepare_scanned");
        let done = self.fresh_label("gather_done");
        self.emit_large_addi("sp", "sp", -FRAME);
        for (i, reg) in ["a0", "a1", "a2", "a3", "a4", "a5", "a6"].iter().enumerate() {
            self.emit_stack_store(reg, i * 8);
        }
        self.emit_stack_store("ra", 56);
        if select {
            self.emit_decode_source_view_to_t1_t2(&invalid);
            for source in [
                CKB_SOURCE_INPUT,
                CKB_SOURCE_OUTPUT,
                CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_INPUT,
                CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_OUTPUT,
            ] {
                self.emit(format!("li t0, {source}"));
                self.emit(format!("beq t0, t2, {source_ready}"));
            }
            self.emit(format!("j {invalid}"));
            self.emit_label(&source_ready);
            self.emit_stack_store("t1", 64);
            self.emit_stack_store("t2", 72);
        } else {
            self.emit_stack_store("zero", 64);
            self.emit_stack_store("zero", 72);
        }
        self.emit(format!("li t0, {}", if select { self.runtime_abi().load_witness } else { 2051 }));
        self.emit_stack_store("t0", 80);
        self.emit_stack_store("zero", 88);
        self.emit_sp_addi("a0", 96);
        self.emit_sp_addi("a1", 88);
        self.emit("li a2, 0");
        self.emit_stack_load("a3", 64);
        self.emit_stack_load("a4", 72);
        self.emit_stack_load("a7", 80);
        self.emit("ecall");
        self.emit(format!("bnez a0, {failed}"));
        self.emit_stack_load("t0", 88);
        self.emit_stack_store("t0", 96); // complete source length
        self.emit_stack_store("zero", 104); // descriptor count
        self.emit_stack_store("zero", 112); // concatenated length
        self.emit_stack_store("zero", 120); // selected chunk / offset iterator

        self.emit_stack_load("t0", if select { 32 } else { 16 });
        self.emit("ld t1, -8(t0)");
        self.emit("li t2, 256");
        self.emit(format!("bltu t2, t1, {failed}"));
        self.emit("li t2, 0");
        self.emit_gather_descriptor(&failed);
        // Keep the vector count in slot 88 now that probing is finished.
        self.emit_stack_load("t0", if select { 24 } else { 0 });
        self.emit("ld t1, -8(t0)");
        self.emit(format!("li t2, {}", if select { 256 } else { 32 }));
        self.emit(format!("bltu t2, t1, {failed}"));
        self.emit_stack_store("t1", 88);
        if select {
            self.emit_stack_load("t2", 96);
            self.emit_stack_load("t3", 8);
            self.emit(format!("bltu t2, t3, {failed}"));
            self.emit("sub t2, t2, t3");
            let bounded = self.fresh_label("gather_selection_bounded");
            self.emit(format!("beqz t1, {bounded}"));
            self.emit("divu t2, t2, t1");
            self.emit_stack_load("t3", 16);
            self.emit(format!("bltu t2, t3, {failed}"));
            self.emit_label(&bounded);
        } else {
            self.emit_stack_load("t2", 8);
            self.emit("ld t2, -8(t2)");
            self.emit(format!("bne t1, t2, {failed}"));
        }
        self.emit_label(&scan);
        self.emit_stack_load("t0", 120);
        self.emit_stack_load("t1", 88);
        self.emit(format!("bgeu t0, t1, {scanned}"));
        if select {
            self.emit_stack_load("t2", 24);
            self.emit("add t2, t2, t0");
            self.emit("lbu t2, 0(t2)");
            self.emit("li t3, 1");
            self.emit(format!("bltu t3, t2, {failed}"));
            self.emit(format!("beqz t2, {skip}"));
            self.emit_stack_load("t1", 16);
            self.emit("mul t0, t0, t1");
            self.emit_stack_load("t2", 8);
            self.emit("add t0, t0, t2");
        } else {
            self.emit("slli t0, t0, 3");
            self.emit_stack_load("t1", 8);
            self.emit("add t1, t1, t0");
            self.emit("ld t1, 0(t1)");
            self.emit_stack_load("t2", 0);
            self.emit("add t0, t0, t2");
            self.emit("ld t0, 0(t0)");
            self.emit_stack_load("t2", 96);
            self.emit(format!("bltu t2, t0, {failed}"));
            self.emit("sub t2, t2, t0");
            self.emit(format!("bltu t2, t1, {failed}"));
        }
        self.emit("li t2, 1");
        self.emit_gather_descriptor(&failed);
        self.emit_label(&skip);
        self.emit_stack_load("t0", 120);
        self.emit("addi t0, t0, 1");
        self.emit_stack_store("t0", 120);
        self.emit(format!("j {scan}"));
        self.emit_label(&scanned);
        self.emit_stack_load("t0", if select { 40 } else { 24 });
        self.emit("ld t1, -8(t0)");
        self.emit("li t2, 256");
        self.emit(format!("bltu t2, t1, {failed}"));
        self.emit("li t2, 0");
        self.emit_gather_descriptor(&failed);
        self.emit_sp_addi("a0", 128);
        self.emit_stack_load("a1", 104);
        self.emit_stack_load("a2", 64);
        self.emit_stack_load("a3", 72);
        self.emit_stack_load("a4", 80);
        self.emit_stack_load("a5", if select { 48 } else { 32 });
        self.emit_stack_load("a6", 112);
        self.emit("call __cellscript_blake2b_segments");
        self.emit(format!("j {done}"));
        self.emit_label(&invalid);
        self.emit(format!("li a0, {}", CellScriptRuntimeError::CkbSourceViewInvalid.code()));
        self.emit(format!("j {done}"));
        self.emit_label(&failed);
        self.emit(format!("li a0, {}", CellScriptRuntimeError::SyscallFailed.code()));
        self.emit_label(&done);
        self.emit_stack_load("ra", 56);
        self.emit_large_addi("sp", "sp", FRAME);
        self.emit("ret");
    }

    /// Exact four-byte read from the complete packed Transaction. a0=offset;
    /// returns a0=value, a1=status. LOAD_TRANSACTION uses no Cell source view.
    pub(super) fn emit_runtime_transaction_u32(&mut self, enabled: bool) {
        self.emit_global("__ckb_transaction_u32_le");
        self.emit_label("__ckb_transaction_u32_le");
        if !enabled {
            self.emit_fail(CellScriptRuntimeError::SyscallFailed);
            return;
        }
        let failed = self.fresh_label("transaction_u32_failed");
        let done = self.fresh_label("transaction_u32_done");
        self.emit_large_addi("sp", "sp", -32);
        self.emit_stack_store("ra", 24);
        self.emit("mv a2, a0");
        self.emit("li t0, 4");
        self.emit_stack_store("t0", 0);
        self.emit_sp_addi("a0", 8);
        self.emit_sp_addi("a1", 0);
        self.emit("li a7, 2051");
        self.emit("ecall");
        self.emit(format!("bnez a0, {failed}"));
        self.emit_stack_load("t0", 0);
        self.emit("li t1, 4");
        self.emit(format!("bltu t0, t1, {failed}"));
        self.emit("li a0, 0");
        for byte in 0..4 {
            self.emit_stack_load_byte("t0", 8 + byte);
            self.emit(format!("slli t0, t0, {}", byte * 8));
            self.emit("or a0, a0, t0");
        }
        self.emit("li a1, 0");
        self.emit(format!("j {done}"));
        self.emit_label(&failed);
        self.emit("li a0, 0");
        self.emit(format!("li a1, {}", CellScriptRuntimeError::SyscallFailed.code()));
        self.emit_label(&done);
        self.emit_stack_load("ra", 24);
        self.emit_large_addi("sp", "sp", 32);
        self.emit("ret");
    }
}
