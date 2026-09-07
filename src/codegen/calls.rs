use super::*;

impl CodeGenerator {
    fn emit_ckb_fixed_hash_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !is_ckb_fixed_hash_helper(func) {
            return Ok(false);
        }
        self.emit(format!("# call {}", func));
        let Some(dest) = dest else {
            self.emit("# cellscript abi: fail closed because hash helper result has no destination");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: fail closed because hash helper output buffer was not allocated");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        if matches!(func, "__ckb_hash_pair" | "__ckb_hash_sha256_pair" | "__ckb_hash_sha256d_pair") {
            if args.len() != 2 {
                self.emit("# cellscript abi: fail closed because hash_pair needs two inputs");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            }
            let Some(left) = self.expected_fixed_byte_source(&args[0], 32) else {
                self.emit("# cellscript abi: fail closed because hash_pair left input is not a 32-byte value");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            };
            let Some(right) = self.expected_fixed_byte_source(&args[1], 32) else {
                self.emit("# cellscript abi: fail closed because hash_pair right input is not a 32-byte value");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            };
            self.emit_prepare_fixed_byte_source(&left, 32, "pair hash left input");
            self.emit_prepare_fixed_byte_source(&right, 32, "pair hash right input");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &left) {
                self.emit("# cellscript abi: fail closed because hash_pair left pointer is not materializable");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            }
            if !self.emit_fixed_byte_source_pointer_or_const_to("a1", &right) {
                self.emit("# cellscript abi: fail closed because hash_pair right pointer is not materializable");
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            }
            self.emit_sp_addi("a2", dest_offset);
            self.emit(format!("call {}", func));
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_sp_addi("t0", dest_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(true);
        }
        if func == "__ckb_hash_blake2b_packed" {
            let Some(arg) = args.first() else {
                self.emit("# cellscript abi: fail closed because hash_blake2b_packed is missing input");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            let Some(width) = operand_fixed_byte_width(arg).or_else(|| match arg {
                IrOperand::Var(var) => self.fixed_byte_like_width(&var.ty),
                _ => None,
            }) else {
                self.emit("# cellscript abi: fail closed because hash_blake2b_packed input has no static packed width");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            let Some(source) = self.expected_fixed_byte_source(arg, width) else {
                self.emit("# cellscript abi: fail closed because hash_blake2b_packed input is not materializable");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            let type_name = match arg {
                IrOperand::Var(var) => named_type_name(&var.ty).map(str::to_string).unwrap_or_else(|| aggregate_type_label(&var.ty)),
                IrOperand::Const(_) => "const".to_string(),
            };
            let mut header = b"CellScriptPackedHashV0\0".to_vec();
            header.extend_from_slice(type_name.as_bytes());
            header.push(0);
            header.extend_from_slice(&(width as u32).to_le_bytes());
            let total_width = header.len() + width;
            if total_width > RUNTIME_SCRATCH_BUFFER_SIZE {
                self.emit("# cellscript abi: fail closed because hash_blake2b_packed preimage exceeds scratch buffer");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            }
            let buffer_offset = self.runtime_scratch_buffer_offset();
            for (index, byte) in header.iter().enumerate() {
                self.emit(format!("li t0, {}", byte));
                self.emit_stack_store_byte("t0", buffer_offset + index);
            }
            self.emit_prepare_fixed_byte_source(&source, width, "hash_blake2b_packed input");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
                self.emit("# cellscript abi: fail closed because hash_blake2b_packed input pointer is not materializable");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            }
            self.emit_sp_addi("a1", buffer_offset + header.len());
            self.emit(format!("li a2, {}", width));
            self.emit("call __cellscript_memcpy_fixed");
            self.emit_sp_addi("a0", buffer_offset);
            self.emit(format!("li a1, {}", total_width));
            self.emit_sp_addi("a2", dest_offset);
            self.emit("call __ckb_hash_blake2b_var");
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_sp_addi("t0", dest_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(true);
        }
        if func == "__ckb_hash_data_packed" {
            let Some(arg) = args.first() else {
                self.emit("# cellscript abi: fail closed because hash_data_packed is missing input");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            let Some(width) = operand_fixed_byte_width(arg).or_else(|| match arg {
                IrOperand::Var(var) => self.fixed_byte_like_width(&var.ty),
                _ => None,
            }) else {
                self.emit("# cellscript abi: fail closed because hash_data_packed input has no static packed width");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            let Some(source) = self.expected_fixed_byte_source(arg, width) else {
                self.emit("# cellscript abi: fail closed because hash_data_packed input is not materializable");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            };
            self.emit_prepare_fixed_byte_source(&source, width, "hash_data_packed input");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
                self.emit("# cellscript abi: fail closed because hash_data_packed input pointer is not materializable");
                self.emit_fail(CellScriptRuntimeError::PackedHashPreimageMaterializationUnresolved);
                return Ok(true);
            }
            self.emit(format!("li a1, {}", width));
            self.emit_sp_addi("a2", dest_offset);
            self.emit("call __ckb_hash_blake2b_var");
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_sp_addi("t0", dest_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(true);
        }
        let Some(arg) = args.first() else {
            self.emit("# cellscript abi: fail closed because hash helper is missing input");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(source) = self.expected_fixed_byte_source(arg, 32) else {
            self.emit("# cellscript abi: fail closed because hash helper input is not a 32-byte value");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        self.emit_prepare_fixed_byte_source(&source, 32, "fixed hash input");
        if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
            self.emit("# cellscript abi: fail closed because hash helper input pointer is not materializable");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        }
        self.emit_sp_addi("a1", dest_offset);
        self.emit(format!("call {}", func));
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    pub(super) fn emit_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<()> {
        if let Some(deferred) = crate::ir::IrDeferredRuntimeFeature::from_helper(func) {
            self.emit(format!("# cellscript deferred runtime contract: {}", deferred.feature()));
            self.emit_process_failure(deferred.runtime_error());
            return Ok(());
        }
        if matches!(func, crate::ir::BOUNDED_CONSUME_EACH_FAIL_CLOSED_HELPER | crate::ir::BOUNDED_CREATE_EACH_FAIL_CLOSED_HELPER) {
            self.emit(format!(
                "# cellscript bounded collection: {} has no executable source-selection/codec/correspondence contract; fail closed",
                func
            ));
            self.emit_fail(CellScriptRuntimeError::CollectionRuntimeUnsupported);
            return Ok(());
        }
        if self.emit_ckb_fixed_hash_call(dest, func, args)? {
            return Ok(());
        }
        if matches!(func, "__novaseal_bip340_require_signature" | "__novaseal_bip340_require_signature_from_cell_dep") {
            self.emit(format!("# call {} args={}", func, args.len()));
            let explicit_dep = func == "__novaseal_bip340_require_signature_from_cell_dep";
            let value_offset = usize::from(explicit_dep);
            if args.len() != 3 + value_offset {
                self.emit("# cellscript abi: fail closed because BIP340 verifier requires message, pubkey, signature");
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            }
            let Some(message) = self.expected_fixed_byte_source(&args[value_offset], 32) else {
                self.emit("# cellscript abi: fail closed because BIP340 message is not a 32-byte value");
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            };
            let Some(pubkey) = self.expected_fixed_byte_source(&args[value_offset + 1], 32) else {
                self.emit("# cellscript abi: fail closed because BIP340 pubkey is not a 32-byte value");
                self.emit_fail(CellScriptRuntimeError::Bip340PubkeyMaterializationUnresolved);
                return Ok(());
            };
            let Some(signature) = self.expected_fixed_byte_source(&args[value_offset + 2], 64) else {
                self.emit("# cellscript abi: fail closed because BIP340 signature is not a 64-byte value");
                self.emit_fail(CellScriptRuntimeError::Bip340SignatureMaterializationUnresolved);
                return Ok(());
            };
            self.emit_prepare_fixed_byte_source(&message, 32, "novaseal bip340 message");
            self.emit_prepare_fixed_byte_source(&pubkey, 32, "novaseal bip340 pubkey");
            self.emit_prepare_fixed_byte_source(&signature, 64, "novaseal bip340 signature");
            let Some(read_fd_offset) = self.checked_runtime_expr_temp_offset(0) else {
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            };
            let Some(write_fd_offset) = self.checked_runtime_expr_temp_offset(1) else {
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            };
            let Some(child_pid_offset) = self.checked_runtime_expr_temp_offset(2) else {
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            };
            let ipc_buffer_offset = self.runtime_scratch_buffer_offset();
            self.emit("# cellscript abi: NovaSeal BIP340 verifier IPC envelope via VM2 pipe/spawn/wait");
            let pipe_ok = self.fresh_label("novaseal_bip340_pipe_ok");
            self.emit("call __ckb_pipe");
            self.emit(format!("beqz a0, {}", pipe_ok));
            self.emit_fail(CellScriptRuntimeError::Bip340PipeCreateFailed);
            self.emit_label(&pipe_ok);
            self.emit_stack_store("a1", read_fd_offset);
            self.emit_stack_store("a2", write_fd_offset);
            self.emit("# cellscript abi: materialize cellscript-btc-bip340-ipc-v0 envelope in scratch");
            for (index, byte) in b"NSBV0IPC".iter().enumerate() {
                self.emit(format!("li t0, {}", byte));
                self.emit_stack_store_byte("t0", ipc_buffer_offset + index);
            }
            for (index, byte) in [0u8, 0, 1, 0, 0, 0, 0, 0].iter().enumerate() {
                self.emit(format!("li t0, {}", byte));
                self.emit_stack_store_byte("t0", ipc_buffer_offset + 8 + index);
            }
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &message) {
                self.emit_fail(CellScriptRuntimeError::Bip340MessageMaterializationUnresolved);
                return Ok(());
            }
            self.emit_sp_addi("a1", ipc_buffer_offset + 16);
            self.emit("li a2, 32");
            self.emit("call __cellscript_memcpy_fixed");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &pubkey) {
                self.emit_fail(CellScriptRuntimeError::Bip340PubkeyMaterializationUnresolved);
                return Ok(());
            }
            self.emit_sp_addi("a1", ipc_buffer_offset + 48);
            self.emit("li a2, 32");
            self.emit("call __cellscript_memcpy_fixed");
            if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &signature) {
                self.emit_fail(CellScriptRuntimeError::Bip340SignatureMaterializationUnresolved);
                return Ok(());
            }
            self.emit_sp_addi("a1", ipc_buffer_offset + 80);
            self.emit("li a2, 64");
            self.emit("call __cellscript_memcpy_fixed");
            self.emit("# cellscript abi: spawn manifest-bound verifier CellDep with prepared read fd inherited");
            if explicit_dep {
                self.emit_operand_to_register("a0", &args[0]);
            } else {
                self.emit("li a0, 0");
            }
            self.emit_stack_load("a1", read_fd_offset);
            self.emit("call __ckb_spawn_with_fd1");
            let spawn_ok = self.fresh_label("novaseal_bip340_spawn_ok");
            self.emit(format!("beqz a0, {}", spawn_ok));
            self.emit_fail(CellScriptRuntimeError::Bip340SpawnFailed);
            self.emit_label(&spawn_ok);
            self.emit_stack_store("a1", child_pid_offset);
            self.emit("# cellscript abi: BIP340 IPC write canonical 18-word little-endian envelope");
            for word_index in 0..18 {
                self.emit(format!("# cellscript abi: novaseal bip340 ipc word {}", word_index));
                self.emit_stack_load("a0", write_fd_offset);
                self.emit_stack_load("a1", ipc_buffer_offset + word_index * 8);
                self.emit("call __ckb_pipe_write");
                let write_ok = self.fresh_label("novaseal_bip340_write_ok");
                self.emit(format!("beqz a0, {}", write_ok));
                self.emit_fail(CellScriptRuntimeError::Bip340MessageWriteFailed);
                self.emit_label(&write_ok);
            }
            self.emit_stack_load("a0", write_fd_offset);
            self.emit("call __ckb_close");
            let close_ok = self.fresh_label("novaseal_bip340_close_ok");
            self.emit(format!("beqz a0, {}", close_ok));
            self.emit_fail(CellScriptRuntimeError::Bip340VerifierReadFailed);
            self.emit_label(&close_ok);
            self.emit_stack_load("a0", child_pid_offset);
            self.emit("call __ckb_wait");
            let wait_ok = self.fresh_label("novaseal_bip340_wait_ok");
            self.emit(format!("beqz a0, {}", wait_ok));
            self.emit_fail(CellScriptRuntimeError::Bip340ChildRejected);
            self.emit_label(&wait_ok);
            return Ok(());
        }
        if func.contains("::") {
            return Err(CompileError::new(
                format!("qualified function call '{}' reached codegen without IR label normalization; this is a compiler bug", func),
                crate::error::Span::default(),
            ));
        }
        self.emit(format!("# call {}", func));

        if self.emit_runtime_fixed_hash_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_bounded_cell_dep_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_sha256d_merkle_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_cell_script_args_exact_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_cell_script_hash_type_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_input_out_point_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_xudt_type_args_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_xudt_group_amount_delta_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_metapoint_filtered_pair_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_c256_product_requirement_call(func, args)? {
            return Ok(());
        }
        if self.emit_runtime_c256_sum2_product_requirement_call(func, args)? {
            return Ok(());
        }
        if matches!(func, "__ckb_exec_cell_dep_hex4" | "__ckb_spawn_wait_cell_dep_hex4") {
            let Some(IrOperand::Var(bytes)) = args.get(1) else {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(());
            };
            if args.len() != 6 || bytes.ty != IrType::Named("Vec<u8>".into()) || !self.stack_collection_vars.contains(&bytes.id) {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(());
            }
            self.emit_operand_to_register("a0", &args[0]);
            self.emit_operand_to_register("a1", &args[1]);
            self.emit("ld a2, -8(a1)"); // proven local byte-vector count
            for (arg, register) in args[2..].iter().zip(["a3", "a4", "a5", "a6"]) {
                self.emit_operand_to_register(register, arg);
            }
            self.emit(format!("call {func}"));
            let ok = self.fresh_label("hex4_checked_return");
            self.emit(format!("beqz a0, {ok}"));
            self.emit_process_failure_status();
            self.emit_label(&ok);
            return Ok(());
        }
        if self.emit_runtime_current_script_hash_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_input_out_point_tx_hash_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_cell_data_hash_at_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_span_hash_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_cell_script_hash_field_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_witness_hash_call(dest, func, args)? {
            return Ok(());
        }
        if self.emit_runtime_source_memory_equality_call(dest, func, args)? {
            return Ok(());
        }

        let abi = self.callable_abis.get(func).cloned();
        let outgoing_stack_arg_bytes = align_stack_arg_bytes(call_abi_arg_count(abi.as_ref(), args).saturating_sub(8) * 8);
        let mut abi_index = 0usize;
        for (arg_index, arg) in args.iter().enumerate() {
            if let Some(abi) = &abi
                && let Some(param) = abi.params.get(arg_index)
            {
                let needs_type_hash = abi.type_hash_param_indices.contains(&arg_index);
                if !self.emit_call_param_arg(func, param, needs_type_hash, &mut abi_index, arg, outgoing_stack_arg_bytes) {
                    return Ok(());
                }
                continue;
            }
            if !self.emit_call_scalar_arg(func, &format!("arg{}", arg_index), &mut abi_index, arg, outgoing_stack_arg_bytes) {
                return Ok(());
            }
        }

        if outgoing_stack_arg_bytes > 0 {
            self.emit(format!("# cellscript abi: reserve {} bytes for outgoing stack call arguments", outgoing_stack_arg_bytes));
            self.emit_large_addi("sp", "sp", -(outgoing_stack_arg_bytes as i64));
        }
        if is_cached_exact_read_helper(func) {
            if !self.module_uses_exact_read_cache {
                self.emit_fail(CellScriptRuntimeError::SyscallFailed);
                return Ok(());
            }
            self.emit("mv a2, s11");
        }
        self.emit(format!("call {}", func));
        if outgoing_stack_arg_bytes > 0 {
            self.emit_large_addi("sp", "sp", outgoing_stack_arg_bytes as i64);
        }

        // Exact cached reads terminate inside their shared runtime helper on
        // any invalid source or syscall failure. Successful calls therefore
        // return only the scalar value in a0 and need no per-call status
        // branch. Other scalar runtime helpers retain the a1 status ABI.
        if is_runtime_scalar_failclosed_call(func) && !is_terminal_scalar_runtime_helper(func) {
            let ok_label = self.fresh_label("runtime_scalar_ok");
            self.emit("# cellscript abi: scalar runtime helper status check (a1 == 0)");
            self.emit(format!("beqz a1, {}", ok_label));
            self.emit("addi a0, a1, 0");
            self.emit_process_failure_status();
            self.emit_label(&ok_label);
        }

        if is_void_runtime_requirement_call(func) {
            let ok_label = self.fresh_label("runtime_requirement_ok");
            self.emit(format!("beqz a0, {}", ok_label));
            self.emit_process_failure_status();
            self.emit_label(&ok_label);
        }

        if let Some(d) = dest {
            let payload_enum = match &d.ty {
                IrType::Named(name) => {
                    self.enum_layouts.get(name).filter(|layout| layout.has_payload()).map(|layout| (name.clone(), layout.clone()))
                }
                _ => None,
            };
            if let Some((name, layout)) = payload_enum {
                if let Some(offset) = self.fixed_byte_local_offsets.get(&d.id).copied() {
                    self.emit(format!(
                        "# cellscript abi: receive payload enum {} size={} from a0/a1 register pair",
                        name, layout.encoded_size
                    ));
                    let low_width = layout.encoded_size.min(8);
                    for byte_index in 0..low_width {
                        self.emit_stack_store_byte("a0", offset + byte_index);
                        if byte_index + 1 < low_width {
                            self.emit("srli a0, a0, 8");
                        }
                    }
                    if layout.encoded_size > 8 {
                        let high_width = layout.encoded_size - 8;
                        for byte_index in 0..high_width {
                            self.emit_stack_store_byte("a1", offset + 8 + byte_index);
                            if byte_index + 1 < high_width {
                                self.emit("srli a1, a1, 8");
                            }
                        }
                    }
                    self.emit_sp_addi("t0", offset);
                    self.emit_stack_store("t0", d.id * 8);
                } else {
                    self.emit("# cellscript abi: payload enum call destination has no storage; fail closed");
                    self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                }
            } else if d.ty == IrType::U128 {
                if let Some(offset) = self.u128_value_offsets.get(&d.id).copied() {
                    self.emit("# cellscript abi: receive u128 return from a0(low)/a1(high)");
                    self.emit_stack_store("a0", offset);
                    self.emit_stack_store("a1", offset + 8);
                    self.emit_store_u128_pointer_for_var(d.id, offset);
                } else {
                    self.emit("# cellscript abi: u128 call destination has no storage; fail closed");
                    self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                }
            } else if let IrType::Tuple(items) = &d.ty {
                self.emit_stack_store("a0", d.id * 8);
                for index in 0..items.len().min(8) {
                    let field = index.to_string();
                    if let Some(field_var_id) = self.tuple_call_return_field_slots.get(&(d.id, field)).copied() {
                        self.emit_stack_store(&format!("a{}", index), field_var_id * 8);
                    }
                }
            } else {
                self.emit_stack_store("a0", d.id * 8);
            }
        }

        Ok(())
    }

    fn emit_runtime_source_memory_equality_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_source_bytes_equal_memory" {
            return Ok(false);
        }
        let Some(dest) = dest else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let [view, base, memory, length, kind] = args else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        if dest.ty != IrType::Bool {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        }
        let Some(width) = (match memory {
            IrOperand::Var(var) => self.fixed_byte_like_width(&var.ty),
            IrOperand::Const(_) => operand_fixed_byte_width(memory),
        }) else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(source) = self.expected_fixed_byte_source(memory, width) else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        self.emit_prepare_fixed_byte_source(&source, width, "source byte-range memory operand");
        self.emit_operand_to_register("a0", view);
        self.emit_operand_to_register("a1", base);
        if !self.emit_fixed_byte_source_pointer_or_const_to("a2", &source) {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        }
        self.emit_operand_to_register("a3", length);
        self.emit_operand_to_register("a4", kind);
        self.emit("call __ckb_source_bytes_equal_memory");
        let ok = self.fresh_label("source_memory_equal_status_ok");
        self.emit("# cellscript abi: source-memory equality status check (a1 == 0)");
        self.emit(format!("beqz a1, {ok}"));
        self.emit("addi a0, a1, 0");
        self.emit_process_failure_status();
        self.emit_label(&ok);
        self.emit_stack_store("a0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_current_script_hash_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_current_script_hash" {
            return Ok(false);
        }
        let Some(dest) = dest else {
            return Ok(false);
        };
        if !args.is_empty() || dest.ty != IrType::Hash {
            return Ok(false);
        }
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: current script hash destination has no 32-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: current script hash destination has no buffer storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        self.emit("# cellscript abi: load current script hash into addressable Hash");
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", size_offset);
        self.emit_sp_addi("a0", buffer_offset);
        self.emit_sp_addi("a1", size_offset);
        self.emit("call __ckb_current_script_hash");
        let ok_label = self.fresh_label("current_script_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_input_out_point_tx_hash_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_input_out_point_tx_hash" {
            return Ok(false);
        }
        let Some(dest) = dest else {
            return Ok(false);
        };
        if args.len() != 1 || dest.ty != IrType::Hash {
            return Ok(false);
        }
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: input OutPoint tx hash destination has no 32-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: input OutPoint tx hash destination has no buffer storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        self.emit("# cellscript abi: load SourceView input OutPoint tx hash into addressable Hash");
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", size_offset);
        self.emit_operand_to_register("a0", &args[0]);
        self.emit_sp_addi("a1", buffer_offset);
        self.emit_sp_addi("a2", size_offset);
        self.emit("call __ckb_input_out_point_tx_hash");
        let ok_label = self.fresh_label("input_out_point_tx_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_cell_script_hash_field_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(
            func,
            "__ckb_cell_lock_hash"
                | "__ckb_cell_type_hash"
                | "__ckb_cell_data_hash_field"
                | "__ckb_cell_data_hash"
                | "__ckb_cell_lock_code_hash"
                | "__ckb_cell_type_code_hash"
                | "__ckb_cell_lock_args_hash"
                | "__ckb_cell_type_args_hash"
        ) {
            return Ok(false);
        }
        let Some(dest) = dest else {
            return Ok(false);
        };
        if args.len() != 1 || dest.ty != IrType::Hash {
            return Ok(false);
        }
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: ScriptRef hash destination has no 32-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: ScriptRef hash destination has no buffer storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        self.emit("# cellscript abi: load SourceView ScriptRef hash field into addressable Hash");
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", size_offset);
        self.emit_operand_to_register("a0", &args[0]);
        self.emit_sp_addi("a1", buffer_offset);
        self.emit_sp_addi("a2", size_offset);
        self.emit(format!("call {}", func));
        let ok_label = self.fresh_label("script_ref_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_cell_data_hash_at_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_cell_data_hash_at" {
            return Ok(false);
        }
        let Some(dest) = dest else {
            return Ok(false);
        };
        if args.len() != 2 || dest.ty != IrType::Hash {
            return Ok(false);
        }
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: cell data hash-at destination has no 32-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: cell data hash-at destination has no buffer storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        self.emit("# cellscript abi: load 32 bytes from SourceView cell data into addressable Hash");
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", size_offset);
        self.emit_operand_to_register("a0", &args[0]);
        self.emit_operand_to_register("a1", &args[1]);
        self.emit_sp_addi("a2", buffer_offset);
        self.emit_sp_addi("a3", size_offset);
        self.emit("call __ckb_cell_data_hash_at");
        let ok_label = self.fresh_label("cell_data_hash_at_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_span_hash_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if matches!(func, "__ckb_transaction_blake2b_gather" | "__ckb_witness_blake2b_select_chunks") {
            let select = func == "__ckb_witness_blake2b_select_chunks";
            let Some(dest) = dest else {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            };
            let vector_start = if select { 3 } else { 0 };
            let valid = args.len() == if select { 6 } else { 4 }
                && args.iter().enumerate().skip(vector_start).all(|(index, arg)| {
                    let ty = if !select && index < 2 { "Vec<u64>" } else { "Vec<u8>" };
                    matches!(arg, IrOperand::Var(var) if var.ty == IrType::Named(ty.into()) && self.stack_collection_vars.contains(&var.id))
                });
            let (Some(size), Some(buffer)) =
                (self.cell_buffer_size_offsets.get(&dest.id).copied(), self.cell_buffer_offsets.get(&dest.id).copied())
            else {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            };
            if !valid || dest.ty != IrType::Hash {
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                return Ok(true);
            }
            self.emit("li t0, 32");
            self.emit_stack_store("t0", size);
            for (index, arg) in args.iter().enumerate() {
                self.emit_operand_to_register(&format!("a{index}"), arg);
            }
            self.emit_sp_addi(if select { "a6" } else { "a4" }, buffer);
            self.emit(format!("call {func}"));
            let ok = self.fresh_label("gather_hash_ok");
            self.emit(format!("beqz a0, {ok}"));
            self.emit_process_failure_status();
            self.emit_label(&ok);
            self.emit_sp_addi("t0", buffer);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(true);
        }
        let raw_transaction = func == "__ckb_raw_transaction_hash_without_cell_deps";
        let bytes32 = func == "__ckb_witness_bytes32";
        if !raw_transaction && !bytes32 && !matches!(func, "__ckb_cell_data_blake2b_span" | "__ckb_witness_blake2b_span") {
            return Ok(false);
        }
        let Some(dest) = dest else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        if args.len()
            != if raw_transaction {
                0
            } else if bytes32 {
                2
            } else {
                3
            }
            || dest.ty != IrType::Hash
        {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        }
        let (Some(size), Some(buffer)) =
            (self.cell_buffer_size_offsets.get(&dest.id).copied(), self.cell_buffer_offsets.get(&dest.id).copied())
        else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        self.emit("li t0, 32");
        self.emit_stack_store("t0", size);
        // Arguments are lowered scalar locals/constants. No pointer-loading
        // helper is invoked while the earlier argument registers are live.
        if !raw_transaction {
            self.emit_operand_to_register("a0", &args[0]);
            self.emit_operand_to_register("a1", &args[1]);
            if !bytes32 {
                self.emit_operand_to_register("a2", &args[2]);
            }
        }
        self.emit_sp_addi("a3", buffer);
        self.emit(format!("call {func}"));
        let ok = self.fresh_label("span_hash_ok");
        self.emit(format!("beqz a0, {ok}"));
        self.emit_process_failure_status();
        self.emit_label(&ok);
        self.emit_sp_addi("t0", buffer);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_witness_hash_call(&mut self, dest: Option<&IrVar>, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__ckb_witness_raw" | "__ckb_witness_lock" | "__ckb_witness_input_type" | "__ckb_witness_output_type") {
            return Ok(false);
        }
        let Some(dest) = dest else {
            return Ok(false);
        };
        if args.len() != 1 || dest.ty != IrType::Hash {
            return Ok(false);
        }
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: witness hash destination has no 32-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: witness hash destination has no buffer storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        self.emit("# cellscript abi: load witness hash into addressable Hash");
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", size_offset);
        self.emit_operand_to_register("a0", &args[0]);
        self.emit_sp_addi("a1", buffer_offset);
        self.emit(format!("call {}", func));
        let ok_label = self.fresh_label("witness_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(true)
    }

    fn emit_runtime_fixed_hash_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(
            func,
            "__ckb_require_cell_lock_hash"
                | "__ckb_require_cell_type_hash"
                | "__ckb_require_cell_data_hash"
                | "__ckb_require_cell_lock_args_hash"
                | "__ckb_require_cell_type_args_hash"
                | "__ckb_require_cell_lock_args_prefix_hash"
                | "__ckb_require_cell_type_args_prefix_hash"
                | "__ckb_require_cell_lock_args_suffix_hash"
                | "__ckb_require_cell_type_args_suffix_hash"
                | "__ckb_require_input_out_point_tx_hash"
                | "__xudt_require_owner_mode_input_type"
        ) {
            return Ok(false);
        }
        if args.len() != 2 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[1], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a1", buffer_offset);
                self.emit("li a2, 32");
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "runtime expected hash");
                if self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("li a2, 32");
                } else {
                    self.emit("# cellscript abi: runtime expected hash source is not addressable; pass null to fail closed");
                    self.emit("li a1, 0");
                    self.emit("li a2, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: runtime expected hash source is unavailable; pass null to fail closed");
                self.emit("li a1, 0");
                self.emit("li a2, 0");
            }
        }

        self.emit_operand_to_register("a0", &args[0]);
        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_hash_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_bounded_cell_dep_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_require_bounded_cell_dep_data_hash" {
            return Ok(false);
        }
        if args.len() != 2 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[1], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a1", buffer_offset);
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "bounded CellDep expected data hash");
                if !self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("# cellscript abi: bounded CellDep expected hash is not addressable; pass null to fail closed");
                    self.emit("li a1, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: bounded CellDep expected hash is unavailable; pass null to fail closed");
                self.emit("li a1, 0");
            }
        }
        self.emit_operand_to_register("a0", &args[0]);
        self.emit("call __ckb_require_bounded_cell_dep_data_hash");
        let ok_label = self.fresh_label("bounded_cell_dep_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_sha256d_merkle_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_require_sha256d_merkle_root" {
            return Ok(false);
        }
        if args.len() != 5 {
            return Ok(false);
        }
        let Some(leaf) = self.expected_fixed_byte_source(&args[0], 32) else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(siblings) = self.expected_fixed_byte_source(&args[1], 16 * 32) else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(expected_root) = self.expected_fixed_byte_source(&args[4], 32) else {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        self.emit_prepare_fixed_byte_source(&leaf, 32, "SHA256d Merkle leaf");
        self.emit_prepare_fixed_byte_source(&siblings, 16 * 32, "SHA256d Merkle siblings");
        self.emit_prepare_fixed_byte_source(&expected_root, 32, "SHA256d Merkle expected root");
        if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &leaf)
            || !self.emit_fixed_byte_source_pointer_or_const_to("a1", &siblings)
            || !self.emit_fixed_byte_source_pointer_or_const_to("a4", &expected_root)
        {
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        }
        self.emit_operand_to_register("a2", &args[2]);
        self.emit_operand_to_register("a3", &args[3]);
        self.emit("call __ckb_require_sha256d_merkle_root");
        let ok = self.fresh_label("sha256d_merkle_requirement_ok");
        self.emit(format!("beqz a0, {}", ok));
        self.emit_process_failure_status();
        self.emit_label(&ok);
        Ok(true)
    }

    fn emit_runtime_cell_script_hash_type_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__ckb_require_cell_lock_script_hash_type" | "__ckb_require_cell_type_script_hash_type") {
            return Ok(false);
        }
        if args.len() != 3 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[1], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a1", buffer_offset);
                self.emit("li a2, 32");
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "runtime expected Script code hash");
                if self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("li a2, 32");
                } else {
                    self.emit(
                        "# cellscript abi: runtime expected Script code hash source is not addressable; pass null to fail closed",
                    );
                    self.emit("li a1, 0");
                    self.emit("li a2, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: runtime expected Script code hash is unavailable; pass null to fail closed");
                self.emit("li a1, 0");
                self.emit("li a2, 0");
            }
        }

        self.emit_operand_to_register("a0", &args[0]);
        self.emit_operand_to_register("a3", &args[2]);
        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_script_identity_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_cell_script_args_exact_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__ckb_require_cell_lock_args_exact" | "__ckb_require_cell_type_args_exact") {
            return Ok(false);
        }
        if args.len() != 2 {
            return Ok(false);
        }
        let Some(width) = operand_fixed_byte_width(&args[1]) else {
            self.emit("# cellscript abi: runtime expected Script args source has no fixed byte width; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };
        let Some(expected) = self.expected_fixed_byte_source(&args[1], width) else {
            self.emit("# cellscript abi: runtime expected Script args source is unavailable; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(true);
        };

        match expected {
            ExpectedFixedByteSource::Const(bytes) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                self.emit_store_fixed_byte_const_to_scratch(
                    &IrOperand::Const(IrConst::Array(bytes.into_iter().map(IrConst::U8).collect())),
                    size_offset,
                    buffer_offset,
                    width,
                );
                self.emit_sp_addi("a1", buffer_offset);
            }
            source => {
                self.emit_prepare_fixed_byte_source(&source, width, "runtime expected Script args");
                if !self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("# cellscript abi: runtime expected Script args source is not addressable; fail closed");
                    self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                    return Ok(true);
                }
            }
        }

        self.emit_operand_to_register("a0", &args[0]);
        self.emit(format!("li a2, {}", width));
        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_script_args_exact_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_input_out_point_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__ckb_require_input_out_point" {
            return Ok(false);
        }
        if args.len() != 3 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[1], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a1", buffer_offset);
                self.emit("li a2, 32");
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "runtime expected input out point tx hash");
                if self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("li a2, 32");
                } else {
                    self.emit(
                        "# cellscript abi: runtime expected input out point hash source is not addressable; pass null to fail closed",
                    );
                    self.emit("li a1, 0");
                    self.emit("li a2, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: runtime expected input out point hash source is unavailable; pass null to fail closed");
                self.emit("li a1, 0");
                self.emit("li a2, 0");
            }
        }

        self.emit_operand_to_register("a3", &args[2]);
        self.emit_operand_to_register("a0", &args[0]);
        self.emit("call __ckb_require_input_out_point");
        let ok_label = self.fresh_label("runtime_input_out_point_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_xudt_type_args_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if func != "__xudt_require_owner_mode_type_args" {
            return Ok(false);
        }
        if args.len() != 3 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[1], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a1", buffer_offset);
                self.emit("li a2, 32");
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "runtime expected xUDT owner hash");
                if self.emit_fixed_byte_source_pointer_to("a1", &source) {
                    self.emit("li a2, 32");
                } else {
                    self.emit("# cellscript abi: runtime xUDT owner hash source is not addressable; pass null to fail closed");
                    self.emit("li a1, 0");
                    self.emit("li a2, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: runtime xUDT owner hash source is unavailable; pass null to fail closed");
                self.emit("li a1, 0");
                self.emit("li a2, 0");
            }
        }

        self.emit_operand_to_register("a0", &args[0]);
        self.emit_operand_to_register("a3", &args[2]);
        self.emit("call __xudt_require_owner_mode_type_args");
        let ok_label = self.fresh_label("runtime_xudt_args_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_xudt_group_amount_delta_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__xudt_require_group_amount_minted" | "__xudt_require_group_amount_burned") {
            return Ok(false);
        }
        if args.len() != 1 {
            return Ok(false);
        }

        let source = self.expected_fixed_byte_source(&args[0], 16);
        match source {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let value = u128::from_le_bytes(bytes.as_slice().try_into().expect("expected fixed u128 width"));
                let buffer_offset = self.runtime_scratch_buffer_offset();
                self.emit_store_fixed_byte_const_to_scratch(
                    &IrOperand::Const(IrConst::U128(value)),
                    self.runtime_scratch_size_offset(),
                    buffer_offset,
                    16,
                );
                self.emit_sp_addi("a0", buffer_offset);
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 16, "runtime xUDT group amount delta");
                if !self.emit_fixed_byte_source_pointer_to("a0", &source) {
                    self.emit("# cellscript abi: xUDT group amount delta is not addressable; pass null to fail closed");
                    self.emit("li a0, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: xUDT group amount delta is unavailable; pass null to fail closed");
                self.emit("li a0, 0");
            }
        }

        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_xudt_delta_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_metapoint_filtered_pair_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(
            func,
            "__ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered"
                | "__ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered"
        ) {
            return Ok(false);
        }
        if args.len() != 4 {
            return Ok(false);
        }

        let expected = self.expected_fixed_byte_source(&args[2], 32);
        match expected {
            Some(ExpectedFixedByteSource::Const(bytes)) => {
                let size_offset = self.runtime_scratch_size_offset();
                let buffer_offset = self.runtime_scratch_buffer_offset();
                let hash: [u8; 32] = bytes.as_slice().try_into().expect("expected fixed hash width");
                self.emit_store_fixed_byte_const_to_scratch(&IrOperand::Const(IrConst::Hash(hash)), size_offset, buffer_offset, 32);
                self.emit_sp_addi("a2", buffer_offset);
                self.emit("li a3, 32");
            }
            Some(source) => {
                self.emit_prepare_fixed_byte_source(&source, 32, "runtime filtered MetaPoint related type hash");
                if self.emit_fixed_byte_source_pointer_to("a2", &source) {
                    self.emit("li a3, 32");
                } else {
                    self.emit("# cellscript abi: filtered MetaPoint expected type hash is not addressable; pass null to fail closed");
                    self.emit("li a2, 0");
                    self.emit("li a3, 0");
                }
            }
            None => {
                self.emit("# cellscript abi: filtered MetaPoint expected type hash is unavailable; pass null to fail closed");
                self.emit("li a2, 0");
                self.emit("li a3, 0");
            }
        }

        self.emit_operand_to_register("a0", &args[0]);
        self.emit_operand_to_register("a1", &args[1]);
        self.emit_operand_to_register("a4", &args[3]);
        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_metapoint_filtered_pair_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_c256_product_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__c256_require_u128_product_lte" | "__c256_require_u128_product_eq") {
            return Ok(false);
        }
        if args.len() != 4 {
            return Ok(false);
        }

        let scratch_base = self.runtime_scratch_buffer_offset();
        for (index, (register, arg)) in ["a0", "a1", "a2", "a3"].into_iter().zip(args.iter()).enumerate() {
            let source = self.expected_fixed_byte_source(arg, 16);
            match source {
                Some(ExpectedFixedByteSource::Const(bytes)) => {
                    let value = u128::from_le_bytes(bytes.as_slice().try_into().expect("expected fixed u128 width"));
                    let buffer_offset = scratch_base + index * 16;
                    self.emit_store_fixed_byte_const_to_scratch(
                        &IrOperand::Const(IrConst::U128(value)),
                        self.runtime_scratch_size_offset(),
                        buffer_offset,
                        16,
                    );
                    self.emit_sp_addi(register, buffer_offset);
                }
                Some(source) => {
                    self.emit_prepare_fixed_byte_source(&source, 16, "runtime c256 u128 product operand");
                    if !self.emit_fixed_byte_source_pointer_to(register, &source) {
                        self.emit(format!(
                            "# cellscript abi: c256 product operand {} is not addressable; pass null to fail closed",
                            index
                        ));
                        self.emit(format!("li {}, 0", register));
                    }
                }
                None => {
                    self.emit(format!("# cellscript abi: c256 product operand {} is unavailable; pass null to fail closed", index));
                    self.emit(format!("li {}, 0", register));
                }
            }
        }

        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_c256_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_runtime_c256_sum2_product_requirement_call(&mut self, func: &str, args: &[IrOperand]) -> Result<bool> {
        if !matches!(func, "__c256_require_u128_sum2_products_lte" | "__c256_require_u128_sum2_products_eq") {
            return Ok(false);
        }
        if args.len() != 8 {
            return Ok(false);
        }

        let scratch_base = self.runtime_scratch_buffer_offset();
        for (index, (register, arg)) in ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"].into_iter().zip(args.iter()).enumerate() {
            let source = self.expected_fixed_byte_source(arg, 16);
            match source {
                Some(ExpectedFixedByteSource::Const(bytes)) => {
                    let value = u128::from_le_bytes(bytes.as_slice().try_into().expect("expected fixed u128 width"));
                    let buffer_offset = scratch_base + index * 16;
                    self.emit_store_fixed_byte_const_to_scratch(
                        &IrOperand::Const(IrConst::U128(value)),
                        self.runtime_scratch_size_offset(),
                        buffer_offset,
                        16,
                    );
                    self.emit_sp_addi(register, buffer_offset);
                }
                Some(source) => {
                    self.emit_prepare_fixed_byte_source(&source, 16, "runtime c256 sum-product operand");
                    if !self.emit_fixed_byte_source_pointer_to(register, &source) {
                        self.emit(format!(
                            "# cellscript abi: c256 sum-product operand {} is not addressable; pass null to fail closed",
                            index
                        ));
                        self.emit(format!("li {}, 0", register));
                    }
                }
                None => {
                    self.emit(format!(
                        "# cellscript abi: c256 sum-product operand {} is unavailable; pass null to fail closed",
                        index
                    ));
                    self.emit(format!("li {}, 0", register));
                }
            }
        }

        self.emit("call ".to_string() + func);
        let ok_label = self.fresh_label("runtime_c256_sum_requirement_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure_status();
        self.emit_label(&ok_label);
        Ok(true)
    }

    fn emit_call_param_arg(
        &mut self,
        func: &str,
        param: &IrParam,
        needs_type_hash: bool,
        abi_index: &mut usize,
        arg: &IrOperand,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        if is_ckb_temporal_scalar_ir_type(&param.ty) {
            return self.emit_call_scalar_arg(func, &param.name, abi_index, arg, outgoing_stack_arg_bytes);
        }
        if let IrType::Named(name) = &param.ty
            && let Some(layout) = self.enum_layouts.get(name).filter(|layout| layout.has_payload())
        {
            let width = layout.encoded_size;
            self.emit(format!(
                "# cellscript abi: call {} payload enum param {} pointer={} length={} size={}",
                func,
                param.name,
                abi_arg_label(*abi_index),
                abi_arg_label(*abi_index + 1),
                width
            ));
            if !self.emit_call_pointer_arg(func, &param.name, abi_index, arg, Some(width), outgoing_stack_arg_bytes) {
                return false;
            }
            if !self.emit_call_length_arg(func, &param.name, abi_index, arg, CallLengthKind::FixedBytes, outgoing_stack_arg_bytes) {
                return false;
            }
            return true;
        }
        if let Some(width) = self.fieldless_enum_width(&param.ty) {
            self.emit(format!(
                "# cellscript abi: call {} fieldless enum param {} value={} width={}",
                func,
                param.name,
                abi_arg_label(*abi_index),
                width
            ));
            if !self.emit_call_scalar_arg(func, &param.name, abi_index, arg, outgoing_stack_arg_bytes) {
                return false;
            }
            let register = self.call_abi_register(*abi_index);
            self.emit(format!("li {}, 0", register));
            self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
            *abi_index += 1;
            return true;
        }
        if let Some(width) = self.generic_value_type_width(&param.ty) {
            self.emit(format!(
                "# cellscript abi: call {} fixed named-value param {} pointer={} length={} size={}",
                func,
                param.name,
                abi_arg_label(*abi_index),
                abi_arg_label(*abi_index + 1),
                width
            ));
            if !self.emit_call_pointer_arg(func, &param.name, abi_index, arg, Some(width), outgoing_stack_arg_bytes) {
                return false;
            }
            if !self.emit_call_length_arg(func, &param.name, abi_index, arg, CallLengthKind::FixedBytes, outgoing_stack_arg_bytes) {
                return false;
            }
            return true;
        }
        if named_type_name(&param.ty).is_some() {
            self.emit(format!(
                "# cellscript abi: call {} schema param {} pointer={} length={}",
                func,
                param.name,
                abi_arg_label(*abi_index),
                abi_arg_label(*abi_index + 1)
            ));
            if !self.emit_call_pointer_arg(func, &param.name, abi_index, arg, None, outgoing_stack_arg_bytes) {
                return false;
            }
            if !self.emit_call_length_arg(func, &param.name, abi_index, arg, CallLengthKind::Schema, outgoing_stack_arg_bytes) {
                return false;
            }
            if needs_type_hash {
                self.emit(format!(
                    "# cellscript abi: call {} schema param {} type_hash pointer={} length={} size=32",
                    func,
                    param.name,
                    abi_arg_label(*abi_index),
                    abi_arg_label(*abi_index + 1)
                ));
                if !self.emit_call_type_hash_pointer_arg(func, &param.name, abi_index, arg, outgoing_stack_arg_bytes) {
                    return false;
                }
                if !self.emit_call_type_hash_length_arg(func, &param.name, abi_index, arg, outgoing_stack_arg_bytes) {
                    return false;
                }
            }
            return true;
        }

        let fixed_pointer_width = fixed_byte_pointer_param_width(&param.ty).or_else(|| fixed_aggregate_pointer_param_width(&param.ty));
        if let Some(width) = fixed_pointer_width {
            self.emit(format!(
                "# cellscript abi: call {} fixed-byte param {} pointer={} length={} size={}",
                func,
                param.name,
                abi_arg_label(*abi_index),
                abi_arg_label(*abi_index + 1),
                width
            ));
            if !self.emit_call_pointer_arg(func, &param.name, abi_index, arg, Some(width), outgoing_stack_arg_bytes) {
                return false;
            }
            if !self.emit_call_length_arg(func, &param.name, abi_index, arg, CallLengthKind::FixedBytes, outgoing_stack_arg_bytes) {
                return false;
            }
            return true;
        }

        self.emit_call_scalar_arg(func, &param.name, abi_index, arg, outgoing_stack_arg_bytes)
    }

    fn emit_call_scalar_arg(
        &mut self,
        func: &str,
        label: &str,
        abi_index: &mut usize,
        arg: &IrOperand,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        let register = self.call_abi_register(*abi_index);
        self.emit(format!("# cellscript abi: call {} scalar {} -> {}", func, label, register));
        self.emit_operand_to_register(&register, arg);
        self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
        *abi_index += 1;
        true
    }

    fn emit_call_pointer_arg(
        &mut self,
        func: &str,
        label: &str,
        abi_index: &mut usize,
        arg: &IrOperand,
        const_width: Option<usize>,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        let register = self.call_abi_register(*abi_index);
        if const_width.is_some() && matches!(arg, IrOperand::Const(_)) {
            self.emit(format!(
                "# cellscript abi: call {} pointer param {} uses a constant unsupported by the call ABI; pass null pointer",
                func, label
            ));
            self.emit(format!("li {}, 0", register));
        } else {
            self.emit_operand_to_register(&register, arg);
        }
        self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
        *abi_index += 1;
        true
    }

    fn emit_call_length_arg(
        &mut self,
        func: &str,
        label: &str,
        abi_index: &mut usize,
        arg: &IrOperand,
        kind: CallLengthKind,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        let register = self.call_abi_register(*abi_index);
        let size_offset = match (arg, kind) {
            (IrOperand::Var(var), CallLengthKind::Schema) => self.schema_pointer_size_offsets.get(&var.id).copied(),
            (IrOperand::Var(var), CallLengthKind::FixedBytes) => self.fixed_byte_param_size_offsets.get(&var.id).copied(),
            _ => None,
        };
        if let Some(size_offset) = size_offset {
            self.emit_stack_load(&register, size_offset);
        } else if let (IrOperand::Var(var), CallLengthKind::Schema) = (arg, kind)
            && let Some(width) = self.local_schema_value_widths.get(&var.id).copied()
        {
            self.emit(format!("# cellscript abi: locally materialized schema value var{} has exact width {}", var.id, width));
            self.emit(format!("li {}, {}", register, width));
        } else if let (IrOperand::Var(var), CallLengthKind::FixedBytes) = (arg, kind) {
            if let Some(width) = self.fixed_named_type_width(&var.ty) {
                self.emit(format!("li {}, {}", register, width));
            } else if self.fixed_byte_local_offsets.contains_key(&var.id)
                && let Some(width) = operand_fixed_byte_width(arg)
            {
                // A locally materialized fixed-byte value owns exact-width
                // storage. Unlike a borrowed parameter it needs no length slot.
                self.emit(format!("# cellscript abi: local fixed-byte value var{} has exact width {}", var.id, width));
                self.emit(format!("li {}, {}", register, width));
            } else {
                self.emit(format!(
                    "# cellscript abi: call {} fixed-byte param {} has no tracked ABI length; pass zero length to fail closed",
                    func, label
                ));
                self.emit(format!("li {}, 0", register));
            }
        } else if let CallLengthKind::FixedBytes = kind {
            if matches!(arg, IrOperand::Const(_)) {
                self.emit(format!(
                    "# cellscript abi: call {} fixed-byte const param {} has no materialized pointer; pass zero length to fail closed",
                    func, label
                ));
                self.emit(format!("li {}, 0", register));
            } else {
                self.emit(format!(
                    "# cellscript abi: call {} fixed-byte param {} has no tracked ABI length; pass zero length to fail closed",
                    func, label
                ));
                self.emit(format!("li {}, 0", register));
            }
        } else {
            self.emit(format!(
                "# cellscript abi: call {} schema param {} has no tracked ABI length; pass zero length to fail closed",
                func, label
            ));
            self.emit(format!("li {}, 0", register));
        }
        self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
        *abi_index += 1;
        true
    }

    fn emit_call_type_hash_pointer_arg(
        &mut self,
        func: &str,
        label: &str,
        abi_index: &mut usize,
        arg: &IrOperand,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        let register = self.call_abi_register(*abi_index);
        if let IrOperand::Var(var) = arg {
            if let Some(pointer_offset) = self.param_type_hash_pointer_offsets.get(&var.id).copied() {
                self.emit_stack_load(&register, pointer_offset);
            } else {
                self.emit(format!(
                    "# cellscript abi: call {} schema param {} has no tracked TypeHash pointer; pass null pointer",
                    func, label
                ));
                self.emit(format!("li {}, 0", register));
            }
        } else {
            self.emit(format!(
                "# cellscript abi: call {} schema param {} TypeHash source is not a variable; pass null pointer",
                func, label
            ));
            self.emit(format!("li {}, 0", register));
        }
        self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
        *abi_index += 1;
        true
    }

    fn emit_call_type_hash_length_arg(
        &mut self,
        func: &str,
        label: &str,
        abi_index: &mut usize,
        arg: &IrOperand,
        outgoing_stack_arg_bytes: usize,
    ) -> bool {
        let register = self.call_abi_register(*abi_index);
        if let IrOperand::Var(var) = arg {
            if let Some(size_offset) = self.param_type_hash_size_offsets.get(&var.id).copied() {
                self.emit_stack_load(&register, size_offset);
            } else {
                self.emit(format!(
                    "# cellscript abi: call {} schema param {} has no tracked TypeHash length; pass zero length to fail closed",
                    func, label
                ));
                self.emit(format!("li {}, 0", register));
            }
        } else {
            self.emit(format!(
                "# cellscript abi: call {} schema param {} TypeHash length source is not a variable; pass zero length",
                func, label
            ));
            self.emit(format!("li {}, 0", register));
        }
        self.emit_outgoing_call_stack_arg_store(&register, *abi_index, outgoing_stack_arg_bytes);
        *abi_index += 1;
        true
    }

    fn emit_outgoing_call_stack_arg_store(&mut self, register: &str, abi_index: usize, outgoing_stack_arg_bytes: usize) {
        if abi_index < 8 {
            return;
        }
        let stack_slot_offset = (abi_index - 8) * 8;
        let offset = i64::try_from(stack_slot_offset).expect("call stack slot should fit in i64")
            - i64::try_from(outgoing_stack_arg_bytes).expect("call stack argument area should fit in i64");
        self.emit(format!(
            "# cellscript abi: stage outgoing stack arg{} at pre-call sp{}{}",
            abi_index,
            if offset < 0 { "" } else { "+" },
            offset
        ));
        self.emit_sp_store_signed(register, offset);
    }

    pub(super) fn emit_sp_store_signed(&mut self, register: &str, offset: i64) {
        if small_signed_immediate(offset) {
            self.emit(format!("sd {}, {}(sp)", register, offset));
        } else {
            let scratch = scratch_register_avoiding(&[register]);
            self.emit(format!("li {}, {}", scratch, offset));
            self.emit(format!("add {}, sp, {}", scratch, scratch));
            self.emit(format!("sd {}, 0({})", register, scratch));
        }
    }

    fn call_abi_register(&self, abi_index: usize) -> String {
        if abi_index < 8 {
            format!("a{}", abi_index)
        } else {
            "t0".to_string()
        }
    }
}
