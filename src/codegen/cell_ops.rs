use super::*;

pub(super) struct CellFieldHashLocation<'a> {
    pub(super) reason: &'a str,
    pub(super) source: u64,
    pub(super) index: usize,
}

pub(super) struct CellFieldHashCheck<'a> {
    pub(super) left: CellFieldHashLocation<'a>,
    pub(super) right: CellFieldHashLocation<'a>,
    pub(super) cell_field: u64,
    pub(super) field_name: &'a str,
    pub(super) detail: &'a str,
    pub(super) error: CellScriptRuntimeError,
}

impl CodeGenerator {
    pub(super) fn emit_resolved_cell_membership_checks(&mut self) {
        let bindings =
            self.cell_bindings.iter().filter(|binding| binding.membership != IrCellMembership::Unproven).cloned().collect::<Vec<_>>();
        if bindings.is_empty() {
            return;
        }
        let field_size = self.runtime_scratch_size_offset();
        let field_buffer = self.runtime_scratch_buffer_offset();
        self.emit("# cellscript binding plan: verify current Script group membership");
        for binding in &bindings {
            let field = match binding.membership {
                IrCellMembership::CurrentTypeGroup => CKB_CELL_FIELD_TYPE_HASH,
                IrCellMembership::CurrentLockGroup => CKB_CELL_FIELD_LOCK_HASH,
                IrCellMembership::Unproven => unreachable!(),
            };
            self.emit(format!("li a0, {}", cell_source_value(binding.source)));
            self.emit(format!("li a1, {}", binding.ordinal));
            self.emit(format!("li a2, {}", field));
            self.emit("call __cellscript_require_cell_membership");
            let valid = self.fresh_label("binding_membership_valid");
            self.emit(format!("beqz a0, {}", valid));
            // Preserve the helper's exact error: malformed width is different
            // from a missing, mismatched, or ambiguous Script role.
            self.emit_process_failure_status();
            self.emit_label(&valid);
        }
        // Fixed native Type roles cover the complete executing group. Legacy
        // absolute bindings and selected protected Lock inputs do not claim this.
        if bindings.iter().any(|binding| binding.membership == IrCellMembership::CurrentTypeGroup) {
            for source in [IrCellSource::GroupInput, IrCellSource::GroupOutput] {
                let count =
                    bindings.iter().filter(|binding| binding.source == source).map(|binding| binding.ordinal + 1).max().unwrap_or(0);
                self.emit_load_cell_by_field_syscall_to_offsets(
                    "resolved_binding_group_end",
                    cell_source_value(source),
                    count,
                    CKB_CELL_FIELD_CAPACITY,
                    field_size,
                    field_buffer,
                    8,
                );
                let exact = self.fresh_label("binding_group_count_exact");
                self.emit(format!("li t0, {}", CKB_INDEX_OUT_OF_BOUND));
                self.emit(format!("beq a0, t0, {}", exact));
                self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
                self.emit_label(&exact);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_bound_cell_data_to_offsets(
        &mut self,
        reason: &str,
        role: IrCellBindingRole,
        binding: &str,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        let (source, index) = self.require_cell_location(role, binding);
        self.emit_load_cell_data_syscall_to_offsets(reason, source, index, size_offset, buffer_offset, max_bytes);
    }

    pub(super) fn emit_bounded_cell_load(
        &mut self,
        dest: &IrVar,
        found: &IrVar,
        index: &IrOperand,
        max_elements: usize,
        element_type: &str,
        element_width: usize,
    ) {
        let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        };
        let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        };
        if element_width == 0 || element_width > RUNTIME_CELL_BUFFER_SIZE {
            self.emit_fail(CellScriptRuntimeError::ExactSizeMismatch);
            return;
        }

        let loaded = self.fresh_label("bounded_cell_loaded");
        let out_of_bound = self.fresh_label("bounded_cell_out_of_bound");
        let count_ok = self.fresh_label("bounded_cell_count_ok");
        let type_word_ok = (0..4).map(|_| self.fresh_label("bounded_cell_type_word_ok")).collect::<Vec<_>>();
        let lock_is_distinct = self.fresh_label("bounded_cell_lock_is_distinct");
        let done = self.fresh_label("bounded_cell_load_done");

        self.emit(format!(
            "# cellscript bounded runtime: contract={} source=GroupInput element={} max={} width={}",
            crate::ir::BOUNDED_TYPE_GROUP_INPUTS_V1,
            element_type,
            max_elements,
            element_width
        ));
        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_data_syscall_to_offsets_dynamic_index(
            "bounded_consume_each",
            CKB_SOURCE_GROUP_INPUT,
            "t3",
            size_offset,
            buffer_offset,
            RUNTIME_CELL_BUFFER_SIZE,
        );
        self.emit(format!("beqz a0, {}", loaded));
        self.emit(format!("li t0, {}", CKB_INDEX_OUT_OF_BOUND));
        self.emit("sub t1, a0, t0");
        self.emit(format!("beqz t1, {}", out_of_bound));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);

        self.emit_label(&loaded);
        self.emit_operand_to_register("t3", index);
        self.emit(format!("li t0, {}", max_elements));
        self.emit("sltu t1, t3, t0");
        self.emit(format!("bnez t1, {}", count_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&count_ok);
        self.emit_loaded_schema_exact_size_check(size_offset, element_width, element_type);

        let current_hash_size_offset = self.runtime_scratch2_size_offset();
        let current_hash_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", current_hash_size_offset);
        self.emit_sp_addi("a0", current_hash_buffer_offset);
        self.emit_sp_addi("a1", current_hash_size_offset);
        self.emit("li a2, 0");
        self.emit(format!("li a7, {}", self.runtime_abi().load_script_hash));
        self.emit("ecall");
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(current_hash_size_offset, 32, "current script hash");

        let role_size_offset = self.runtime_scratch_size_offset();
        let role_buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "bounded_consume_each_type_hash",
            CKB_SOURCE_GROUP_INPUT,
            "t3",
            CKB_CELL_FIELD_TYPE_HASH,
            role_size_offset,
            role_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::ScriptRoleMismatch);
        self.emit_loaded_schema_exact_size_check(role_size_offset, 32, "bounded input type hash");
        for (word, ok) in type_word_ok.iter().enumerate() {
            self.emit_stack_load("t0", role_buffer_offset + word * 8);
            self.emit_stack_load("t1", current_hash_buffer_offset + word * 8);
            self.emit("sub t2, t0, t1");
            self.emit(format!("beqz t2, {}", ok));
            self.emit_fail(CellScriptRuntimeError::TypeHashMismatch);
            self.emit_label(ok);
        }

        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "bounded_consume_each_lock_hash",
            CKB_SOURCE_GROUP_INPUT,
            "t3",
            CKB_CELL_FIELD_LOCK_HASH,
            role_size_offset,
            role_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::ScriptRoleMismatch);
        self.emit_loaded_schema_exact_size_check(role_size_offset, 32, "bounded input lock hash");
        self.emit_stack_load("t0", role_buffer_offset);
        self.emit_stack_load("t1", current_hash_buffer_offset);
        self.emit("sub t2, t0, t1");
        for word in 1..4 {
            self.emit_stack_load("t0", role_buffer_offset + word * 8);
            self.emit_stack_load("t1", current_hash_buffer_offset + word * 8);
            self.emit("sub t0, t0, t1");
            self.emit("or t2, t2, t0");
        }
        self.emit(format!("bnez t2, {}", lock_is_distinct));
        self.emit_fail(CellScriptRuntimeError::ScriptRoleMismatch);
        self.emit_label(&lock_is_distinct);

        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        self.emit("li t0, 1");
        self.emit_stack_store("t0", found.id * 8);
        self.emit(format!("j {}", done));

        self.emit_label(&out_of_bound);
        self.emit_stack_store("zero", dest.id * 8);
        self.emit_stack_store("zero", found.id * 8);
        self.emit_label(&done);
    }

    pub(super) fn emit_bounded_plan_load(
        &mut self,
        dest: &IrVar,
        found: &IrVar,
        plan: &IrOperand,
        index: &IrOperand,
        max_elements: usize,
        element_type: &str,
        element_width: usize,
    ) {
        let IrOperand::Var(plan_var) = plan else {
            self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
            return;
        };
        let Some(plan_size_offset) = self.schema_pointer_size_offsets.get(&plan_var.id).copied() else {
            self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
            return;
        };
        let Some(element_size_offset) = self.schema_pointer_size_offsets.get(&dest.id).copied() else {
            self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
            return;
        };
        let magic_ok =
            (0..crate::ir::BOUNDED_OUTPUT_PLAN_MAGIC_V1.len()).map(|_| self.fresh_label("bounded_plan_magic_ok")).collect::<Vec<_>>();
        let header_ok = self.fresh_label("bounded_plan_header_ok");
        let count_ok = self.fresh_label("bounded_plan_count_ok");
        let length_ok = self.fresh_label("bounded_plan_length_ok");
        let found_label = self.fresh_label("bounded_plan_element_found");
        let done = self.fresh_label("bounded_plan_load_done");

        self.emit(format!(
            "# cellscript bounded runtime: contract={} codec=MoleculeFixVec magic=CSBPLv1 element={} max={} width={}",
            crate::ir::BOUNDED_OUTPUT_PLAN_V1,
            element_type,
            max_elements,
            element_width
        ));
        self.emit_stack_load("t4", plan_var.id * 8);
        self.emit_stack_load("t5", plan_size_offset);
        self.emit(format!("li t0, {}", 12));
        self.emit("sltu t2, t5, t0");
        self.emit(format!("beqz t2, {}", header_ok));
        self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
        self.emit_label(&header_ok);
        for (byte_index, (byte, ok)) in crate::ir::BOUNDED_OUTPUT_PLAN_MAGIC_V1.iter().zip(&magic_ok).enumerate() {
            self.emit(format!("lbu t0, {}(t4)", byte_index));
            self.emit(format!("li t1, {}", byte));
            self.emit("sub t2, t0, t1");
            self.emit(format!("beqz t2, {}", ok));
            self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
            self.emit_label(ok);
        }
        self.emit("li t3, 0");
        for byte_index in 0..4 {
            self.emit(format!("lbu t0, {}(t4)", 8 + byte_index));
            if byte_index != 0 {
                self.emit(format!("slli t0, t0, {}", byte_index * 8));
            }
            self.emit("or t3, t3, t0");
        }
        self.emit(format!("li t0, {}", max_elements));
        self.emit("sltu t2, t0, t3");
        self.emit(format!("beqz t2, {}", count_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&count_ok);
        self.emit(format!("li t0, {}", element_width));
        self.emit("mul t1, t3, t0");
        self.emit("addi t1, t1, 12");
        self.emit("sub t2, t5, t1");
        self.emit(format!("beqz t2, {}", length_ok));
        self.emit_fail(CellScriptRuntimeError::EntryWitnessAbiInvalid);
        self.emit_label(&length_ok);

        self.emit_operand_to_register("t0", index);
        self.emit("sltu t2, t0, t3");
        self.emit(format!("bnez t2, {}", found_label));
        self.emit_stack_store("zero", dest.id * 8);
        self.emit_schema_size_store("zero", element_size_offset);
        self.emit_stack_store("zero", found.id * 8);
        self.emit(format!("j {}", done));

        self.emit_label(&found_label);
        self.emit(format!("li t1, {}", element_width));
        self.emit("mul t2, t0, t1");
        self.emit("addi t2, t2, 12");
        self.emit_stack_load("t4", plan_var.id * 8);
        self.emit("add t4, t4, t2");
        self.emit_stack_store("t4", dest.id * 8);
        self.emit(format!("li t1, {}", element_width));
        self.emit_schema_size_store("t1", element_size_offset);
        self.emit("li t1, 1");
        self.emit_stack_store("t1", found.id * 8);
        self.emit_label(&done);
    }

    pub(super) fn emit_bounded_output_verify(&mut self, index: &IrOperand, pattern: &CreatePattern, capacity_floor_shannons: u64) {
        let data_size_offset = self.runtime_scratch_size_offset();
        let data_buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit(format!(
            "# cellscript bounded runtime: contract={} source=GroupOutput output={} capacity_floor={}",
            crate::ir::BOUNDED_OUTPUT_PLAN_V1,
            pattern.ty,
            capacity_floor_shannons
        ));
        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_data_syscall_to_offsets_dynamic_index(
            "bounded_create_each_output",
            CKB_SOURCE_GROUP_OUTPUT,
            "t3",
            data_size_offset,
            data_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::CollectionBoundsInvalid);
        if self.can_verify_create_output_fields(pattern) {
            self.emit_create_output_checks_at(pattern, data_size_offset, data_buffer_offset);
        } else {
            self.emit_fail(CellScriptRuntimeError::AssertionFailed);
            return;
        }

        let current_hash_size_offset = self.runtime_scratch2_size_offset();
        let current_hash_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit("li t0, 32");
        self.emit_schema_size_store("t0", current_hash_size_offset);
        self.emit_sp_addi("a0", current_hash_buffer_offset);
        self.emit_sp_addi("a1", current_hash_size_offset);
        self.emit("li a2, 0");
        self.emit(format!("li a7, {}", self.runtime_abi().load_script_hash));
        self.emit("ecall");
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(current_hash_size_offset, 32, "current script hash");

        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "bounded_create_each_lock_hash",
            CKB_SOURCE_GROUP_OUTPUT,
            "t3",
            CKB_CELL_FIELD_LOCK_HASH,
            data_size_offset,
            data_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::LockHashPreservationMismatch);
        self.emit_loaded_schema_exact_size_check(data_size_offset, 32, "bounded output lock hash");
        self.emit_stack_load("t0", data_buffer_offset);
        self.emit_stack_load("t1", current_hash_buffer_offset);
        self.emit("sub t2, t0, t1");
        for word in 1..4 {
            self.emit_stack_load("t0", data_buffer_offset + word * 8);
            self.emit_stack_load("t1", current_hash_buffer_offset + word * 8);
            self.emit("sub t0, t0, t1");
            self.emit("or t2, t2, t0");
        }
        let type_only = self.fresh_label("bounded_output_type_only");
        self.emit(format!("bnez t2, {}", type_only));
        self.emit_fail(CellScriptRuntimeError::ScriptRoleMismatch);
        self.emit_label(&type_only);
        let Some(lock) = &pattern.lock else {
            self.emit_fail(CellScriptRuntimeError::LockHashPreservationMismatch);
            return;
        };
        let Some(lock_source) = self.expected_fixed_byte_source(lock, 32) else {
            self.emit_fail(CellScriptRuntimeError::LockHashPreservationMismatch);
            return;
        };
        self.emit_loaded_fixed_bytes_against_source(
            data_buffer_offset,
            0,
            &lock_source,
            32,
            CellScriptRuntimeError::LockHashPreservationMismatch,
        );

        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "bounded_create_each_capacity",
            CKB_SOURCE_GROUP_OUTPUT,
            "t3",
            CKB_CELL_FIELD_CAPACITY,
            data_size_offset,
            data_buffer_offset,
            8,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::CapacityPreservationMismatch);
        self.emit_loaded_schema_exact_size_check(data_size_offset, 8, "bounded output capacity");
        self.emit_stack_load("t0", data_buffer_offset);
        self.emit(format!("li t1, {}", capacity_floor_shannons));
        let capacity_ok = self.fresh_label("bounded_output_capacity_ok");
        self.emit(format!("bgeu t0, t1, {}", capacity_ok));
        self.emit_fail(CellScriptRuntimeError::CapacityPreservationMismatch);
        self.emit_label(&capacity_ok);
    }

    pub(super) fn emit_bounded_output_end(&mut self, index: &IrOperand) {
        let size_offset = self.runtime_scratch_size_offset();
        let buffer_offset = self.runtime_scratch_buffer_offset();
        let exact = self.fresh_label("bounded_output_count_exact");
        self.emit("# cellscript bounded runtime: require GroupOutput count equals plan count");
        self.emit_operand_to_register("t3", index);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "bounded_create_each_output_end",
            CKB_SOURCE_GROUP_OUTPUT,
            "t3",
            CKB_CELL_FIELD_CAPACITY,
            size_offset,
            buffer_offset,
            8,
        );
        self.emit(format!("li t0, {}", CKB_INDEX_OUT_OF_BOUND));
        self.emit("sub t1, a0, t0");
        self.emit(format!("beqz t1, {}", exact));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&exact);
    }

    pub(super) fn emit_mutate_replacement_field_hash_check(
        &mut self,
        pattern: &MutatePattern,
        cell_field: u64,
        field_name: &str,
        error: CellScriptRuntimeError,
    ) {
        let (input_source, input_index) = self.require_cell_location(IrCellBindingRole::Input, &pattern.binding);
        let (output_source, output_index) = self.require_cell_location(IrCellBindingRole::Output, &pattern.binding);
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();

        self.emit_load_cell_by_field_syscall_to_offsets(
            &format!("mutate_input_{}", field_name),
            input_source,
            input_index,
            cell_field,
            input_size_offset,
            input_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_load_cell_by_field_syscall_to_offsets(
            &format!("mutate_output_{}", field_name),
            output_source,
            output_index,
            cell_field,
            output_size_offset,
            output_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(input_size_offset, 32, &format!("mutate input {}", field_name));
        self.emit_loaded_schema_exact_size_check(output_size_offset, 32, &format!("mutate output {}", field_name));
        self.emit(format!(
            "# cellscript abi: verify mutate output {} {} Input#{} == Output#{} size=32",
            pattern.ty, field_name, pattern.input_index, pattern.output_index
        ));
        self.emit_sp_addi("a0", input_buffer_offset);
        self.emit_sp_addi("a1", output_buffer_offset);
        self.emit("li a2, 32");
        self.emit("call __cellscript_memcmp_fixed");
        let ok_label = self.fresh_label("mutate_identity_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_fail(error);
        self.emit_label(&ok_label);
    }

    pub(super) fn emit_cell_metadata_equality(&mut self, left: &IrOperand, right: &IrOperand, field: CellMetadataField) -> Result<()> {
        let Some((left_source, left_index)) = self.operand_cell_location(left) else {
            self.emit("# cellscript abi: fail closed because left cell metadata source cannot be determined");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        };
        let Some((right_source, right_index)) = self.operand_cell_location(right) else {
            self.emit("# cellscript abi: fail closed because right cell metadata source cannot be determined");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return Ok(());
        };
        let (cell_field, field_name, width, mismatch_error) = match field {
            CellMetadataField::LockHash => {
                (CKB_CELL_FIELD_LOCK_HASH, "lock_hash", 32usize, CellScriptRuntimeError::LockHashPreservationMismatch)
            }
            CellMetadataField::Capacity => {
                (CKB_CELL_FIELD_CAPACITY, "capacity", 8usize, CellScriptRuntimeError::CapacityPreservationMismatch)
            }
        };

        let left_size_offset = self.runtime_scratch_size_offset();
        let left_buffer_offset = self.runtime_scratch_buffer_offset();
        let right_size_offset = self.runtime_scratch2_size_offset();
        let right_buffer_offset = self.runtime_scratch2_buffer_offset();

        self.emit_load_cell_by_field_syscall_to_offsets(
            &format!("cell_metadata_left_{}", field_name),
            left_source,
            left_index,
            cell_field,
            left_size_offset,
            left_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_load_cell_by_field_syscall_to_offsets(
            &format!("cell_metadata_right_{}", field_name),
            right_source,
            right_index,
            cell_field,
            right_size_offset,
            right_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(left_size_offset, width, &format!("cell metadata left {}", field_name));
        self.emit_loaded_schema_exact_size_check(right_size_offset, width, &format!("cell metadata right {}", field_name));
        self.emit(format!(
            "# cellscript abi: verify cell metadata {} equality {}#{} == {}#{} size={}",
            field_name,
            ckb_source_name(left_source),
            left_index,
            ckb_source_name(right_source),
            right_index,
            width
        ));
        self.emit_sp_addi("a0", left_buffer_offset);
        self.emit_sp_addi("a1", right_buffer_offset);
        self.emit(format!("li a2, {}", width));
        self.emit("call __cellscript_memcmp_fixed");
        let ok_label = self.fresh_label("cell_metadata_equal");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_fail(mismatch_error);
        self.emit_label(&ok_label);
        Ok(())
    }

    pub(super) fn emit_cell_field_hash_equality(&mut self, check: CellFieldHashCheck<'_>) {
        let CellFieldHashCheck { left, right, cell_field, field_name, detail, error } = check;
        let left_size_offset = self.runtime_scratch_size_offset();
        let left_buffer_offset = self.runtime_scratch_buffer_offset();
        let right_size_offset = self.runtime_scratch2_size_offset();
        let right_buffer_offset = self.runtime_scratch2_buffer_offset();

        self.emit_load_cell_by_field_syscall_to_offsets(
            left.reason,
            left.source,
            left.index,
            cell_field,
            left_size_offset,
            left_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(error);
        self.emit_load_cell_by_field_syscall_to_offsets(
            right.reason,
            right.source,
            right.index,
            cell_field,
            right_size_offset,
            right_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(error);
        self.emit_loaded_schema_exact_size_check(left_size_offset, 32, &format!("{} {}", left.reason, field_name));
        self.emit_loaded_schema_exact_size_check(right_size_offset, 32, &format!("{} {}", right.reason, field_name));
        self.emit(format!(
            "# cellscript abi: verify {} {} {}#{} == {}#{} size=32",
            detail,
            field_name,
            ckb_source_name(left.source),
            left.index,
            ckb_source_name(right.source),
            right.index
        ));
        self.emit_sp_addi("a0", left_buffer_offset);
        self.emit_sp_addi("a1", right_buffer_offset);
        self.emit("li a2, 32");
        self.emit("call __cellscript_memcmp_fixed");
        let ok_label = self.fresh_label("identity_hash_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure(error);
        self.emit_label(&ok_label);
    }

    pub(super) fn emit_output_type_hash_present_check(&mut self, source: u64, output_index: usize, context: &str) {
        let size_offset = self.runtime_scratch2_size_offset();
        let buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_load_cell_by_field_syscall_to_offsets(
            context,
            source,
            output_index,
            CKB_CELL_FIELD_TYPE_HASH,
            size_offset,
            buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::TypeHashMismatch);
        self.emit_loaded_schema_exact_size_check(size_offset, 32, context);
        self.emit(format!("# cellscript abi: verify {} Output#{} TypeHash is present size=32", context, output_index));
    }

    pub(super) fn emit_loaded_fixed_field_pointer_to_stack(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        layout: &SchemaFieldLayout,
        width: usize,
        context: &str,
        pointer_stack_offset: usize,
    ) {
        self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, context);
        self.emit_sp_addi("t5", buffer_offset + layout.offset);
        self.emit_stack_store("t5", pointer_stack_offset);
    }

    pub(super) fn emit_dynamic_fixed_field_pointer_to_stack(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        layout: &SchemaFieldLayout,
        field_count: usize,
        width: usize,
        context: &str,
        pointer_stack_offset: usize,
        len_stack_offset: usize,
    ) {
        self.emit_dynamic_table_field_span_to_stack(
            size_offset,
            buffer_offset,
            layout.index,
            field_count,
            context,
            pointer_stack_offset,
            len_stack_offset,
        );
        self.emit_stack_load("t0", len_stack_offset);
        self.emit(format!("li t1, {}", width));
        self.emit("sub t2, t0, t1");
        let ok_label = self.fresh_label("identity_field_len_ok");
        self.emit(format!("beqz t2, {}", ok_label));
        self.emit_process_failure(CellScriptRuntimeError::DynamicFieldValueMismatch);
        self.emit_label(&ok_label);
    }

    pub(super) fn emit_fixed_pointer_equality(
        &mut self,
        left_pointer_stack_offset: usize,
        right_pointer_stack_offset: usize,
        width: usize,
        context: &str,
        error: CellScriptRuntimeError,
    ) {
        self.emit(format!("# cellscript abi: verify {} size={}", context, width));
        self.emit_stack_load("a0", left_pointer_stack_offset);
        self.emit_stack_load("a1", right_pointer_stack_offset);
        self.emit(format!("li a2, {}", width));
        self.emit("call __cellscript_memcmp_fixed");
        let ok_label = self.fresh_label("identity_field_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_process_failure(error);
        self.emit_label(&ok_label);
    }

    pub(super) fn operand_cell_location(&self, operand: &IrOperand) -> Option<(u64, usize)> {
        let IrOperand::Var(var) = operand else {
            return None;
        };
        if let Some(location) = self.resolved_cell_location_for_local(var.id) {
            Some(location)
        } else if let Some(input_index) = self.consume_indices.get(&var.id).copied() {
            Some((CKB_SOURCE_INPUT, input_index))
        } else if let Some(output_index) = self.operation_output_indices.get(&var.id).copied() {
            Some((CKB_SOURCE_OUTPUT, output_index))
        } else if let Some(dep_index) = self.read_ref_indices.get(&var.id).copied() {
            Some((CKB_SOURCE_CELL_DEP, dep_index))
        } else if let Some(input_index) = self.read_ref_param_input_indices.get(&var.id).copied() {
            Some((CKB_SOURCE_INPUT, input_index))
        } else {
            self.read_ref_param_dep_indices.get(&var.id).copied().map(|dep_index| (CKB_SOURCE_CELL_DEP, dep_index))
        }
    }

    pub(super) fn emit_destroy_group_output_absence_scan(&mut self, pattern: &CellPattern, _input_index: usize) {
        let (input_source, input_index) = self.require_cell_location(IrCellBindingRole::Input, &pattern.binding);
        let output_source = if input_source == CKB_SOURCE_GROUP_INPUT { CKB_SOURCE_GROUP_OUTPUT } else { CKB_SOURCE_OUTPUT };
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        let loop_label = self.fresh_label("destroy_output_scan");
        let type_hash_label = self.fresh_label("destroy_output_type_hash");
        let next_label = self.fresh_label("destroy_output_next");
        let done_label = self.fresh_label("destroy_output_done");

        self.emit(format!("# cellscript abi: destroy output type-hash absence scan binding={} size=32", pattern.binding));
        self.emit_load_cell_by_field_syscall_to_offsets(
            "destroy_input_type_hash",
            input_source,
            input_index,
            CKB_CELL_FIELD_TYPE_HASH,
            input_size_offset,
            input_buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(input_size_offset, 32, "destroy input type hash");
        self.emit("li t6, 0");
        self.emit_label(&loop_label);
        self.emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
            "destroy_output_type_hash",
            output_source,
            "t6",
            CKB_CELL_FIELD_TYPE_HASH,
            output_size_offset,
            output_buffer_offset,
            32,
        );
        self.emit(format!("beqz a0, {}", type_hash_label));
        self.emit(format!("li t0, {}", CKB_INDEX_OUT_OF_BOUND));
        self.emit("sub t1, a0, t0");
        self.emit(format!("beqz t1, {}", done_label));
        self.emit(format!("li t0, {}", CKB_ITEM_MISSING));
        self.emit("sub t1, a0, t0");
        self.emit(format!("beqz t1, {}", next_label));
        self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);

        self.emit_label(&type_hash_label);
        self.emit_loaded_schema_exact_size_check(output_size_offset, 32, "destroy output type hash");
        self.emit(format!("# cellscript abi: reject destroy successor when Output#t6 TypeHash matches consumed {}", pattern.binding));
        self.emit_sp_addi("t4", output_buffer_offset);
        self.emit_sp_addi("t5", input_buffer_offset);
        for byte_index in 0..32 {
            self.emit(format!("lbu t0, {}(t4)", byte_index));
            self.emit(format!("lbu t1, {}(t5)", byte_index));
            self.emit("sub t2, t0, t1");
            self.emit(format!("bnez t2, {}", next_label));
        }
        self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);

        self.emit_label(&next_label);
        self.emit("addi t6, t6, 1");
        self.emit(format!("j {}", loop_label));
        self.emit_label(&done_label);
        self.emit("li a0, 0");
    }

    pub(super) fn mutate_preserved_field_layouts(&self, pattern: &MutatePattern) -> Vec<(String, SchemaFieldLayout, usize)> {
        let Some(type_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return Vec::new();
        };
        if type_size > RUNTIME_SCRATCH_BUFFER_SIZE {
            return Vec::new();
        }
        pattern
            .preserved_fields
            .iter()
            .filter_map(|field| {
                let layout = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(field)).cloned()?;
                let width = layout_fixed_byte_width(&layout)?;
                (layout.offset + width <= RUNTIME_SCRATCH_BUFFER_SIZE).then(|| (field.clone(), layout, width))
            })
            .collect()
    }

    pub(super) fn mutate_transition_exclusion_ranges(&self, pattern: &MutatePattern) -> Option<Vec<(usize, usize)>> {
        if pattern.transitions.len() != pattern.fields.len() {
            return None;
        }
        let type_size = self.type_fixed_sizes.get(&pattern.ty).copied()?;
        if type_size > RUNTIME_SCRATCH_BUFFER_SIZE {
            return None;
        }
        let mut ranges = Vec::new();
        for transition in &pattern.transitions {
            let layout = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&transition.field))?;
            let width = layout_fixed_byte_width(layout)?;
            if layout.offset + width > RUNTIME_SCRATCH_BUFFER_SIZE {
                return None;
            }
            ranges.push((layout.offset, layout.offset + width));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            if start >= end {
                continue;
            }
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        Some(merged)
    }

    pub(super) fn emit_mutate_replacement_preserved_field_checks(&mut self, pattern: &MutatePattern) {
        let preserved_fields = self.mutate_preserved_field_layouts(pattern);
        if !pattern.preserved_fields.is_empty() && preserved_fields.len() != pattern.preserved_fields.len() {
            if self.emit_mutate_replacement_dynamic_table_preserved_field_checks(pattern) {
                return;
            }
            if self.emit_mutate_replacement_data_except_transition_checks(pattern) {
                return;
            }
            self.emit("# cellscript abi: fail closed because not all preserved fields are verifier-addressable");
            self.emit_fail(CellScriptRuntimeError::FieldPreservationMismatch);
            return;
        }
        if preserved_fields.is_empty() {
            return;
        }
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_data",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_data",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(input_size_offset, expected_size, &format!("{} mutate input", pattern.ty));
            self.emit_loaded_schema_exact_size_check(output_size_offset, expected_size, &format!("{} mutate output", pattern.ty));
        }
        self.emit(format!(
            "# cellscript abi: verify mutate preserved fields {} Input#{} == Output#{}",
            pattern.ty, pattern.input_index, pattern.output_index
        ));
        self.emit_sp_addi("t4", input_buffer_offset);
        self.emit_sp_addi("t5", output_buffer_offset);
        for (field, layout, width) in preserved_fields {
            self.emit_loaded_schema_bounds_check(input_size_offset, layout.offset + width, &format!("{} input.{}", pattern.ty, field));
            self.emit_loaded_schema_bounds_check(
                output_size_offset,
                layout.offset + width,
                &format!("{} output.{}", pattern.ty, field),
            );
            self.emit(format!(
                "# cellscript abi: verify mutate preserved field {}.{} Input#{} == Output#{} offset={} size={}",
                pattern.ty, field, pattern.input_index, pattern.output_index, layout.offset, width
            ));
            let mismatch_label = self.fresh_label("mutate_preserved_byte_mismatch");
            for byte_index in 0..width {
                self.emit(format!("lbu t0, {}(t4)", layout.offset + byte_index));
                self.emit(format!("lbu t1, {}(t5)", layout.offset + byte_index));
                self.emit("sub t2, t0, t1");
                self.emit(format!("bnez t2, {}", mismatch_label));
            }
            self.emit_fixed_byte_mismatch_fail(&mismatch_label, CellScriptRuntimeError::FieldPreservationMismatch);
        }
    }

    pub(super) fn emit_mutate_replacement_dynamic_table_preserved_field_checks(&mut self, pattern: &MutatePattern) -> bool {
        if self.type_fixed_sizes.contains_key(&pattern.ty) || pattern.preserved_fields.is_empty() {
            return false;
        }
        let Some(layouts) = self.type_layouts.get(&pattern.ty).cloned() else {
            return false;
        };
        let field_count = layouts.len();
        if field_count == 0 || !pattern.preserved_fields.iter().all(|field| layouts.contains_key(field)) {
            return false;
        }

        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_table_preserved",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_table_preserved",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit(format!(
            "# cellscript abi: verify mutate preserved Molecule table fields {} Input#{} == Output#{}",
            pattern.ty, pattern.input_index, pattern.output_index
        ));
        for field in &pattern.preserved_fields {
            let Some(layout) = layouts.get(field).cloned() else {
                return false;
            };
            self.emit_dynamic_table_field_equality_check(
                &pattern.ty,
                field,
                &layout,
                field_count,
                input_size_offset,
                input_buffer_offset,
                output_size_offset,
                output_buffer_offset,
                CellScriptRuntimeError::FieldPreservationMismatch,
            );
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_dynamic_table_field_equality_check(
        &mut self,
        type_name: &str,
        field: &str,
        layout: &SchemaFieldLayout,
        field_count: usize,
        input_size_offset: usize,
        input_buffer_offset: usize,
        output_size_offset: usize,
        output_buffer_offset: usize,
        fail_code: CellScriptRuntimeError,
    ) {
        let start_offset = self.runtime_expr_temp_offset(0);
        let len_offset = self.runtime_expr_temp_offset(1);
        let output_start_offset = self.runtime_expr_temp_offset(2);
        if let Some(width) = layout_fixed_byte_width(layout) {
            self.emit_dynamic_table_fixed_field_pointer_to_stack(
                input_size_offset,
                input_buffer_offset,
                layout,
                width,
                &format!("{} input.{}", type_name, field),
                start_offset,
            );
            self.emit_dynamic_table_fixed_field_pointer_to_stack(
                output_size_offset,
                output_buffer_offset,
                layout,
                width,
                &format!("{} output.{}", type_name, field),
                output_start_offset,
            );
            self.emit(format!("li t0, {}", width));
            self.emit_schema_size_store("t0", len_offset);
        } else {
            self.emit_dynamic_table_field_span_to_stack(
                input_size_offset,
                input_buffer_offset,
                layout.index,
                field_count,
                &format!("{} input.{}", type_name, field),
                start_offset,
                len_offset,
            );
            self.emit_dynamic_table_field_span_to_stack(
                output_size_offset,
                output_buffer_offset,
                layout.index,
                field_count,
                &format!("{} output.{}", type_name, field),
                output_start_offset,
                self.runtime_expr_temp_offset(3),
            );
            self.emit_stack_load("t0", len_offset);
            self.emit_stack_load("t1", self.runtime_expr_temp_offset(3));
            self.emit("sub t2, t0, t1");
            let len_ok = self.fresh_label("mutate_table_field_len_ok");
            self.emit(format!("beqz t2, {}", len_ok));
            self.emit_fail(fail_code);
            self.emit_label(&len_ok);
        }

        self.emit(format!(
            "# cellscript abi: verify mutate preserved Molecule table field {}.{} Input#{} == Output#{}",
            type_name, field, 0, 1
        ));
        let mismatch_label = self.fresh_label("mutate_table_field_mismatch");
        self.emit_stack_load("a0", start_offset);
        self.emit_stack_load("a1", output_start_offset);
        self.emit_stack_load("a2", len_offset);
        self.emit("call __cellscript_memcmp_fixed");
        self.emit(format!("bnez a0, {}", mismatch_label));
        self.emit_fixed_byte_mismatch_fail(&mismatch_label, fail_code);
    }

    pub(super) fn emit_dynamic_table_field_span_to_stack(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        field_index: usize,
        field_count: usize,
        context: &str,
        start_stack_offset: usize,
        len_stack_offset: usize,
    ) {
        self.emit_sp_addi("t4", buffer_offset);
        self.emit_molecule_table_field_span_to_t5_t6("t4", size_offset, field_index, field_count, context);
        self.emit_sp_addi("t4", buffer_offset);
        self.emit("add t5, t4, t5");
        self.emit("add t6, t4, t6");
        self.emit("sub t0, t6, t5");
        self.emit_stack_store("t5", start_stack_offset);
        self.emit_stack_store("t0", len_stack_offset);
    }

    pub(super) fn emit_dynamic_table_fixed_field_pointer_to_stack(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        layout: &SchemaFieldLayout,
        width: usize,
        context: &str,
        start_stack_offset: usize,
    ) {
        self.emit_sp_addi("t4", buffer_offset);
        self.emit_molecule_table_field_bounds_to_t5("t4", size_offset, layout.index, width, context);
        self.emit_sp_addi("t4", buffer_offset);
        self.emit("add t5, t4, t5");
        self.emit_stack_store("t5", start_stack_offset);
    }

    pub(super) fn emit_mutate_replacement_dynamic_table_append_checks(&mut self, pattern: &MutatePattern) -> bool {
        if self.type_fixed_sizes.contains_key(&pattern.ty) || pattern.transitions.is_empty() {
            return false;
        }
        let Some(layouts) = self.type_layouts.get(&pattern.ty).cloned() else {
            return false;
        };
        let field_count = layouts.len();
        let appends = pattern
            .transitions
            .iter()
            .filter_map(|transition| {
                if transition.op != MutateTransitionOp::Append {
                    return None;
                }
                let layout = layouts.get(&transition.field).cloned()?;
                let element_width = molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)?;
                self.fixed_append_fields(&transition.operand, element_width)
                    .map(|fields| (transition.clone(), layout, element_width, fields))
            })
            .collect::<Vec<_>>();
        if appends.len() != pattern.transitions.len() {
            return false;
        }

        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_table_append",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_table_append",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit(format!(
            "# cellscript abi: verify mutate Molecule table append fields {} Input#{} -> Output#{}",
            pattern.ty, pattern.input_index, pattern.output_index
        ));
        for (transition, layout, element_width, fields) in appends {
            self.emit_dynamic_table_vector_append_check(
                &pattern.ty,
                &transition.field,
                &layout,
                field_count,
                element_width,
                &fields,
                input_size_offset,
                input_buffer_offset,
                output_size_offset,
                output_buffer_offset,
            );
        }
        true
    }

    pub(super) fn fixed_append_fields(
        &self,
        operand: &IrOperand,
        expected_width: usize,
    ) -> Option<Vec<(IrOperand, SchemaFieldLayout, usize)>> {
        if self.expected_fixed_byte_source(operand, expected_width).is_some() {
            let ty = match operand {
                IrOperand::Var(var) => var.ty.clone(),
                IrOperand::Const(IrConst::Address(_)) => IrType::Address,
                IrOperand::Const(IrConst::Hash(_)) => IrType::Hash,
                IrOperand::Const(IrConst::Array(items)) => IrType::Array(Box::new(IrType::U8), items.len()),
                IrOperand::Const(_) => return None,
            };
            return Some(vec![(
                operand.clone(),
                SchemaFieldLayout { index: 0, offset: 0, ty, fixed_size: Some(expected_width), fixed_enum_size: None },
                expected_width,
            )]);
        }
        let IrOperand::Var(var) = operand else {
            return None;
        };
        let fields = self.tuple_aggregate_fields.get(&var.id)?;
        let type_name = named_type_name(&var.ty)?;
        let mut layouts = self.type_layouts.get(type_name)?.values().cloned().collect::<Vec<_>>();
        layouts.sort_by_key(|layout| layout.offset);
        if layouts.len() != fields.len() {
            return None;
        }
        let total_width = self.type_fixed_sizes.get(type_name).copied()?;
        if total_width != expected_width {
            return None;
        }
        fields
            .iter()
            .cloned()
            .zip(layouts)
            .map(|(field_operand, layout)| {
                let width = layout_fixed_byte_width(&layout)?;
                self.expected_fixed_byte_source(&field_operand, width)?;
                Some((field_operand, layout, width))
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_dynamic_table_vector_append_check(
        &mut self,
        type_name: &str,
        field: &str,
        layout: &SchemaFieldLayout,
        field_count: usize,
        element_width: usize,
        fields: &[(IrOperand, SchemaFieldLayout, usize)],
        input_size_offset: usize,
        input_buffer_offset: usize,
        output_size_offset: usize,
        output_buffer_offset: usize,
    ) {
        let input_start_offset = self.runtime_expr_temp_offset(0);
        let input_len_offset = self.runtime_expr_temp_offset(1);
        let output_start_offset = self.runtime_expr_temp_offset(2);
        let output_len_offset = self.runtime_expr_temp_offset(3);
        self.emit_dynamic_table_field_span_to_stack(
            input_size_offset,
            input_buffer_offset,
            layout.index,
            field_count,
            &format!("{} input.{}", type_name, field),
            input_start_offset,
            input_len_offset,
        );
        self.emit_dynamic_table_field_span_to_stack(
            output_size_offset,
            output_buffer_offset,
            layout.index,
            field_count,
            &format!("{} output.{}", type_name, field),
            output_start_offset,
            output_len_offset,
        );
        self.emit(format!(
            "# cellscript abi: verify mutate Molecule vector append {}.{} element_size={}",
            type_name, field, element_width
        ));
        self.emit_loaded_schema_bounds_check(input_len_offset, 4, &format!("{} input.{} vector", type_name, field));
        self.emit_loaded_schema_bounds_check(output_len_offset, 4 + element_width, &format!("{} output.{} vector", type_name, field));

        self.emit_stack_load("t4", input_start_offset);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, 4);
        self.emit_stack_load("t1", input_len_offset);
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t0, t2");
        self.emit("addi t3, t3, 4");
        self.emit("sub t2, t1, t3");
        let input_size_ok = self.fresh_label("molecule_append_input_size_ok");
        self.emit(format!("beqz t2, {}", input_size_ok));
        self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
        self.emit_label(&input_size_ok);

        self.emit_stack_load("t4", output_start_offset);
        self.emit_unaligned_scalar_load("t4", "t1", "t2", 0, 4);
        self.emit("addi t0, t0, 1");
        self.emit("sub t2, t1, t0");
        let count_ok = self.fresh_label("molecule_append_count_ok");
        self.emit(format!("beqz t2, {}", count_ok));
        self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
        self.emit_label(&count_ok);

        self.emit_stack_load("t0", input_len_offset);
        self.emit(format!("li t1, {}", element_width));
        self.emit("add t0, t0, t1");
        self.emit_stack_load("t1", output_len_offset);
        self.emit("sub t2, t1, t0");
        let len_ok = self.fresh_label("molecule_append_len_ok");
        self.emit(format!("beqz t2, {}", len_ok));
        self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
        self.emit_label(&len_ok);

        let prefix_ok = self.fresh_label("molecule_append_prefix_ok");
        self.emit_stack_load("a0", input_start_offset);
        self.emit("addi a0, a0, 4");
        self.emit_stack_load("a1", output_start_offset);
        self.emit("addi a1, a1, 4");
        self.emit_stack_load("a2", input_len_offset);
        self.emit("addi a2, a2, -4");
        self.emit("call __cellscript_memcmp_fixed");
        self.emit(format!("beqz a0, {}", prefix_ok));
        self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
        self.emit_label(&prefix_ok);

        self.emit_stack_load("t0", output_start_offset);
        self.emit_stack_load("t1", input_len_offset);
        self.emit("add t0, t0, t1");
        self.emit_stack_store("t0", output_start_offset);
        for (operand, field_layout, width) in fields {
            let Some(source) = self.expected_fixed_byte_source(operand, *width) else {
                self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
                continue;
            };
            self.emit_prepare_fixed_byte_source(&source, *width, &format!("append {}.{}", type_name, field));
            self.emit_pointer_fixed_bytes_against_source(
                output_start_offset,
                field_layout.offset,
                &source,
                *width,
                CellScriptRuntimeError::MutateTransitionMismatch,
            );
        }
    }

    pub(super) fn emit_pointer_fixed_bytes_against_source(
        &mut self,
        output_pointer_stack_offset: usize,
        output_field_offset: usize,
        source: &ExpectedFixedByteSource,
        width: usize,
        fail_code: CellScriptRuntimeError,
    ) {
        let mismatch_label = self.fresh_label("fixed_byte_mismatch");
        match source {
            ExpectedFixedByteSource::Const(bytes) => {
                self.emit_stack_load("t4", output_pointer_stack_offset);
                for (byte_index, byte) in bytes.iter().take(width).enumerate() {
                    self.emit(format!("lbu t0, {}(t4)", output_field_offset + byte_index));
                    self.emit(format!("li t1, {}", byte));
                    self.emit("sub t2, t0, t1");
                    self.emit(format!("bnez t2, {}", mismatch_label));
                }
            }
            ExpectedFixedByteSource::SchemaField(source) => {
                if self.emit_schema_field_source_pointer_to("a1", source, width) {
                    self.emit_stack_load("a0", output_pointer_stack_offset);
                    if output_field_offset != 0 {
                        self.emit_large_addi("a0", "a0", output_field_offset as i64);
                    }
                    self.emit(format!("li a2, {}", width));
                    self.emit("call __cellscript_memcmp_fixed");
                    self.emit(format!("bnez a0, {}", mismatch_label));
                } else {
                    self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);
                }
            }
            ExpectedFixedByteSource::StackSlot { var_id, .. } => {
                self.emit_stack_load("a0", output_pointer_stack_offset);
                if output_field_offset != 0 {
                    self.emit_large_addi("a0", "a0", output_field_offset as i64);
                }
                self.emit_sp_addi("a1", var_id * 8);
                self.emit(format!("li a2, {}", width));
                self.emit("call __cellscript_memcmp_fixed");
                self.emit(format!("bnez a0, {}", mismatch_label));
            }
            ExpectedFixedByteSource::PointerBytes { var_id, .. }
            | ExpectedFixedByteSource::ParamBytes { var_id, .. }
            | ExpectedFixedByteSource::LoadedBytes { var_id, .. } => {
                self.emit_stack_load("a0", output_pointer_stack_offset);
                if output_field_offset != 0 {
                    self.emit_large_addi("a0", "a0", output_field_offset as i64);
                }
                self.emit_stack_load("a1", var_id * 8);
                self.emit(format!("li a2, {}", width));
                self.emit("call __cellscript_memcmp_fixed");
                self.emit(format!("bnez a0, {}", mismatch_label));
            }
        }
        self.emit_fixed_byte_mismatch_fail(&mismatch_label, fail_code);
    }

    pub(super) fn emit_mutate_replacement_data_except_transition_checks(&mut self, pattern: &MutatePattern) -> bool {
        let Some(exclusion_ranges) = self.mutate_transition_exclusion_ranges(pattern) else {
            return false;
        };
        if exclusion_ranges.is_empty() {
            return false;
        }
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_preserved_data",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_preserved_data",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(
                input_size_offset,
                expected_size,
                &format!("{} preserved-data input", pattern.ty),
            );
            self.emit_loaded_schema_exact_size_check(
                output_size_offset,
                expected_size,
                &format!("{} preserved-data output", pattern.ty),
            );
        }
        let size_ok_label = self.fresh_label("mutate_preserved_data_size_ok");
        self.emit_stack_load("t0", input_size_offset);
        self.emit_stack_load("t1", output_size_offset);
        self.emit("sub t2, t0, t1");
        self.emit(format!("beqz t2, {}", size_ok_label));
        self.emit_fail(CellScriptRuntimeError::FieldPreservationMismatch);
        self.emit_label(&size_ok_label);

        self.emit(format!(
            "# cellscript abi: verify mutate preserved data {} Input#{} == Output#{} except transition ranges {:?}",
            pattern.ty, pattern.input_index, pattern.output_index, exclusion_ranges
        ));
        let loop_label = self.fresh_label("mutate_preserved_data_loop");
        let compare_label = self.fresh_label("mutate_preserved_data_compare");
        let skip_label = self.fresh_label("mutate_preserved_data_skip");
        let done_label = self.fresh_label("mutate_preserved_data_done");
        let mismatch_label = self.fresh_label("mutate_preserved_data_mismatch");
        self.emit_sp_addi("a3", input_buffer_offset);
        self.emit_sp_addi("a4", output_buffer_offset);
        self.emit("li t6, 0");
        self.emit_label(&loop_label);
        self.emit("sltu t2, t6, t0");
        self.emit(format!("beqz t2, {}", done_label));
        for (range_index, (start, end)) in exclusion_ranges.iter().enumerate() {
            let next_range_label = self.fresh_label(&format!("mutate_preserved_data_next_range_{}", range_index));
            self.emit(format!("li t3, {}", start));
            self.emit("sltu t2, t6, t3");
            self.emit(format!("bnez t2, {}", compare_label));
            self.emit(format!("li t3, {}", end));
            self.emit("sltu t2, t6, t3");
            self.emit(format!("beqz t2, {}", next_range_label));
            self.emit(format!("j {}", skip_label));
            self.emit_label(&next_range_label);
        }
        self.emit_label(&compare_label);
        self.emit("add t3, a3, t6");
        self.emit("lbu t4, 0(t3)");
        self.emit("add t3, a4, t6");
        self.emit("lbu t5, 0(t3)");
        self.emit("sub t2, t4, t5");
        self.emit(format!("bnez t2, {}", mismatch_label));
        self.emit_label(&skip_label);
        self.emit("addi t6, t6, 1");
        self.emit(format!("j {}", loop_label));
        self.emit_label(&mismatch_label);
        self.emit_fail(CellScriptRuntimeError::FieldPreservationMismatch);
        self.emit_label(&done_label);
        true
    }

    pub(super) fn mutate_u128_transition_layouts(&self, pattern: &MutatePattern) -> Vec<(MutateFieldTransition, SchemaFieldLayout)> {
        let Some(type_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return Vec::new();
        };
        if type_size > RUNTIME_SCRATCH_BUFFER_SIZE {
            return Vec::new();
        }
        pattern
            .transitions
            .iter()
            .filter_map(|transition| {
                if transition.op == MutateTransitionOp::Set {
                    return None;
                }
                let layout = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&transition.field)).cloned()?;
                // Only u128 fields (16 bytes) that don't fit in a single register.
                if layout.ty != IrType::U128 || layout.fixed_size != Some(16) {
                    return None;
                }
                if layout.offset + 16 > RUNTIME_SCRATCH_BUFFER_SIZE {
                    return None;
                }
                // u128 transition: the operand must be a u64 value (delta always fits in 64 bits).
                self.prelude_u64_operand_source(&transition.operand)?;
                Some((transition.clone(), layout))
            })
            .collect()
    }

    pub(super) fn mutate_transition_layouts(&self, pattern: &MutatePattern) -> Vec<(MutateFieldTransition, SchemaFieldLayout, usize)> {
        let Some(type_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return Vec::new();
        };
        if type_size > RUNTIME_SCRATCH_BUFFER_SIZE {
            return Vec::new();
        }
        pattern
            .transitions
            .iter()
            .filter_map(|transition| {
                if transition.op == MutateTransitionOp::Set {
                    return None;
                }
                let layout = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&transition.field)).cloned()?;
                let width = fixed_register_width(&layout.ty, layout.fixed_size)?;
                if layout.offset + width > RUNTIME_SCRATCH_BUFFER_SIZE {
                    return None;
                }
                self.prelude_u64_operand_source(&transition.operand)?;
                Some((transition.clone(), layout, width))
            })
            .collect()
    }

    pub(super) fn mutate_set_transition_layouts(
        &self,
        pattern: &MutatePattern,
    ) -> Vec<(MutateFieldTransition, SchemaFieldLayout, usize)> {
        let Some(type_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return Vec::new();
        };
        if type_size > RUNTIME_SCRATCH_BUFFER_SIZE {
            return Vec::new();
        }
        pattern
            .transitions
            .iter()
            .filter_map(|transition| {
                if transition.op != MutateTransitionOp::Set {
                    return None;
                }
                let layout = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&transition.field)).cloned()?;
                let width = layout_fixed_byte_width(&layout)?;
                if layout.offset + width > RUNTIME_SCRATCH_BUFFER_SIZE {
                    return None;
                }
                if layout_fixed_scalar_width(&layout).is_none()
                    && self.expected_fixed_byte_source(&transition.operand, width).is_none()
                {
                    return None;
                }
                Some((transition.clone(), layout, width))
            })
            .collect()
    }

    pub(super) fn emit_mutate_replacement_transition_checks(&mut self, pattern: &MutatePattern) {
        if self.emit_mutate_replacement_dynamic_table_append_checks(pattern) {
            return;
        }
        if self.emit_mutate_replacement_dynamic_table_transition_checks(pattern) {
            return;
        }
        let transitions = self.mutate_transition_layouts(pattern);
        if transitions.is_empty() {
            return;
        }
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_transition",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_transition",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(
                input_size_offset,
                expected_size,
                &format!("{} mutate transition input", pattern.ty),
            );
            self.emit_loaded_schema_exact_size_check(
                output_size_offset,
                expected_size,
                &format!("{} mutate transition output", pattern.ty),
            );
        }
        self.emit(format!(
            "# cellscript abi: verify mutate transition fields {} Input#{} -> Output#{}",
            pattern.ty, pattern.input_index, pattern.output_index
        ));
        for (transition, layout, width) in transitions {
            let Some(delta) = self.prelude_u64_operand_source(&transition.operand) else {
                continue;
            };
            self.emit_loaded_schema_bounds_check(
                input_size_offset,
                layout.offset + width,
                &format!("{} input.{}", pattern.ty, transition.field),
            );
            self.emit_loaded_schema_bounds_check(
                output_size_offset,
                layout.offset + width,
                &format!("{} output.{}", pattern.ty, transition.field),
            );
            self.emit(format!(
                "# cellscript abi: verify mutate transition field {}.{} {:?} Input#{} -> Output#{} offset={} size={}",
                pattern.ty, transition.field, transition.op, pattern.input_index, pattern.output_index, layout.offset, width
            ));
            self.emit_sp_addi("t4", input_buffer_offset);
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
            let input_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 2);
            self.emit("# cellscript abi: preserve mutate input scalar before transition expression");
            self.emit_stack_store("t0", input_value_offset);
            self.emit_prelude_u64_operand_source_to_t1(&delta);
            self.emit_stack_load("t0", input_value_offset);
            match transition.op {
                MutateTransitionOp::Add => self.emit("add t1, t0, t1"),
                MutateTransitionOp::Sub => self.emit("sub t1, t0, t1"),
                MutateTransitionOp::Set => {
                    unreachable!("set transitions are verified by emit_mutate_replacement_set_transition_checks")
                }
                MutateTransitionOp::Append => {
                    unreachable!("append transitions are verified by emit_mutate_replacement_dynamic_table_append_checks")
                }
            }
            let expected_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 1);
            self.emit("# cellscript abi: preserve mutate expected scalar across output field load");
            self.emit_stack_store("t1", expected_value_offset);
            self.emit_sp_addi("t4", output_buffer_offset);
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
            self.emit_stack_load("t1", expected_value_offset);
            self.emit("sub t2, t0, t1");
            let ok_label = self.fresh_label("mutate_transition_ok");
            self.emit(format!("beqz t2, {}", ok_label));
            self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
            self.emit_label(&ok_label);
        }
    }

    pub(super) fn emit_mutate_replacement_dynamic_table_transition_checks(&mut self, pattern: &MutatePattern) -> bool {
        if self.type_fixed_sizes.contains_key(&pattern.ty) || pattern.transitions.is_empty() {
            return false;
        }
        let Some(layouts) = self.type_layouts.get(&pattern.ty).cloned() else {
            return false;
        };
        let field_count = layouts.len();
        let transitions = pattern
            .transitions
            .iter()
            .filter_map(|transition| {
                let layout = layouts.get(&transition.field).cloned()?;
                let width = layout_fixed_scalar_width(&layout)?;
                (width <= 8 && self.prelude_u64_operand_source(&transition.operand).is_some())
                    .then(|| (transition.clone(), layout, width))
            })
            .collect::<Vec<_>>();
        if transitions.len() != pattern.transitions.len() {
            return false;
        }

        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_table_transition",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_table_transition",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit(format!(
            "# cellscript abi: verify mutate Molecule table transition fields {} Input#{} -> Output#{}",
            pattern.ty, pattern.input_index, pattern.output_index
        ));
        for (transition, layout, width) in transitions {
            let Some(delta) = self.prelude_u64_operand_source(&transition.operand) else {
                continue;
            };
            self.emit_sp_addi("t4", input_buffer_offset);
            self.emit_molecule_table_field_bounds_to_t5(
                "t4",
                input_size_offset,
                layout.index,
                width,
                &format!("{} input.{}", pattern.ty, transition.field),
            );
            self.emit("add t4, t4, t5");
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, width);
            let input_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 2);
            self.emit("# cellscript abi: preserve mutate table input scalar before transition expression");
            self.emit_stack_store("t0", input_value_offset);
            self.emit_prelude_u64_operand_source_to_t1(&delta);
            self.emit_stack_load("t0", input_value_offset);
            match transition.op {
                MutateTransitionOp::Add => self.emit("add t1, t0, t1"),
                MutateTransitionOp::Sub => self.emit("sub t1, t0, t1"),
                MutateTransitionOp::Set => {}
                MutateTransitionOp::Append => {}
            }
            let expected_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 1);
            self.emit("# cellscript abi: preserve mutate table expected scalar across output field load");
            self.emit_stack_store("t1", expected_value_offset);
            self.emit_sp_addi("t4", output_buffer_offset);
            self.emit_molecule_table_field_bounds_to_t5(
                "t4",
                output_size_offset,
                layout.index,
                width,
                &format!("{} output.{}", pattern.ty, transition.field),
            );
            self.emit("add t4, t4, t5");
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, width);
            self.emit_stack_load("t1", expected_value_offset);
            self.emit("sub t2, t0, t1");
            let ok_label = self.fresh_label("mutate_table_transition_ok");
            self.emit(format!("beqz t2, {}", ok_label));
            self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
            self.emit_label(&ok_label);
        }
        let _ = field_count;
        true
    }

    pub(super) fn emit_mutate_replacement_set_transition_checks(&mut self, pattern: &MutatePattern) {
        let transitions = self.mutate_set_transition_layouts(pattern);
        if transitions.is_empty() {
            return;
        }
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_set_transition",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(
                output_size_offset,
                expected_size,
                &format!("{} mutate set transition output", pattern.ty),
            );
        }
        self.emit(format!("# cellscript abi: verify mutate set transition fields {} Output#{}", pattern.ty, pattern.output_index));
        for (transition, layout, width) in transitions {
            self.emit(format!(
                "# cellscript abi: verify mutate set transition field {}.{} Output#{} offset={} size={}",
                pattern.ty, transition.field, pattern.output_index, layout.offset, width
            ));
            if !self.emit_loaded_field_bytes_equals_expected(
                output_size_offset,
                output_buffer_offset,
                &layout,
                &transition.operand,
                &format!("{} set.{}", pattern.ty, transition.field),
            ) {
                self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
            }
        }
    }

    /// u128 transition verification using 128-bit add/sub with carry.
    /// Layout: field is 16 bytes (low 8 + high 8, little-endian).
    /// Delta is always u64 (fits in a single register).
    /// Verification: output == input +/- delta, with carry propagation.
    pub(super) fn emit_mutate_replacement_u128_transition_checks(&mut self, pattern: &MutatePattern) {
        let transitions = self.mutate_u128_transition_layouts(pattern);
        if transitions.is_empty() {
            return;
        }
        let input_size_offset = self.runtime_scratch_size_offset();
        let input_buffer_offset = self.runtime_scratch_buffer_offset();
        let output_size_offset = self.runtime_scratch2_size_offset();
        let output_buffer_offset = self.runtime_scratch2_buffer_offset();
        // Load Input and Output cell data (already done by the caller for
        // preserved field checks, but we need it for transition checks too).
        // If the scratch buffers were already loaded by the preserved-field
        // path, the syscall results are cached in the buffer; we only need
        // to reload if this function is called independently.
        self.emit_bound_cell_data_to_offsets(
            "mutate_input_u128_transition",
            IrCellBindingRole::Input,
            &pattern.binding,
            input_size_offset,
            input_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_bound_cell_data_to_offsets(
            "mutate_output_u128_transition",
            IrCellBindingRole::Output,
            &pattern.binding,
            output_size_offset,
            output_buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(
                input_size_offset,
                expected_size,
                &format!("{} mutate u128 transition input", pattern.ty),
            );
            self.emit_loaded_schema_exact_size_check(
                output_size_offset,
                expected_size,
                &format!("{} mutate u128 transition output", pattern.ty),
            );
        }
        for (transition, layout) in transitions {
            let Some(delta) = self.prelude_u64_operand_source(&transition.operand) else {
                continue;
            };
            self.emit_loaded_schema_bounds_check(
                input_size_offset,
                layout.offset + 16,
                &format!("{} input.{}", pattern.ty, transition.field),
            );
            self.emit_loaded_schema_bounds_check(
                output_size_offset,
                layout.offset + 16,
                &format!("{} output.{}", pattern.ty, transition.field),
            );
            self.emit(format!(
                "# cellscript abi: verify mutate u128 transition field {}.{} {:?} Input#{} -> Output#{} offset={} size=16",
                pattern.ty, transition.field, transition.op, pattern.input_index, pattern.output_index, layout.offset
            ));

            // Load input low 64 bits (little-endian bytes 0..8) into t0
            // Load input high 64 bits (little-endian bytes 8..16) into t3
            self.emit_sp_addi("t4", input_buffer_offset);
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, 8);
            self.emit_unaligned_scalar_load("t4", "t3", "t2", layout.offset + 8, 8);

            // Load delta into t1
            self.emit_prelude_u64_operand_source_to_t1(&delta);

            // Compute expected output = input +/- delta with carry
            match transition.op {
                MutateTransitionOp::Add => {
                    // expected_lo = input_lo + delta
                    // expected_hi = input_hi + carry
                    // where carry = (input_lo + delta < input_lo) ? 1 : 0
                    self.emit("add t5, t0, t1"); // expected_lo = input_lo + delta
                    self.emit("sltu t2, t5, t0"); // carry = 1 if addition overflowed
                    self.emit("add t6, t3, t2"); // expected_hi = input_hi + carry
                }
                MutateTransitionOp::Sub => {
                    // expected_lo = input_lo - delta
                    // expected_hi = input_hi - borrow
                    // where borrow = (input_lo < delta) ? 1 : 0
                    self.emit("sub t5, t0, t1"); // expected_lo = input_lo - delta
                    self.emit("sltu t2, t0, t1"); // borrow = 1 if subtraction underflowed
                    self.emit("sub t6, t3, t2"); // expected_hi = input_hi - borrow
                }
                MutateTransitionOp::Set => {
                    unreachable!("set transitions are verified by emit_mutate_replacement_set_transition_checks")
                }
                MutateTransitionOp::Append => {
                    unreachable!("append transitions are verified by emit_mutate_replacement_dynamic_table_append_checks")
                }
            }

            // Load actual output low 64 bits into t0, high 64 bits into t3
            self.emit_sp_addi("t4", output_buffer_offset);
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, 8);
            self.emit_unaligned_scalar_load("t4", "t3", "t2", layout.offset + 8, 8);

            // Compare: expected (t5, t6) == actual (t0, t3)
            let ok_label = self.fresh_label("mutate_u128_transition_ok");
            self.emit("sub t2, t0, t5"); // diff_lo = actual_lo - expected_lo
            self.emit("sub t1, t3, t6"); // diff_hi = actual_hi - expected_hi
            self.emit("or t2, t2, t1"); // combined diff = diff_lo | diff_hi
            self.emit(format!("beqz t2, {}", ok_label));
            self.emit_fail(CellScriptRuntimeError::MutateTransitionMismatch);
            self.emit_label(&ok_label);
        }
    }

    pub(super) fn can_verify_create_output_fields(&self, pattern: &CreatePattern) -> bool {
        if pattern.fields.is_empty() {
            return false;
        }
        if !self.create_output_fields_cover_type(pattern) {
            return false;
        }
        pattern.fields.iter().all(|(field, value)| {
            self.type_layouts.get(&pattern.ty).and_then(|layouts| layouts.get(field)).is_some_and(|layout| {
                if let Some(width) = layout_fixed_byte_width(layout).or_else(|| self.fixed_named_type_width(&layout.ty)) {
                    self.is_prelude_available_fixed_value(value, width)
                } else {
                    self.can_verify_dynamic_create_output_field_value(value, layout)
                }
            })
        })
    }

    pub(super) fn create_output_fields_cover_type(&self, pattern: &CreatePattern) -> bool {
        let Some(layouts) = self.type_layouts.get(&pattern.ty) else {
            return false;
        };
        let covered_fields = pattern.fields.iter().map(|(field, _)| field.as_str()).collect::<BTreeSet<_>>();
        layouts.keys().all(|field| covered_fields.contains(field.as_str()))
    }

    pub(super) fn can_verify_dynamic_create_output_field_value(&self, value: &IrOperand, layout: &SchemaFieldLayout) -> bool {
        let IrOperand::Var(var) = value else {
            return false;
        };
        (self.schema_pointer_vars.contains(&var.id) && self.schema_pointer_size_offsets.contains_key(&var.id))
            || self.constructed_byte_vectors.contains_key(&var.id)
            || (self.empty_molecule_vector_vars.contains(&var.id)
                && molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).is_some())
    }

    pub(super) fn can_verify_output_lock(&self, pattern: &CreatePattern) -> bool {
        match &pattern.lock {
            Some(lock) => self.expected_fixed_byte_source(lock, 32).is_some(),
            None => true,
        }
    }

    pub(super) fn emit_create_output_checks(&mut self, pattern: &CreatePattern) {
        let size_offset = self.runtime_scratch_size_offset();
        let buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_create_output_checks_at(pattern, size_offset, buffer_offset);
    }

    pub(super) fn emit_create_output_checks_at(&mut self, pattern: &CreatePattern, size_offset: usize, buffer_offset: usize) {
        let is_fixed_type = self.type_fixed_sizes.contains_key(&pattern.ty);
        if let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() {
            self.emit_loaded_schema_exact_size_check(size_offset, expected_size, &pattern.ty);
        }
        for (field, value) in &pattern.fields {
            let Some(layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(field)).cloned() else {
                continue;
            };
            if layout_fixed_byte_width(&layout).or_else(|| self.fixed_named_type_width(&layout.ty)).is_some() {
                if is_fixed_type {
                    self.emit_loaded_field_bytes_equals_expected(
                        size_offset,
                        buffer_offset,
                        &layout,
                        value,
                        &format!("{}.{}", pattern.ty, field),
                    );
                } else {
                    let Some(field_count) = self.type_layouts.get(&pattern.ty).map(|fields| fields.len()) else {
                        self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                        continue;
                    };
                    if !self.emit_dynamic_create_output_fixed_field_equals_expected(
                        size_offset,
                        buffer_offset,
                        &pattern.ty,
                        field,
                        &layout,
                        field_count,
                        value,
                    ) {
                        self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    }
                }
            } else {
                let Some(field_count) = self.type_layouts.get(&pattern.ty).map(|fields| fields.len()) else {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                    continue;
                };
                if !self.emit_dynamic_create_output_field_equals_expected(
                    size_offset,
                    buffer_offset,
                    &pattern.ty,
                    field,
                    &layout,
                    field_count,
                    value,
                ) {
                    self.emit_fail(CellScriptRuntimeError::AssertionFailed);
                }
            }
        }
        if pattern.operation == "settle" {
            self.emit_settle_final_state_check(pattern, size_offset, buffer_offset);
        } else {
            self.emit_state_transition_check(pattern, size_offset, buffer_offset);
        }
    }

    pub(super) fn emit_dynamic_create_output_fixed_field_equals_expected(
        &mut self,
        output_size_offset: usize,
        output_buffer_offset: usize,
        type_name: &str,
        field: &str,
        layout: &SchemaFieldLayout,
        field_count: usize,
        expected: &IrOperand,
    ) -> bool {
        let Some(width) = layout_fixed_byte_width(layout).or_else(|| self.fixed_named_type_width(&layout.ty)) else {
            return false;
        };
        let output_start_offset = self.runtime_expr_temp_offset(0);
        let output_len_offset = self.runtime_expr_temp_offset(1);
        self.emit_dynamic_table_field_span_to_stack(
            output_size_offset,
            output_buffer_offset,
            layout.index,
            field_count,
            &format!("{}.{}", type_name, field),
            output_start_offset,
            output_len_offset,
        );
        self.emit_stack_load("t0", output_len_offset);
        self.emit(format!("li t1, {}", width));
        self.emit("sub t2, t0, t1");
        let len_ok = self.fresh_label("create_fixed_table_field_len_ok");
        self.emit(format!("beqz t2, {}", len_ok));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        self.emit_label(&len_ok);

        if layout_fixed_scalar_width(layout).is_some() {
            self.emit(format!(
                "# cellscript abi: verify output Molecule table scalar field {}.{} index={} size={}",
                type_name, field, layout.index, width
            ));
            self.emit_stack_load("t4", output_start_offset);
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, width);
            let actual_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 1);
            self.emit("# cellscript abi: preserve output table scalar before expected expression");
            self.emit_stack_store("t0", actual_value_offset);
            self.emit_expected_operand_to_t1(expected);
            self.emit_stack_load("t0", actual_value_offset);
            self.emit("sub t2, t0, t1");
            let ok_label = self.fresh_label("output_table_field_ok");
            self.emit(format!("beqz t2, {}", ok_label));
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            self.emit_label(&ok_label);
            return true;
        }

        let Some(source) = self.expected_fixed_byte_source(expected, width) else {
            return false;
        };
        self.emit(format!(
            "# cellscript abi: verify output Molecule table bytes field {}.{} index={} size={}",
            type_name, field, layout.index, width
        ));
        self.emit_prepare_fixed_byte_source(&source, width, &format!("{}.{}", type_name, field));
        self.emit_pointer_fixed_bytes_against_source(
            output_start_offset,
            0,
            &source,
            width,
            CellScriptRuntimeError::DynamicFieldValueMismatch,
        );
        true
    }

    pub(super) fn emit_dynamic_create_output_field_equals_expected(
        &mut self,
        output_size_offset: usize,
        output_buffer_offset: usize,
        type_name: &str,
        field: &str,
        layout: &SchemaFieldLayout,
        field_count: usize,
        expected: &IrOperand,
    ) -> bool {
        let IrOperand::Var(var) = expected else {
            return false;
        };
        let output_start_offset = self.runtime_expr_temp_offset(0);
        let output_len_offset = self.runtime_expr_temp_offset(1);
        self.emit_dynamic_table_field_span_to_stack(
            output_size_offset,
            output_buffer_offset,
            layout.index,
            field_count,
            &format!("{}.{}", type_name, field),
            output_start_offset,
            output_len_offset,
        );
        if let Some(parts) = self.constructed_byte_vectors.get(&var.id).cloned()
            && let Some(element_width) =
                molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        {
            if parts.is_empty() && element_width != 1 {
                self.emit_empty_molecule_vector_field_check(type_name, field, output_start_offset, output_len_offset);
                return true;
            }
            self.emit_constructed_molecule_vector_field_check(
                type_name,
                field,
                output_start_offset,
                output_len_offset,
                &parts,
                element_width,
            );
            return true;
        }
        if self.empty_molecule_vector_vars.contains(&var.id)
            && molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).is_some()
        {
            self.emit_empty_molecule_vector_field_check(type_name, field, output_start_offset, output_len_offset);
            return true;
        }
        if !self.schema_pointer_vars.contains(&var.id) {
            return false;
        }
        let Some(expected_size_offset) = self.schema_pointer_size_offsets.get(&var.id).copied() else {
            return false;
        };
        self.emit_stack_load("t0", output_len_offset);
        self.emit_stack_load("t1", expected_size_offset);
        self.emit("sub t2, t0, t1");
        let len_ok = self.fresh_label("create_dynamic_field_len_ok");
        self.emit(format!("beqz t2, {}", len_ok));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        self.emit_label(&len_ok);

        self.emit(format!("# cellscript abi: verify output dynamic field {}.{} as Molecule bytes", type_name, field));
        let mismatch_label = self.fresh_label("create_dynamic_field_mismatch");
        self.emit_stack_load("a0", output_start_offset);
        self.emit_stack_load("a1", var.id * 8);
        self.emit_stack_load("a2", output_len_offset);
        self.emit("call __cellscript_memcmp_fixed");
        self.emit(format!("bnez a0, {}", mismatch_label));
        self.emit_fixed_byte_mismatch_fail(&mismatch_label, CellScriptRuntimeError::CellLoadFailed);
        true
    }

    pub(super) fn emit_empty_molecule_vector_field_check(
        &mut self,
        type_name: &str,
        field: &str,
        output_start_offset: usize,
        output_len_offset: usize,
    ) {
        self.emit(format!("# cellscript abi: verify output dynamic field {}.{} as empty Molecule vector", type_name, field));
        self.emit_stack_load("t0", output_len_offset);
        self.emit("li t1, 4");
        self.emit("sub t2, t0, t1");
        let len_ok = self.fresh_label("create_empty_vector_len_ok");
        self.emit(format!("beqz t2, {}", len_ok));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        self.emit_label(&len_ok);
        self.emit_stack_load("t0", output_start_offset);
        for offset in 0..4 {
            self.emit(format!("lbu t1, {}(t0)", offset));
            let byte_ok = self.fresh_label("create_empty_vector_byte_ok");
            self.emit(format!("beqz t1, {}", byte_ok));
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            self.emit_label(&byte_ok);
        }
    }

    pub(super) fn emit_constructed_molecule_vector_field_check(
        &mut self,
        type_name: &str,
        field: &str,
        output_start_offset: usize,
        output_len_offset: usize,
        parts: &[IrOperand],
        element_width: usize,
    ) {
        let Some(expected_bytes) =
            parts.iter().try_fold(0usize, |acc, part| self.constructed_byte_vector_part_width(part).map(|width| acc + width))
        else {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        };
        if element_width == 0 || expected_bytes % element_width != 0 {
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            return;
        }
        let expected_elements = expected_bytes / element_width;
        let expected_len = 4 + expected_bytes;
        if element_width == 1 {
            self.emit(format!(
                "# cellscript abi: verify output dynamic field {}.{} as constructed Molecule byte vector len={}",
                type_name, field, expected_bytes
            ));
        } else {
            self.emit(format!(
                "# cellscript abi: verify output dynamic field {}.{} as constructed Molecule vector elements={} bytes={} element_size={}",
                type_name, field, expected_elements, expected_bytes, element_width
            ));
        }
        self.emit_stack_load("t0", output_len_offset);
        self.emit(format!("li t1, {}", expected_len));
        self.emit("sub t2, t0, t1");
        let len_ok = self.fresh_label("create_constructed_vector_len_ok");
        self.emit(format!("beqz t2, {}", len_ok));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        self.emit_label(&len_ok);

        self.emit_stack_load("t4", output_start_offset);
        for (offset, byte) in (expected_elements as u32).to_le_bytes().iter().enumerate() {
            self.emit(format!("lbu t0, {}(t4)", offset));
            self.emit(format!("li t1, {}", byte));
            self.emit("sub t2, t0, t1");
            let byte_ok = self.fresh_label("create_constructed_vector_count_ok");
            self.emit(format!("beqz t2, {}", byte_ok));
            self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
            self.emit_label(&byte_ok);
        }

        let mut cursor = 4usize;
        for part in parts {
            let Some(width) = self.constructed_byte_vector_part_width(part) else {
                self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
                continue;
            };
            let Some(source) = self.expected_fixed_byte_source(part, width) else {
                self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
                continue;
            };
            self.emit_prepare_fixed_byte_source(&source, width, &format!("constructed {}.{}", type_name, field));
            self.emit_pointer_fixed_bytes_against_source(
                output_start_offset,
                cursor,
                &source,
                width,
                CellScriptRuntimeError::CellLoadFailed,
            );
            cursor += width;
        }
    }

    pub(super) fn emit_output_lock_hash_check(&mut self, source: u64, output_index: usize, expected: &IrOperand) -> bool {
        if self.expected_fixed_byte_source(expected, 32).is_none() {
            return false;
        }
        let size_offset = self.runtime_scratch_size_offset();
        let buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_load_cell_by_field_syscall_to_offsets(
            "output_lock_hash",
            source,
            output_index,
            CKB_CELL_FIELD_LOCK_HASH,
            size_offset,
            buffer_offset,
            RUNTIME_SCRATCH_BUFFER_SIZE,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(size_offset, 32, "output lock hash");
        self.emit("# cellscript abi: verify output lock hash offset=0 size=32");
        let layout = SchemaFieldLayout { index: 0, offset: 0, ty: IrType::Hash, fixed_size: Some(32), fixed_enum_size: None };
        self.emit_loaded_field_bytes_equals_expected(size_offset, buffer_offset, &layout, expected, "output lock hash")
    }

    pub(super) fn emit_state_transition_check(
        &mut self,
        pattern: &CreatePattern,
        output_size_offset: usize,
        output_buffer_offset: usize,
    ) {
        let Some(states) = self.flow_states.get(&pattern.ty) else {
            return;
        };
        let state_count = states.len();
        let action_edges = self.state_transition_edges_for_pattern(pattern);
        let Some(consumed_var_id) = self.consumed_var_for_state_transition(&pattern.ty, &action_edges) else {
            if !action_edges.is_empty() {
                self.emit_fail(CellScriptRuntimeError::FlowTransitionMismatch);
            }
            return;
        };
        let Some(input_size_offset) = self.cell_buffer_size_offsets.get(&consumed_var_id).copied() else {
            return;
        };
        let Some(input_buffer_offset) = self.cell_buffer_offsets.get(&consumed_var_id).copied() else {
            return;
        };
        let state_field = self.flow_state_fields.get(&pattern.ty).cloned().unwrap_or_else(|| FLOW_STATE_FIELD_NAME.to_string());
        let Some(state_layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&state_field)).cloned() else {
            return;
        };
        let Some(width) = layout_flow_state_width(&state_layout) else {
            return;
        };
        let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return;
        };

        self.emit(format!("# cellscript abi: state transition {}.{} state_count={}", pattern.ty, state_field, state_count));
        self.emit_loaded_schema_exact_size_check(input_size_offset, expected_size, &format!("{} input", pattern.ty));
        self.emit_loaded_schema_bounds_check(
            input_size_offset,
            state_layout.offset + width,
            &format!("{} input.{}", pattern.ty, state_field),
        );
        self.emit_loaded_schema_bounds_check(
            output_size_offset,
            state_layout.offset + width,
            &format!("{} output.{}", pattern.ty, state_field),
        );
        self.emit_sp_addi("t4", input_buffer_offset);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", state_layout.offset, width);
        let old_range_ok_label = self.fresh_label("flow_old_state_range_ok");
        self.emit(format!("li t3, {}", state_count));
        self.emit("sltu t2, t0, t3");
        self.emit(format!("bnez t2, {}", old_range_ok_label));
        self.emit_fail(CellScriptRuntimeError::FlowOldStateInvalid);
        self.emit_label(&old_range_ok_label);

        self.emit_sp_addi("t4", output_buffer_offset);
        self.emit_unaligned_scalar_load("t4", "t1", "t2", state_layout.offset, width);
        let ok_label = self.fresh_label("flow_transition_ok");
        let rules = self.state_transition_rules_for_pattern(pattern, &action_edges);
        if rules.is_empty() {
            self.emit("addi t0, t0, 1");
            self.emit("sub t2, t1, t0");
            self.emit(format!("beqz t2, {}", ok_label));
        } else {
            for rule in rules {
                let next_rule_label = self.fresh_label("flow_transition_next_rule");
                self.emit(format!("li t3, {}", rule.from_index));
                self.emit("sub t2, t0, t3");
                self.emit(format!("bnez t2, {}", next_rule_label));
                self.emit(format!("li t3, {}", rule.to_index));
                self.emit("sub t2, t1, t3");
                self.emit(format!("beqz t2, {}", ok_label));
                self.emit_label(&next_rule_label);
            }
        }
        self.emit_fail(CellScriptRuntimeError::FlowTransitionMismatch);
        self.emit_label(&ok_label);

        let range_ok_label = self.fresh_label("flow_state_range_ok");
        self.emit(format!("li t3, {}", state_count));
        self.emit("sltu t2, t1, t3");
        self.emit(format!("bnez t2, {}", range_ok_label));
        self.emit_fail(CellScriptRuntimeError::FlowNewStateInvalid);
        self.emit_label(&range_ok_label);
    }

    pub(super) fn state_transition_edges_for_pattern(&self, pattern: &CreatePattern) -> Vec<IrStateTransitionEdge> {
        self.current_state_transition_edges
            .iter()
            .filter(|state_edge| {
                state_edge.type_name == pattern.ty
                    && state_edge.output_binding.as_ref().is_none_or(|binding| binding == &pattern.binding)
            })
            .cloned()
            .collect()
    }

    pub(super) fn state_transition_rules_for_pattern(
        &self,
        pattern: &CreatePattern,
        action_edges: &[IrStateTransitionEdge],
    ) -> Vec<IrFlowRule> {
        if !action_edges.is_empty() {
            return action_edges
                .iter()
                .map(|state_edge| IrFlowRule {
                    from: state_edge.from.clone(),
                    to: state_edge.to.clone(),
                    from_index: state_edge.from_index,
                    to_index: state_edge.to_index,
                })
                .collect();
        }
        self.flow_rules.get(&pattern.ty).cloned().unwrap_or_default()
    }

    pub(super) fn consumed_var_for_state_transition(&self, type_name: &str, action_edges: &[IrStateTransitionEdge]) -> Option<usize> {
        if let Some(binding) = action_edges.iter().filter_map(|state_edge| state_edge.input_binding.as_ref()).next() {
            let var_id = self.consume_binding_ids.get(binding).copied()?;
            if self.consume_type_names.get(&var_id).is_some_and(|consumed_type| consumed_type == type_name) {
                return Some(var_id);
            }
            return None;
        }
        self.consumed_var_for_type(type_name)
    }

    pub(super) fn emit_settle_final_state_check(
        &mut self,
        pattern: &CreatePattern,
        output_size_offset: usize,
        output_buffer_offset: usize,
    ) {
        let Some(states) = self.flow_states.get(&pattern.ty) else {
            return;
        };
        if states.len() < 2 {
            return;
        }
        let final_state = states.len() - 1;
        let Some(consumed_var_id) = self.consumed_var_for_type(&pattern.ty) else {
            return;
        };
        let Some(input_size_offset) = self.cell_buffer_size_offsets.get(&consumed_var_id).copied() else {
            return;
        };
        let Some(input_buffer_offset) = self.cell_buffer_offsets.get(&consumed_var_id).copied() else {
            return;
        };
        let state_field = self.flow_state_fields.get(&pattern.ty).cloned().unwrap_or_else(|| FLOW_STATE_FIELD_NAME.to_string());
        let Some(state_layout) = self.type_layouts.get(&pattern.ty).and_then(|fields| fields.get(&state_field)).cloned() else {
            return;
        };
        let Some(width) = layout_flow_state_width(&state_layout) else {
            return;
        };
        let Some(expected_size) = self.type_fixed_sizes.get(&pattern.ty).copied() else {
            return;
        };

        self.emit(format!(
            "# cellscript abi: settle final-state {}.{} final_state={} state_count={}",
            pattern.ty,
            state_field,
            final_state,
            states.len()
        ));
        self.emit_loaded_schema_exact_size_check(input_size_offset, expected_size, &format!("{} input", pattern.ty));
        self.emit_loaded_schema_bounds_check(
            input_size_offset,
            state_layout.offset + width,
            &format!("{} input.{}", pattern.ty, state_field),
        );
        self.emit_loaded_schema_bounds_check(
            output_size_offset,
            state_layout.offset + width,
            &format!("{} output.{}", pattern.ty, state_field),
        );

        self.emit_sp_addi("t4", input_buffer_offset);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", state_layout.offset, width);
        self.emit(format!("li t3, {}", final_state));
        self.emit("sub t2, t0, t3");
        let input_ok_label = self.fresh_label("settle_input_final_state_ok");
        self.emit(format!("beqz t2, {}", input_ok_label));
        self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
        self.emit_label(&input_ok_label);

        self.emit_sp_addi("t4", output_buffer_offset);
        self.emit_unaligned_scalar_load("t4", "t1", "t2", state_layout.offset, width);
        self.emit("sub t2, t1, t3");
        let output_ok_label = self.fresh_label("settle_output_final_state_ok");
        self.emit(format!("beqz t2, {}", output_ok_label));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&output_ok_label);
    }

    pub(super) fn consumed_var_for_type(&self, type_name: &str) -> Option<usize> {
        self.consume_order
            .iter()
            .copied()
            .find(|var_id| self.consume_type_names.get(var_id).is_some_and(|consumed_type| consumed_type == type_name))
    }

    pub(super) fn is_prelude_available_scalar(&self, operand: &IrOperand) -> bool {
        match operand {
            IrOperand::Const(IrConst::Bool(_) | IrConst::U8(_) | IrConst::U16(_) | IrConst::U32(_) | IrConst::U64(_)) => true,
            IrOperand::Var(var) => matches!(var.ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64),
            _ => false,
        }
    }

    pub(super) fn is_prelude_available_fixed_value(&self, operand: &IrOperand, expected_width: usize) -> bool {
        if self.is_prelude_available_scalar(operand) {
            return true;
        }
        self.expected_fixed_byte_source(operand, expected_width).is_some()
    }

    pub(super) fn emit_unaligned_scalar_load(
        &mut self,
        base_reg: &str,
        dest_reg: &str,
        scratch_reg: &str,
        offset: usize,
        width: usize,
    ) {
        self.emit(format!("li {}, 0", dest_reg));
        for byte_index in 0..width {
            self.emit_memory_load_with_avoid("lbu", scratch_reg, base_reg, offset + byte_index, &[dest_reg, scratch_reg, base_reg]);
            if byte_index != 0 {
                self.emit(format!("slli {}, {}, {}", scratch_reg, scratch_reg, byte_index * 8));
            }
            self.emit(format!("or {}, {}, {}", dest_reg, dest_reg, scratch_reg));
        }
    }

    /// Load a fixed-width scalar from schema bytes. Cell data retained in a
    /// compiler-owned frame buffer starts at an eight-byte-aligned address, so
    /// an aligned u64 field can use one native load. Pointers without that
    /// provenance, narrower scalars, and unaligned fields keep the bytewise
    /// little-endian path.
    pub(super) fn emit_schema_scalar_load(
        &mut self,
        schema_var_id: usize,
        base_reg: &str,
        dest_reg: &str,
        scratch_reg: &str,
        offset: usize,
        width: usize,
    ) {
        if width == 8 && offset.is_multiple_of(8) && self.cell_buffer_offsets.contains_key(&schema_var_id) {
            self.emit(format!("# cellscript abi: aligned u64 schema load var{} offset={}", schema_var_id, offset));
            self.emit_memory_load_with_avoid("ld", dest_reg, base_reg, offset, &[dest_reg, base_reg]);
            return;
        }
        self.emit_unaligned_scalar_load(base_reg, dest_reg, scratch_reg, offset, width);
    }

    pub(super) fn emit_sign_extend_i32(&mut self, register: &str) {
        self.emit(format!("# cellscript abi: sign-extend i32 in {}", register));
        self.emit(format!("slli {}, {}, 32", register, register));
        self.emit(format!("srai {}, {}, 32", register, register));
    }

    pub(super) fn fresh_label(&mut self, prefix: &str) -> String {
        let label = format!(".L{}_{}", prefix, self.next_runtime_label);
        self.next_runtime_label += 1;
        label
    }
}
