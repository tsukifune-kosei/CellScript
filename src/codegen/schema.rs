use super::*;

impl CodeGenerator {
    pub(super) fn emit_loaded_schema_bounds_check(&mut self, size_offset: usize, required_size: usize, context: &str) {
        let known_exact =
            self.dominant_schema_exact_sizes.get(&size_offset).or_else(|| self.block_schema_exact_sizes.get(&size_offset)).copied();
        let known_min = self.block_schema_min_sizes.get(&size_offset).copied().unwrap_or(0);
        if known_exact.is_some_and(|size| size >= required_size) || known_min >= required_size {
            self.emit(format!("# cellscript abi: bounds check {} required={} elided by proven size", context, required_size));
            // The removed guard used to end a machine block. Preserve a zero-byte
            // layout boundary so long runs of proven field accesses remain
            // independently auditable without paying for a synthetic branch.
            let boundary = self.fresh_label("schema_proof_boundary");
            self.emit_label(&boundary);
            return;
        }
        self.emit(format!("# cellscript abi: bounds check {} required={}", context, required_size));
        let ok_label = self.fresh_label("schema_bounds_ok");
        self.emit_stack_load("a0", size_offset);
        self.emit(format!("li a1, {}", required_size));
        self.emit("call __cellscript_require_min_size");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&ok_label);
        self.block_schema_min_sizes
            .entry(size_offset)
            .and_modify(|known| *known = (*known).max(required_size))
            .or_insert(required_size);
    }

    pub(super) fn emit_loaded_schema_exact_size_check(&mut self, size_offset: usize, expected_size: usize, context: &str) {
        let known_exact =
            self.dominant_schema_exact_sizes.get(&size_offset).or_else(|| self.block_schema_exact_sizes.get(&size_offset)).copied();
        if known_exact == Some(expected_size) {
            self.emit(format!("# cellscript abi: exact size check {} expected={} elided by proven size", context, expected_size));
            return;
        }
        self.emit(format!("# cellscript abi: exact size check {} expected={}", context, expected_size));
        let ok_label = self.fresh_label("schema_size_ok");
        self.emit_stack_load("a0", size_offset);
        self.emit(format!("li a1, {}", expected_size));
        // Inline the exact-size helper's sub/ret body. Keep its argument and
        // result registers unchanged, without clobbering any scratch register.
        self.emit("sub a0, a0, a1");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_fail(CellScriptRuntimeError::ExactSizeMismatch);
        self.emit_label(&ok_label);
        self.block_schema_exact_sizes.insert(size_offset, expected_size);
        self.block_schema_min_sizes.insert(size_offset, expected_size);
    }

    pub(super) fn emit_dominating_schema_exact_size_check(&mut self, size_offset: usize, expected_size: usize, context: &str) {
        self.emit_loaded_schema_exact_size_check(size_offset, expected_size, context);
        self.dominant_schema_exact_sizes.insert(size_offset, expected_size);
    }

    pub(super) fn invalidate_schema_size_facts(&mut self, size_offset: usize) {
        self.dominant_schema_exact_sizes.remove(&size_offset);
        self.block_schema_exact_sizes.remove(&size_offset);
        self.block_schema_min_sizes.remove(&size_offset);
    }

    pub(super) fn emit_molecule_table_field_bounds_to_t5(
        &mut self,
        base_reg: &str,
        size_offset: usize,
        field_index: usize,
        field_width: usize,
        context: &str,
    ) {
        self.emit(format!("# cellscript abi: molecule table field {} index={} min_width={}", context, field_index, field_width));
        let field_count = field_index + 1;
        let header_size = 4 + 4 * field_count;
        self.emit_loaded_schema_bounds_check(size_offset, header_size, context);

        self.emit_stack_load("a0", size_offset);
        let total_ok = self.fresh_label("molecule_table_total_ok");
        self.emit_unaligned_scalar_load(base_reg, "t0", "t2", 0, 4);
        self.emit("sub t2, t0, a0");
        self.emit(format!("beqz t2, {}", total_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&total_ok);

        self.emit_unaligned_scalar_load(base_reg, "t5", "t2", 4 + 4 * field_index, 4);
        self.emit(format!("li t1, {}", header_size));
        self.emit("sltu t2, t5, t1");
        let start_ok = self.fresh_label("molecule_table_start_ok");
        self.emit(format!("beqz t2, {}", start_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&start_ok);

        if field_width > 0 {
            self.emit(format!("li t1, {}", field_width));
            self.emit("add t3, t5, t1");
            self.emit("sltu t2, t3, t5");
            let overflow_ok = self.fresh_label("molecule_table_field_overflow_ok");
            self.emit(format!("beqz t2, {}", overflow_ok));
            self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
            self.emit_label(&overflow_ok);
            self.emit("sltu t2, a0, t3");
            let end_ok = self.fresh_label("molecule_table_end_ok");
            self.emit(format!("beqz t2, {}", end_ok));
            self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
            self.emit_label(&end_ok);
        }
    }

    pub(super) fn emit_molecule_table_field_span_to_t5_t6(
        &mut self,
        base_reg: &str,
        size_offset: usize,
        field_index: usize,
        field_count: usize,
        context: &str,
    ) {
        self.emit(format!(
            "# cellscript abi: molecule table dynamic field {} index={} field_count={}",
            context, field_index, field_count
        ));
        let header_size = 4 + 4 * field_count;
        self.emit_loaded_schema_bounds_check(size_offset, header_size, context);

        self.emit_stack_load("a0", size_offset);
        let total_ok = self.fresh_label("molecule_table_total_ok");
        self.emit_unaligned_scalar_load(base_reg, "t0", "t2", 0, 4);
        self.emit("sub t2, t0, a0");
        self.emit(format!("beqz t2, {}", total_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&total_ok);

        self.emit_unaligned_scalar_load(base_reg, "t5", "t2", 4 + 4 * field_index, 4);
        if field_index + 1 < field_count {
            self.emit_unaligned_scalar_load(base_reg, "t6", "t2", 4 + 4 * (field_index + 1), 4);
        } else {
            self.emit("add t6, a0, zero");
        }

        self.emit(format!("li t1, {}", header_size));
        self.emit("sltu t2, t5, t1");
        let start_ok = self.fresh_label("molecule_table_start_ok");
        self.emit(format!("beqz t2, {}", start_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&start_ok);

        self.emit("sltu t2, t6, t5");
        let order_ok = self.fresh_label("molecule_table_order_ok");
        self.emit(format!("beqz t2, {}", order_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&order_ok);

        self.emit("sltu t2, a0, t6");
        let end_ok = self.fresh_label("molecule_table_end_ok");
        self.emit(format!("beqz t2, {}", end_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&end_ok);
    }

    pub(super) fn emit_loaded_field_equals_expected(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        layout: &SchemaFieldLayout,
        expected: &IrOperand,
        context: &str,
    ) {
        let Some(width) = layout_fixed_scalar_width(layout) else {
            return;
        };
        self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, context);
        self.emit(format!("# cellscript abi: verify output field {} offset={} size={}", context, layout.offset, width));
        self.emit_sp_addi("t4", buffer_offset);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
        let actual_value_offset = self.runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 1);
        self.emit("# cellscript abi: preserve output scalar before expected expression");
        self.emit_stack_store("t0", actual_value_offset);
        self.emit_expected_operand_to_t1(expected);
        self.emit_stack_load("t0", actual_value_offset);
        self.emit("sub t2, t0, t1");
        let ok_label = self.fresh_label("output_field_ok");
        self.emit(format!("beqz t2, {}", ok_label));
        self.emit_fail(CellScriptRuntimeError::CellLoadFailed);
        self.emit_label(&ok_label);
    }

    pub(super) fn emit_loaded_fixed_bytes_against_source(
        &mut self,
        output_buffer_offset: usize,
        output_field_offset: usize,
        source: &ExpectedFixedByteSource,
        width: usize,
        fail_code: CellScriptRuntimeError,
    ) {
        let mismatch_label = self.fresh_label("fixed_byte_mismatch");
        self.emit_sp_addi("t4", output_buffer_offset);
        match source {
            ExpectedFixedByteSource::SchemaField(source) => {
                if self.emit_schema_field_source_pointer_to("a1", source, width) {
                    self.emit_sp_addi("a0", output_buffer_offset + output_field_offset);
                    self.emit(format!("li a2, {}", width));
                    self.emit("call __cellscript_memcmp_fixed");
                    self.emit(format!("bnez a0, {}", mismatch_label));
                } else {
                    self.emit("# cellscript abi: fail closed because schema field byte source is not addressable");
                    self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);
                }
            }
            ExpectedFixedByteSource::Const(bytes) => {
                if width >= 8 && bytes.iter().take(width).all(|byte| *byte == 0) {
                    self.emit_sp_addi("a0", output_buffer_offset + output_field_offset);
                    self.emit(format!("li a1, {}", width));
                    self.emit("call __cellscript_memzero_fixed");
                    self.emit(format!("bnez a0, {}", mismatch_label));
                } else {
                    for (byte_index, byte) in bytes.iter().take(width).enumerate() {
                        self.emit(format!("lbu t0, {}(t4)", output_field_offset + byte_index));
                        self.emit(format!("li t1, {}", byte));
                        self.emit("sub t2, t0, t1");
                        self.emit(format!("bnez t2, {}", mismatch_label));
                    }
                }
            }
            ExpectedFixedByteSource::StackSlot { var_id, .. } => {
                self.emit_loaded_fixed_bytes_helper_call(
                    output_buffer_offset,
                    output_field_offset,
                    SourcePointer::StackAddress { offset: var_id * 8 },
                    width,
                    &mismatch_label,
                );
            }
            ExpectedFixedByteSource::PointerBytes { var_id, .. }
            | ExpectedFixedByteSource::ParamBytes { var_id, .. }
            | ExpectedFixedByteSource::LoadedBytes { var_id, .. } => {
                self.emit_loaded_fixed_bytes_helper_call(
                    output_buffer_offset,
                    output_field_offset,
                    SourcePointer::LoadedStackPointer { var_id: *var_id, offset: 0 },
                    width,
                    &mismatch_label,
                );
            }
        }
        self.emit_fixed_byte_mismatch_fail(&mismatch_label, fail_code);
    }

    pub(super) fn emit_loaded_fixed_bytes_helper_call(
        &mut self,
        output_buffer_offset: usize,
        output_field_offset: usize,
        source: SourcePointer,
        width: usize,
        mismatch_label: &str,
    ) {
        self.emit_sp_addi("a0", output_buffer_offset + output_field_offset);
        match source {
            SourcePointer::LoadedStackPointer { var_id, offset } => {
                self.emit_stack_load("a1", var_id * 8);
                if offset != 0 {
                    self.emit_large_addi("a1", "a1", offset as i64);
                }
            }
            SourcePointer::StackAddress { offset } => {
                self.emit_sp_addi("a1", offset);
            }
        }
        self.emit(format!("li a2, {}", width));
        self.emit("call __cellscript_memcmp_fixed");
        self.emit(format!("bnez a0, {}", mismatch_label));
    }

    pub(super) fn emit_loaded_field_bytes_equals_expected(
        &mut self,
        size_offset: usize,
        buffer_offset: usize,
        layout: &SchemaFieldLayout,
        expected: &IrOperand,
        context: &str,
    ) -> bool {
        if layout_fixed_scalar_width(layout).is_some() {
            self.emit_loaded_field_equals_expected(size_offset, buffer_offset, layout, expected, context);
            return true;
        }
        let Some(width) = layout_fixed_byte_width(layout).or_else(|| self.fixed_named_type_width(&layout.ty)) else {
            return false;
        };
        let Some(source) = self.expected_fixed_byte_source(expected, width) else {
            return false;
        };
        self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, context);
        match source {
            ExpectedFixedByteSource::SchemaField(source) => {
                if let Some(source_size_offset) = self.schema_pointer_size_offsets.get(&source.obj_var_id).copied() {
                    if let Some(expected_size) = self.type_fixed_sizes.get(&source.type_name).copied() {
                        self.emit_loaded_schema_exact_size_check(source_size_offset, expected_size, &source.type_name);
                    }
                    self.emit_loaded_schema_bounds_check(
                        source_size_offset,
                        source.layout.offset + width,
                        &format!("{}.{}", source.type_name, source.field),
                    );
                }
                self.emit(format!("# cellscript abi: verify output bytes field {} offset={} size={}", context, layout.offset, width));
                self.emit(format!(
                    "# cellscript abi: expected bytes field {}.{} offset={} size={}",
                    source.type_name, source.field, source.layout.offset, width
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::SchemaField(source),
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
            ExpectedFixedByteSource::Const(bytes) => {
                self.emit(format!(
                    "# cellscript abi: verify output bytes field {} offset={} size={} against const",
                    context, layout.offset, width
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::Const(bytes),
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
            ExpectedFixedByteSource::StackSlot { var_id, width } => {
                self.emit(format!(
                    "# cellscript abi: verify output bytes field {} offset={} size={} against stack slot var{}",
                    context, layout.offset, width, var_id
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::StackSlot { var_id, width },
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
            ExpectedFixedByteSource::PointerBytes { var_id, width } => {
                self.emit(format!(
                    "# cellscript abi: verify output bytes field {} offset={} size={} against pointer var{}",
                    context, layout.offset, width, var_id
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::PointerBytes { var_id, width },
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
            ExpectedFixedByteSource::ParamBytes { var_id, size_offset, width } => {
                self.emit_loaded_schema_exact_size_check(size_offset, width, &format!("param var{}", var_id));
                self.emit(format!(
                    "# cellscript abi: verify output bytes field {} offset={} size={} against fixed-byte param var{}",
                    context, layout.offset, width, var_id
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::ParamBytes { var_id, size_offset, width },
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
            ExpectedFixedByteSource::LoadedBytes { var_id, size_offset, width } => {
                self.emit_loaded_schema_exact_size_check(size_offset, width, &format!("loaded bytes var{}", var_id));
                self.emit(format!(
                    "# cellscript abi: verify output bytes field {} offset={} size={} against loaded bytes var{}",
                    context, layout.offset, width, var_id
                ));
                self.emit_loaded_fixed_bytes_against_source(
                    buffer_offset,
                    layout.offset,
                    &ExpectedFixedByteSource::LoadedBytes { var_id, size_offset, width },
                    width,
                    CellScriptRuntimeError::CellLoadFailed,
                );
            }
        }
        true
    }

    pub(super) fn emit_prepare_fixed_byte_source(&mut self, source: &ExpectedFixedByteSource, width: usize, context: &str) {
        match source {
            ExpectedFixedByteSource::SchemaField(source) => {
                self.emit_prepare_schema_field_source(source, width);
            }
            ExpectedFixedByteSource::ParamBytes { var_id, size_offset, width } => {
                self.emit_loaded_schema_exact_size_check(*size_offset, *width, &format!("{} param var{}", context, var_id));
            }
            ExpectedFixedByteSource::LoadedBytes { var_id, size_offset, width } => {
                self.emit_loaded_schema_exact_size_check(*size_offset, *width, &format!("{} loaded bytes var{}", context, var_id));
            }
            ExpectedFixedByteSource::Const(_)
            | ExpectedFixedByteSource::StackSlot { .. }
            | ExpectedFixedByteSource::PointerBytes { .. } => {}
        }
    }

    pub(super) fn emit_fixed_byte_source_byte_to(
        &mut self,
        dest_reg: &str,
        base_reg: &str,
        source: &ExpectedFixedByteSource,
        byte_index: usize,
    ) {
        match source {
            ExpectedFixedByteSource::SchemaField(source) => {
                if self.emit_schema_field_source_pointer_to(base_reg, source, byte_index + 1) {
                    self.emit(format!("lbu {}, {}({})", dest_reg, byte_index, base_reg));
                } else {
                    self.emit("# cellscript abi: fail closed because schema field byte source is not addressable");
                    self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);
                }
            }
            ExpectedFixedByteSource::Const(bytes) => {
                self.emit(format!("li {}, {}", dest_reg, bytes[byte_index]));
            }
            ExpectedFixedByteSource::StackSlot { var_id, .. } => {
                self.emit_sp_addi(base_reg, var_id * 8);
                self.emit(format!("lbu {}, {}({})", dest_reg, byte_index, base_reg));
            }
            ExpectedFixedByteSource::PointerBytes { var_id, .. }
            | ExpectedFixedByteSource::ParamBytes { var_id, .. }
            | ExpectedFixedByteSource::LoadedBytes { var_id, .. } => {
                self.emit_stack_load(base_reg, var_id * 8);
                self.emit(format!("lbu {}, {}({})", dest_reg, byte_index, base_reg));
            }
        }
    }

    pub(super) fn emit_fixed_byte_source_pointer_to(&mut self, dest_reg: &str, source: &ExpectedFixedByteSource) -> bool {
        match source {
            ExpectedFixedByteSource::SchemaField(source) => {
                let Some(width) = layout_fixed_byte_width(&source.layout).or_else(|| self.fixed_named_type_width(&source.layout.ty))
                else {
                    return false;
                };
                self.emit_schema_field_source_pointer_to(dest_reg, source, width)
            }
            ExpectedFixedByteSource::StackSlot { var_id, .. } => {
                self.emit_sp_addi(dest_reg, var_id * 8);
                true
            }
            ExpectedFixedByteSource::PointerBytes { var_id, .. }
            | ExpectedFixedByteSource::ParamBytes { var_id, .. }
            | ExpectedFixedByteSource::LoadedBytes { var_id, .. } => {
                self.emit_stack_load(dest_reg, var_id * 8);
                true
            }
            ExpectedFixedByteSource::Const(_) => false,
        }
    }

    pub(super) fn emit_fixed_byte_source_pointer_or_const_to(&mut self, dest_reg: &str, source: &ExpectedFixedByteSource) -> bool {
        if let ExpectedFixedByteSource::Const(bytes) = source {
            let label = self.const_data_label_for_bytes(bytes.clone());
            self.emit(format!("la {}, {}", dest_reg, label));
            true
        } else {
            self.emit_fixed_byte_source_pointer_to(dest_reg, source)
        }
    }

    pub(super) fn emit_fixed_byte_mismatch_fail(&mut self, mismatch_label: &str, fail_code: CellScriptRuntimeError) {
        let done_label = self.fresh_label("fixed_byte_verify_done");
        self.emit(format!("j {}", done_label));
        self.emit_label(mismatch_label);
        self.emit_fail(fail_code);
        self.emit_label(&done_label);
    }

    pub(super) fn emit_fixed_byte_comparison(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> bool {
        let Some(width) = operand_fixed_byte_width(left) else {
            return false;
        };
        if operand_fixed_byte_width(right) != Some(width) {
            return false;
        }
        let Some(left_source) = self.expected_fixed_byte_source(left, width) else {
            return false;
        };
        let Some(right_source) = self.expected_fixed_byte_source(right, width) else {
            return false;
        };
        self.emit(format!("# cellscript abi: fixed-byte {:?} comparison size={}", op, width));
        self.emit_prepare_fixed_byte_source(&left_source, width, "left fixed-byte comparison");
        self.emit_prepare_fixed_byte_source(&right_source, width, "right fixed-byte comparison");
        if width >= 8 && self.emit_fixed_byte_comparison_helper(dest, op, &left_source, &right_source, width) {
            return true;
        }
        let mismatch_label = self.fresh_label("fixed_byte_mismatch");
        let done_label = self.fresh_label("fixed_byte_done");
        for byte_index in 0..width {
            self.emit_fixed_byte_source_byte_to("t0", "t4", &left_source, byte_index);
            self.emit_fixed_byte_source_byte_to("t1", "t5", &right_source, byte_index);
            self.emit("sub t2, t0, t1");
            self.emit(format!("bnez t2, {}", mismatch_label));
        }
        let equal_value = if matches!(op, BinaryOp::Eq) { 1 } else { 0 };
        let mismatch_value = if matches!(op, BinaryOp::Eq) { 0 } else { 1 };
        self.emit(format!("li t3, {}", equal_value));
        self.emit(format!("j {}", done_label));
        self.emit_label(&mismatch_label);
        self.emit(format!("li t3, {}", mismatch_value));
        self.emit_label(&done_label);
        self.emit_stack_store("t3", dest.id * 8);
        true
    }

    pub(super) fn emit_fixed_byte_comparison_helper(
        &mut self,
        dest: &IrVar,
        op: BinaryOp,
        left_source: &ExpectedFixedByteSource,
        right_source: &ExpectedFixedByteSource,
        width: usize,
    ) -> bool {
        match (left_source, right_source) {
            (ExpectedFixedByteSource::Const(bytes), source) if bytes.iter().take(width).all(|byte| *byte == 0) => {
                if !self.emit_fixed_byte_source_pointer_to("a0", source) {
                    return false;
                }
                self.emit(format!("li a1, {}", width));
                self.emit("call __cellscript_memzero_fixed");
            }
            (source, ExpectedFixedByteSource::Const(bytes)) if bytes.iter().take(width).all(|byte| *byte == 0) => {
                if !self.emit_fixed_byte_source_pointer_to("a0", source) {
                    return false;
                }
                self.emit(format!("li a1, {}", width));
                self.emit("call __cellscript_memzero_fixed");
            }
            (ExpectedFixedByteSource::Const(_), _) | (_, ExpectedFixedByteSource::Const(_)) => return false,
            _ => {
                if !self.emit_fixed_byte_source_pointer_to("a0", left_source) {
                    return false;
                }
                let Some(left_pointer_offset) = self.checked_runtime_expr_temp_offset(0) else {
                    return false;
                };
                self.emit_stack_store("a0", left_pointer_offset);
                if !self.emit_fixed_byte_source_pointer_to("a1", right_source) {
                    return false;
                }
                self.emit_stack_load("a0", left_pointer_offset);
                self.emit(format!("li a2, {}", width));
                self.emit("call __cellscript_memcmp_fixed");
            }
        }
        if matches!(op, BinaryOp::Eq) {
            self.emit("seqz t3, a0");
        } else {
            self.emit("snez t3, a0");
        }
        self.emit_stack_store("t3", dest.id * 8);
        true
    }

    pub(super) fn expected_fixed_byte_source(&self, operand: &IrOperand, expected_width: usize) -> Option<ExpectedFixedByteSource> {
        match operand {
            IrOperand::Const(value) => {
                let bytes = fixed_byte_const_bytes(value).or_else(|| {
                    fixed_scalar_const_value(value)
                        .and_then(|value| (expected_width <= 8).then(|| value.to_le_bytes()[..expected_width].to_vec()))
                })?;
                (bytes.len() == expected_width).then_some(ExpectedFixedByteSource::Const(bytes))
            }
            IrOperand::Var(var)
                if self.fixed_byte_like_width(&var.ty).or_else(|| fixed_aggregate_pointer_param_width(&var.ty)).is_some() =>
            {
                let var_width = self.fixed_byte_like_width(&var.ty).or_else(|| fixed_aggregate_pointer_param_width(&var.ty))?;
                if let Some(source) = self.schema_field_value_sources.get(&var.id).cloned() {
                    let source_width =
                        layout_fixed_byte_width(&source.layout).or_else(|| self.fixed_named_type_width(&source.layout.ty))?;
                    if source_width == expected_width {
                        return Some(ExpectedFixedByteSource::SchemaField(source));
                    }
                }
                if let Some(bytes) = self.prelude_fixed_byte_constants.get(&var.id).cloned()
                    && bytes.len() == expected_width
                {
                    return Some(ExpectedFixedByteSource::Const(bytes));
                }
                if self.schema_pointer_vars.contains(&var.id) && var_width == expected_width {
                    if let Some(size_offset) = self.schema_pointer_size_offsets.get(&var.id).copied() {
                        return Some(ExpectedFixedByteSource::LoadedBytes { var_id: var.id, size_offset, width: expected_width });
                    }
                    return Some(ExpectedFixedByteSource::PointerBytes { var_id: var.id, width: expected_width });
                }
                if let Some(size_offset) = self.cell_buffer_size_offsets.get(&var.id).copied()
                    && var_width == expected_width
                {
                    return Some(ExpectedFixedByteSource::LoadedBytes { var_id: var.id, size_offset, width: expected_width });
                }
                if self.fixed_byte_local_offsets.contains_key(&var.id) && var_width == expected_width {
                    return Some(ExpectedFixedByteSource::PointerBytes { var_id: var.id, width: expected_width });
                }
                if expected_width <= 8
                    && (fixed_scalar_width(&var.ty, type_static_length(&var.ty)).is_some()
                        || (var_width == expected_width && fixed_byte_width(&var.ty, type_static_length(&var.ty)).is_some()))
                    && expected_width <= var_width
                {
                    return Some(ExpectedFixedByteSource::StackSlot { var_id: var.id, width: expected_width });
                }
                if self.u128_value_offsets.contains_key(&var.id)
                    && !self.fixed_byte_param_size_offsets.contains_key(&var.id)
                    && var_width == expected_width
                {
                    return Some(ExpectedFixedByteSource::PointerBytes { var_id: var.id, width: expected_width });
                }
                if self.aggregate_pointer_sources.contains_key(&var.id) && var_width == expected_width {
                    return Some(ExpectedFixedByteSource::PointerBytes { var_id: var.id, width: expected_width });
                }
                if self.param_vars.contains(&var.id)
                    && var_width == expected_width
                    && let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&var.id).copied()
                {
                    return Some(ExpectedFixedByteSource::ParamBytes { var_id: var.id, size_offset, width: expected_width });
                }
                if let Some(param_id) = self.param_type_hash_sources.get(&var.id).copied()
                    && var_width == expected_width
                    && let Some(size_offset) = self.param_type_hash_size_offsets.get(&param_id).copied()
                {
                    return Some(ExpectedFixedByteSource::LoadedBytes { var_id: var.id, size_offset, width: expected_width });
                }
                None
            }
            _ => None,
        }
    }

    /// Generic fixed-byte comparison: when `emit_fixed_byte_comparison` can't determine
    /// the source of bytes, this method loads pointers from stack slots and performs
    /// a byte-by-byte comparison. Works for Var operands whose stack slots contain
    /// pointers to the fixed-byte data.
    pub(super) fn emit_generic_fixed_byte_comparison(
        &mut self,
        dest: &IrVar,
        op: BinaryOp,
        left: &IrOperand,
        right: &IrOperand,
    ) -> bool {
        let left_width = operand_fixed_byte_width(left);
        let right_width = operand_fixed_byte_width(right);

        // Need at least one Var operand with known width for this to work
        let width = match (left_width, right_width) {
            (Some(w), Some(r)) if w == r => w,
            (Some(w), None) | (None, Some(w)) => w,
            _ => return false,
        };

        if width == 0 {
            return false;
        }

        // We need at least one Var operand
        let left_var = match left {
            IrOperand::Var(v) => Some(v),
            _ => None,
        };
        let right_var = match right {
            IrOperand::Var(v) => Some(v),
            _ => None,
        };
        if left_var.is_none() && right_var.is_none() {
            return false;
        }

        self.emit(format!("# cellscript abi: generic fixed-byte {:?} comparison size={}", op, width));

        // Load left pointer to t4
        if let Some(v) = left_var {
            self.emit_stack_load("t4", v.id * 8);
        } else {
            // Left is a constant – store it to scratch buffer and point t4 there
            let size_offset = self.runtime_scratch_size_offset();
            let buffer_offset = self.runtime_scratch_buffer_offset();
            self.emit_store_fixed_byte_const_to_scratch(left, size_offset, buffer_offset, width);
            self.emit_sp_addi("t4", buffer_offset);
        }

        // Load right pointer to t5
        if let Some(v) = right_var {
            self.emit_stack_load("t5", v.id * 8);
        } else {
            let size_offset = self.runtime_scratch2_size_offset();
            let buffer_offset = self.runtime_scratch2_buffer_offset();
            self.emit_store_fixed_byte_const_to_scratch(right, size_offset, buffer_offset, width);
            self.emit_sp_addi("t5", buffer_offset);
        }

        let mismatch_label = self.fresh_label("gen_fb_mismatch");
        let done_label = self.fresh_label("gen_fb_done");
        for byte_index in 0..width {
            self.emit(format!("lbu t0, {}(t4)", byte_index));
            self.emit(format!("lbu t1, {}(t5)", byte_index));
            self.emit("sub t2, t0, t1");
            self.emit(format!("bnez t2, {}", mismatch_label));
        }
        let equal_value = if matches!(op, BinaryOp::Eq) { 1 } else { 0 };
        let mismatch_value = if matches!(op, BinaryOp::Eq) { 0 } else { 1 };
        self.emit(format!("li t3, {}", equal_value));
        self.emit(format!("j {}", done_label));
        self.emit_label(&mismatch_label);
        self.emit(format!("li t3, {}", mismatch_value));
        self.emit_label(&done_label);
        self.emit_stack_store("t3", dest.id * 8);
        true
    }

    /// Store fixed-byte constant value to scratch buffer area.
    pub(super) fn emit_store_fixed_byte_const_to_scratch(
        &mut self,
        operand: &IrOperand,
        size_offset: usize,
        buffer_offset: usize,
        width: usize,
    ) {
        match operand {
            IrOperand::Const(IrConst::Address(bytes)) | IrOperand::Const(IrConst::Hash(bytes)) => {
                self.emit(format!("# cellscript abi: store fixed-byte const size={}", width));
                self.emit(format!("li t0, {}", width));
                self.emit_schema_size_store("t0", size_offset);
                for (i, byte) in bytes.iter().enumerate() {
                    self.emit(format!("li t0, {}", byte));
                    if buffer_offset + i <= 2047 {
                        self.emit_stack_store_byte("t0", buffer_offset + i);
                    } else {
                        self.emit(format!("li t6, {}", buffer_offset + i));
                        self.emit("add t6, sp, t6");
                        self.emit("sb t0, 0(t6)");
                    }
                }
            }
            IrOperand::Const(IrConst::U128(value)) => {
                self.emit(format!("# cellscript abi: store u128 const size={}", width));
                self.emit(format!("li t0, {}", width));
                self.emit_schema_size_store("t0", size_offset);
                for (i, byte) in value.to_le_bytes().iter().enumerate() {
                    self.emit(format!("li t0, {}", byte));
                    self.emit_stack_store_byte("t0", buffer_offset + i);
                }
            }
            IrOperand::Const(IrConst::Array(values)) => {
                self.emit(format!("# cellscript abi: store fixed-byte array const size={}", width));
                self.emit(format!("li t0, {}", width));
                self.emit_schema_size_store("t0", size_offset);
                for (i, value) in values.iter().enumerate() {
                    if let IrConst::U8(byte) = value {
                        self.emit(format!("li t0, {}", byte));
                        if buffer_offset + i <= 2047 {
                            self.emit_stack_store_byte("t0", buffer_offset + i);
                        } else {
                            self.emit(format!("li t6, {}", buffer_offset + i));
                            self.emit("add t6, sp, t6");
                            self.emit("sb t0, 0(t6)");
                        }
                    }
                }
            }
            _ => {
                self.emit("# cellscript abi: cannot store unknown const type to scratch".to_string());
            }
        }
    }

    pub(super) fn operand_is_u128(&self, operand: &IrOperand) -> bool {
        match operand {
            IrOperand::Const(IrConst::U128(_)) => true,
            IrOperand::Var(var) => var.ty == IrType::U128,
            _ => false,
        }
    }

    pub(super) fn emit_u128_add_sub_with_u64(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> bool {
        if dest.ty != IrType::U128 || !matches!(op, BinaryOp::Add | BinaryOp::Sub) {
            return false;
        }
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return false;
        };

        let (wide_operand, delta_operand) = match op {
            BinaryOp::Add if self.operand_is_u128(left) => (left, right),
            BinaryOp::Add if self.operand_is_u128(right) => (right, left),
            BinaryOp::Sub if self.operand_is_u128(left) => (left, right),
            _ => return false,
        };
        if self.expected_fixed_byte_source(wide_operand, 16).is_none() {
            return false;
        }
        let Some(delta) = self.prelude_u64_operand_source(delta_operand) else {
            return false;
        };

        match op {
            BinaryOp::Add => self.emit("# cellscript abi: u128 add with carry"),
            BinaryOp::Sub => self.emit("# cellscript abi: u128 sub with borrow"),
            _ => unreachable!("guarded u128 binary op"),
        }
        if !self.emit_u128_operand_limbs("t0", "t3", "t2", "t4", wide_operand, "u128 arithmetic wide operand") {
            return true;
        }
        let wide_low_offset = self.runtime_expr_temp_offset(0);
        let wide_high_offset = self.runtime_expr_temp_offset(1);
        self.emit_stack_store("t0", wide_low_offset);
        self.emit_stack_store("t3", wide_high_offset);
        self.emit_prelude_u64_operand_source_to_t1(&delta);
        self.emit_stack_load("t0", wide_low_offset);
        self.emit_stack_load("t3", wide_high_offset);
        let overflow_label = self.fresh_label("u128_arithmetic_overflow");
        let done_label = self.fresh_label("u128_arithmetic_done");
        match op {
            BinaryOp::Add => {
                self.emit("add t5, t0, t1");
                self.emit("sltu t2, t5, t0");
                self.emit("add t6, t3, t2");
                self.emit("sltu a6, t6, t3");
                self.emit(format!("bnez a6, {}", overflow_label));
            }
            BinaryOp::Sub => {
                self.emit("sub t5, t0, t1");
                self.emit("sltu t2, t0, t1");
                self.emit(format!("bltu t3, t2, {}", overflow_label));
                self.emit("sub t6, t3, t2");
            }
            _ => unreachable!("guarded u128 binary op"),
        }
        self.emit_stack_store("t5", dest_offset);
        self.emit_stack_store("t6", dest_offset + 8);
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        self.emit(format!("j {}", done_label));
        self.emit_label(&overflow_label);
        self.emit_fail(CellScriptRuntimeError::AggregateAmountMismatch);
        self.emit_label(&done_label);
        true
    }

    pub(super) fn emit_expected_operand_to_t1(&mut self, operand: &IrOperand) {
        match operand {
            IrOperand::Const(IrConst::Bool(b)) => self.emit(format!("li t1, {}", if *b { 1 } else { 0 })),
            IrOperand::Const(IrConst::U8(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U16(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U32(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U64(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Var(var) => {
                if let Some(source) = self.schema_field_value_sources.get(&var.id).cloned() {
                    self.emit_schema_field_source_to_t1(&source);
                } else if let Some(source) = self.prelude_u64_value_sources.get(&var.id).cloned() {
                    self.emit_prelude_u64_value_source_to_t1(&source);
                } else if matches!(var.ty, IrType::Bool | IrType::U8 | IrType::U16 | IrType::U32 | IrType::I32 | IrType::U64) {
                    self.emit_stack_load("t1", var.id * 8);
                } else if let Some(value) = self.prelude_scalar_immediates.get(&var.id).copied() {
                    self.emit(format!("li t1, {}", value));
                } else {
                    self.emit_stack_load("t1", var.id * 8);
                }
            }
            _ => self.emit("li t1, 0"),
        }
    }

    pub(super) fn emit_prelude_u64_value_source_to_t1(&mut self, source: &PreludeU64ValueSource) {
        self.emit_prelude_u64_value_source_to_t1_at_depth(source, 0);
    }

    pub(super) fn emit_prelude_u64_value_source_to_t1_at_depth(&mut self, source: &PreludeU64ValueSource, _depth: usize) {
        match source {
            PreludeU64ValueSource::Const(n) => self.emit(format!("li t1, {}", n)),
            PreludeU64ValueSource::ParamVar(var_id) => self.emit_stack_load("t1", var_id * 8),
            PreludeU64ValueSource::StackVar(var_id) => self.emit_stack_load("t1", var_id * 8),
            PreludeU64ValueSource::Field(source) => self.emit_schema_field_source_to_t1(source),
            PreludeU64ValueSource::Binary { op, left, right } => {
                self.emit(format!("# cellscript abi: expected expression u64 {:?}", op));
                let Some(temp_offset) = self.checked_runtime_expr_temp_offset(_depth) else {
                    self.emit("# cellscript abi: fail closed because expression verifier temp stack is exhausted");
                    self.emit_fail(CellScriptRuntimeError::DataPreservationMismatch);
                    return;
                };
                self.emit_prelude_u64_value_source_to_t1_at_depth(left, _depth + 1);
                self.emit_stack_store("t1", temp_offset);
                self.emit_prelude_u64_operand_source_to_t1_at_depth(right, _depth + 1);
                self.emit_stack_load("t3", temp_offset);
                match op {
                    BinaryOp::Add => self.emit("add t1, t3, t1"),
                    BinaryOp::Sub => self.emit("sub t1, t3, t1"),
                    BinaryOp::Mul => self.emit("mul t1, t3, t1"),
                    BinaryOp::Div => {
                        let divisor_ok = self.fresh_label("prelude_divisor_nonzero");
                        self.emit(format!("bnez t1, {}", divisor_ok));
                        self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
                        self.emit_label(&divisor_ok);
                        self.emit("divu t1, t3, t1");
                    }
                    _ => unreachable!("prelude u64 binary source only supports add/sub/mul/div"),
                }
            }
            PreludeU64ValueSource::Min { left, right } => {
                self.emit("# cellscript abi: expected expression u64 min");
                let Some(temp_offset) = self.checked_runtime_expr_temp_offset(_depth) else {
                    self.emit("# cellscript abi: fail closed because expression verifier temp stack is exhausted");
                    self.emit_fail(CellScriptRuntimeError::DataPreservationMismatch);
                    return;
                };
                self.emit_prelude_u64_value_source_to_t1_at_depth(left, _depth + 1);
                self.emit_stack_store("t1", temp_offset);
                self.emit_prelude_u64_operand_source_to_t1_at_depth(right, _depth + 1);
                self.emit_stack_load("t3", temp_offset);
                self.emit("slt t2, t3, t1");
                let right_ok_label = self.fresh_label("prelude_min_right_ok");
                self.emit(format!("beqz t2, {}", right_ok_label));
                self.emit("add t1, t3, zero");
                self.emit_label(&right_ok_label);
            }
        }
    }

    pub(super) fn emit_prelude_u64_operand_source_to_t1(&mut self, source: &PreludeU64OperandSource) {
        self.emit_prelude_u64_operand_source_to_t1_at_depth(source, 0);
    }

    pub(super) fn emit_prelude_u64_operand_source_to_t1_at_depth(&mut self, source: &PreludeU64OperandSource, _depth: usize) {
        match source {
            PreludeU64OperandSource::Const(n) => self.emit(format!("li t1, {}", n)),
            PreludeU64OperandSource::ParamVar(var_id) => self.emit_stack_load("t1", var_id * 8),
            PreludeU64OperandSource::StackVar(var_id) => self.emit_stack_load("t1", var_id * 8),
            PreludeU64OperandSource::Field(source) => self.emit_schema_field_source_to_t1(source),
            PreludeU64OperandSource::Expr(source) => self.emit_prelude_u64_value_source_to_t1_at_depth(source, _depth),
        }
    }

    pub(super) fn emit_schema_field_source_to_t1(&mut self, source: &SchemaFieldValueSource) {
        let context = format!("{}.{}", source.type_name, source.field);
        let Some(width) = layout_fixed_scalar_width(&source.layout) else {
            self.emit("li t1, 0");
            return;
        };
        if !self.type_fixed_sizes.contains_key(&source.type_name) {
            if self.emit_schema_field_source_pointer_to("t4", source, width) {
                self.emit(format!("# cellscript abi: expected table field {} index={} size={}", context, source.layout.index, width));
                self.emit_unaligned_scalar_load("t4", "t1", "t2", 0, width);
            } else {
                self.emit("li t1, 0");
            }
            return;
        }
        if let Some(size_offset) = self.schema_pointer_size_offsets.get(&source.obj_var_id).copied() {
            if let Some(expected_size) = self.type_fixed_sizes.get(&source.type_name).copied() {
                self.emit_loaded_schema_exact_size_check(size_offset, expected_size, &source.type_name);
            }
            self.emit_loaded_schema_bounds_check(size_offset, source.layout.offset + width, &context);
        }
        self.emit(format!("# cellscript abi: expected field {} offset={} size={}", context, source.layout.offset, width));
        self.emit_stack_load("t4", source.obj_var_id * 8);
        self.emit_schema_scalar_load(source.obj_var_id, "t4", "t1", "t2", source.layout.offset, width);
    }

    pub(super) fn emit_prepare_schema_field_source(&mut self, source: &SchemaFieldValueSource, width: usize) {
        let context = format!("{}.{}", source.type_name, source.field);
        let Some(size_offset) = self.schema_pointer_size_offsets.get(&source.obj_var_id).copied() else {
            return;
        };
        if let Some(expected_size) = self.type_fixed_sizes.get(&source.type_name).copied() {
            self.emit_loaded_schema_exact_size_check(size_offset, expected_size, &source.type_name);
            self.emit_loaded_schema_bounds_check(size_offset, source.layout.offset + width, &context);
        } else {
            self.emit_stack_load("t4", source.obj_var_id * 8);
            self.emit_molecule_table_field_bounds_to_t5("t4", size_offset, source.layout.index, width, &context);
        }
    }

    pub(super) fn emit_schema_field_source_pointer_to(
        &mut self,
        dest_reg: &str,
        source: &SchemaFieldValueSource,
        width: usize,
    ) -> bool {
        let context = format!("{}.{}", source.type_name, source.field);
        if let Some(size_offset) = self.schema_pointer_size_offsets.get(&source.obj_var_id).copied() {
            if let Some(expected_size) = self.type_fixed_sizes.get(&source.type_name).copied() {
                self.emit_loaded_schema_exact_size_check(size_offset, expected_size, &source.type_name);
                self.emit_loaded_schema_bounds_check(size_offset, source.layout.offset + width, &context);
                self.emit_stack_load(dest_reg, source.obj_var_id * 8);
                if source.layout.offset != 0 {
                    self.emit_large_addi(dest_reg, dest_reg, source.layout.offset as i64);
                }
            } else {
                self.emit_stack_load("t4", source.obj_var_id * 8);
                self.emit_molecule_table_field_bounds_to_t5("t4", size_offset, source.layout.index, width, &context);
                self.emit(format!("add {}, t4, t5", dest_reg));
            }
            true
        } else if self.aggregate_pointer_sources.contains_key(&source.obj_var_id)
            || self.type_fixed_sizes.contains_key(&source.type_name)
        {
            self.emit_stack_load(dest_reg, source.obj_var_id * 8);
            if source.layout.offset != 0 {
                self.emit_large_addi(dest_reg, dest_reg, source.layout.offset as i64);
            }
            true
        } else {
            false
        }
    }
}
