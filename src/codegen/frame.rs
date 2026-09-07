use super::*;

impl CodeGenerator {
    pub(super) fn emit_prologue(&mut self) {
        self.emit_large_addi("sp", "sp", -(self.frame_size as i64));
        self.emit_stack_store("ra", self.frame_size - 8);
        self.emit_stack_store("fp", self.frame_size - 16);
        self.emit_sp_addi("fp", self.frame_size);
        if let Some(cache_offset) = self.exact_read_cache_offset {
            self.emit_stack_store("zero", cache_offset);
            self.emit_stack_store("zero", cache_offset + 8);
            self.emit_stack_store("s11", cache_offset + 16);
            if self.module_uses_exact_read_hot_cache {
                for (index, register) in ["s10", "s9", "s8", "s7", "s6", "s5"].iter().enumerate() {
                    self.emit_stack_store(register, cache_offset + 24 + index * 8);
                }
            }
            let header_size = self.exact_read_cache_header_size();
            for way in 0..RUNTIME_EXACT_READ_CACHE_WAYS {
                self.emit_stack_store("zero", cache_offset + header_size + way * RUNTIME_EXACT_READ_CACHE_ENTRY_SIZE + 24);
            }
            self.emit_sp_addi("s11", cache_offset);
            if self.module_uses_exact_read_hot_cache {
                self.emit("li s10, 0");
            }
        }
    }

    pub(super) fn emit_epilogue(&mut self) {
        if let Some(function) = &self.current_function {
            self.emit(format!("j .L{}_epilogue", function));
            return;
        }
        self.emit_epilogue_body();
    }

    pub(super) fn emit_fail(&mut self, error: CellScriptRuntimeError) {
        if let Some(function) = self.current_function.clone() {
            self.fail_handler_codes.insert(error);
            self.emit(format!("j .L{}_fail_{}", function, error.code()));
            return;
        }
        self.emit_process_failure(error);
    }

    /// Terminate the VM process even inside a value-returning helper. Returning
    /// an error in a0 would let a caller mistake it for a scalar or byte pointer.
    /// A fresh label makes the exact error constant independently addressable
    /// in machine evidence. No frame/RA or caller-live registers must survive.
    pub(super) fn emit_process_failure(&mut self, error: CellScriptRuntimeError) {
        let failure = self.fresh_label(&format!("verifier_failure_{}", error.code()));
        self.emit_label(&failure);
        self.emit_runtime_error_comment(error);
        self.emit(format!("li a0, {}", error.code()));
        self.emit_process_failure_status();
    }

    /// a0 holds a nonzero verifier status already checked by the caller. This
    /// does not apply to ordinary scalar returns or deliberate raw status APIs.
    pub(super) fn emit_process_failure_status(&mut self) {
        self.needs_process_failure_helper = true;
        self.emit("j __cellscript_abort");
    }

    pub(super) fn emit_process_failure_helper(&mut self) {
        if !self.needs_process_failure_helper {
            return;
        }
        self.entry_frame_sizes.insert("__cellscript_abort".to_string(), 0);
        self.emit_global("__cellscript_abort");
        self.emit_label("__cellscript_abort");
        self.emit("# cellscript verifier failure: terminate current VM process; a0 is the nonzero error");
        self.emit(format!("li a7, {}", ckb_abi::syscall::EXIT));
        self.emit("ecall");
        // The VM EXIT ABI never returns. Retain a terminal fallback even under
        // a nonstandard syscall runner; never manufacture a normal value.
        self.emit("j __cellscript_abort");
    }

    pub(super) fn emit_shared_epilogue(&mut self) {
        let Some(function) = self.current_function.clone() else {
            return;
        };
        let fail_codes = self.fail_handler_codes.iter().copied().collect::<Vec<_>>();
        for error in fail_codes {
            self.emit_label(&format!(".L{}_fail_{}", function, error.code()));
            self.emit_process_failure(error);
        }
        self.emit_label(&format!(".L{}_epilogue", function));
        self.emit_epilogue_body();
    }

    pub(super) fn emit_runtime_error_comment(&mut self, error: CellScriptRuntimeError) {
        self.emit(format!("# cellscript runtime error {} {}", error.code(), error.name()));
    }

    pub(super) fn emit_epilogue_body(&mut self) {
        if let Some(cache_offset) = self.exact_read_cache_offset {
            if self.module_uses_exact_read_hot_cache {
                for (index, register) in ["s10", "s9", "s8", "s7", "s6", "s5"].iter().enumerate().rev() {
                    self.emit_stack_load(register, cache_offset + 24 + index * 8);
                }
            }
            self.emit_stack_load("s11", cache_offset + 16);
        }
        self.emit_stack_load("ra", self.frame_size - 8);
        self.emit_stack_load("fp", self.frame_size - 16);
        self.emit_large_addi("sp", "sp", self.frame_size as i64);
        self.emit("ret");
    }

    /// Emit `addi rd, rs1, imm` handling immediates that don't fit in 12 bits.
    pub(super) fn emit_large_addi(&mut self, rd: &str, rs1: &str, imm: i64) {
        if (-2048..=2047).contains(&imm) {
            self.emit(format!("addi {}, {}, {}", rd, rs1, imm));
        } else {
            let scratch = scratch_register_avoiding(&[rs1]);
            self.emit(format!("li {}, {}", scratch, imm));
            self.emit(format!("add {}, {}, {}", rd, rs1, scratch));
        }
    }

    pub(super) fn emit_memory_load_with_avoid(&mut self, opcode: &str, dst: &str, base: &str, offset: usize, avoid: &[&str]) {
        let offset = i64::try_from(offset).expect("memory offset should fit in i64");
        if small_signed_immediate(offset) {
            self.emit(format!("{} {}, {}({})", opcode, dst, offset, base));
        } else {
            let mut registers = Vec::with_capacity(2 + avoid.len());
            registers.push(dst);
            registers.push(base);
            registers.extend_from_slice(avoid);
            let scratch = scratch_register_avoiding(&registers);
            self.emit(format!("li {}, {}", scratch, offset));
            self.emit(format!("add {}, {}, {}", scratch, base, scratch));
            self.emit(format!("{} {}, 0({})", opcode, dst, scratch));
        }
    }

    pub(super) fn emit_memory_store_with_avoid(&mut self, opcode: &str, src: &str, base: &str, offset: usize, avoid: &[&str]) {
        let offset = i64::try_from(offset).expect("memory offset should fit in i64");
        if small_signed_immediate(offset) {
            self.emit(format!("{} {}, {}({})", opcode, src, offset, base));
        } else {
            let mut registers = Vec::with_capacity(2 + avoid.len());
            registers.push(src);
            registers.push(base);
            registers.extend_from_slice(avoid);
            let scratch = scratch_register_avoiding(&registers);
            self.emit(format!("li {}, {}", scratch, offset));
            self.emit(format!("add {}, {}, {}", scratch, base, scratch));
            self.emit(format!("{} {}, 0({})", opcode, src, scratch));
        }
    }

    /// Emit `ld rd, offset(sp)` through the centralized stack-offset gate.
    pub(super) fn emit_stack_load(&mut self, rd: &str, offset: usize) {
        self.emit_stack_access_with_avoid("ld", rd, offset, &[]);
    }

    /// Emit `ld rd, offset(sp)` without clobbering explicitly live registers.
    pub(super) fn emit_stack_load_with_avoid(&mut self, rd: &str, offset: usize, avoid: &[&str]) {
        self.emit_stack_access_with_avoid("ld", rd, offset, avoid);
    }

    /// Emit `lbu rd, offset(sp)` through the centralized stack-offset gate.
    pub(super) fn emit_stack_load_byte(&mut self, rd: &str, offset: usize) {
        self.emit_stack_access("lbu", rd, offset);
    }

    /// Emit `sd rs2, offset(sp)` through the centralized stack-offset gate.
    pub(super) fn emit_stack_store(&mut self, rs2: &str, offset: usize) {
        self.emit_stack_access_with_avoid("sd", rs2, offset, &[]);
    }

    /// Emit `sd rs2, offset(sp)` without clobbering explicitly live registers.
    pub(super) fn emit_stack_store_with_avoid(&mut self, rs2: &str, offset: usize, avoid: &[&str]) {
        self.emit_stack_access_with_avoid("sd", rs2, offset, avoid);
    }

    /// Emit `sb rs2, offset(sp)` through the centralized stack-offset gate.
    pub(super) fn emit_stack_store_byte(&mut self, rs2: &str, offset: usize) {
        self.emit_stack_access("sb", rs2, offset);
    }

    pub(super) fn emit_stack_access(&mut self, opcode: &str, register: &str, offset: usize) {
        self.emit_stack_access_with_avoid(opcode, register, offset, &[]);
    }

    pub(super) fn emit_stack_access_with_avoid(&mut self, opcode: &str, register: &str, offset: usize, avoid: &[&str]) {
        let offset = i64::try_from(offset).expect("stack offset should fit in i64");
        if small_signed_immediate(offset) {
            self.emit(format!("{} {}, {}(sp)", opcode, register, offset));
        } else {
            let mut live_registers = Vec::with_capacity(1 + avoid.len());
            live_registers.push(register);
            live_registers.extend_from_slice(avoid);
            let scratch = scratch_register_avoiding(&live_registers);
            self.emit(format!("li {}, {}", scratch, offset));
            self.emit(format!("add {}, sp, {}", scratch, scratch));
            self.emit(format!("{} {}, 0({})", opcode, register, scratch));
        }
    }

    /// Emit `addi rd, sp, offset` handling offsets that don't fit in 12 bits.
    pub(super) fn emit_sp_addi(&mut self, rd: &str, offset: usize) {
        if offset <= 2047 {
            self.emit(format!("addi {}, sp, {}", rd, offset));
        } else if rd == "sp" {
            self.emit_large_addi("sp", "sp", offset as i64);
        } else {
            self.emit(format!("li {}, {}", rd, offset));
            self.emit(format!("add {}, sp, {}", rd, rd));
        }
    }

    pub(super) fn prepare_function_layout(&mut self, body: &IrBody, params: &[IrParam]) {
        self.cell_bindings.clone_from(&body.cell_bindings);
        self.cell_locations_by_local = body
            .cell_bindings
            .iter()
            .filter_map(|binding| binding.local_id.map(|id| (id, (cell_source_value(binding.source), binding.ordinal))))
            .collect();
        let mut max_var_id = None;
        let mut fixed_byte_locals = HashMap::<usize, usize>::new();
        let mut named_vars = BTreeSet::<String>::new();
        for param in params {
            self.record_var(&param.binding, &mut max_var_id);
        }
        for block in &body.blocks {
            for instruction in &block.instructions {
                self.record_instruction_var(instruction, &mut max_var_id);
                self.record_instruction_fixed_byte_local(instruction, &mut fixed_byte_locals);
                if let IrInstruction::StoreVar { name, .. } = instruction {
                    named_vars.insert(name.clone());
                }
            }
            self.record_terminator_var(&block.terminator, &mut max_var_id);
        }

        let locals_size = max_var_id.map(|id| (id + 1) * 8).unwrap_or(0);
        self.fixed_byte_local_offsets.clear();
        self.named_var_offsets.clear();
        self.cell_buffer_offsets.clear();
        self.cell_buffer_size_offsets.clear();
        self.exact_read_cache_offset = None;
        self.dynamic_value_size_offsets.clear();
        self.empty_molecule_vector_vars.clear();
        self.constructed_byte_vectors.clear();
        self.constructed_byte_vector_roots.clear();
        self.verified_collection_construction_vectors.clear();
        self.output_type_hash_sources.clear();
        self.consume_order.clear();
        self.consume_indices.clear();
        self.consume_type_names.clear();
        self.consume_binding_ids.clear();
        self.read_ref_indices.clear();
        self.read_ref_param_ids.clear();
        self.read_ref_param_input_indices.clear();
        self.read_ref_param_dep_indices.clear();
        self.output_param_ids.clear();
        self.mutate_param_ids.clear();
        self.schema_pointer_size_offsets.clear();
        self.dominant_schema_exact_sizes.clear();
        self.block_schema_exact_sizes.clear();
        self.block_schema_min_sizes.clear();
        self.local_schema_value_widths.clear();
        self.branch_only_vars = body
            .blocks
            .iter()
            .filter_map(|block| match (block.instructions.last(), &block.terminator) {
                (Some(IrInstruction::Binary { dest, .. }), IrTerminator::Branch { cond: IrOperand::Var(cond), .. })
                    if dest.id == cond.id && body_var_use_count(body, dest.id) == 1 =>
                {
                    Some(dest.id)
                }
                _ => None,
            })
            .collect();
        self.fixed_byte_param_size_offsets.clear();
        self.param_type_hash_pointer_offsets.clear();
        self.param_type_hash_size_offsets.clear();
        self.param_type_hash_sources.clear();
        self.u128_value_offsets.clear();
        self.collection_region_start = 0;
        self.next_collection_slot = 0;

        for instruction in body.blocks.iter().flat_map(|block| &block.instructions) {
            if let IrInstruction::Tuple { dest, .. } = instruction
                && let IrType::Named(name) = &dest.ty
                && !self.cell_type_names.contains(name)
                && let Some(width) = self.type_fixed_sizes.get(name).copied()
            {
                self.local_schema_value_widths.insert(dest.id, width);
            }
        }

        let schema_param_ids = params
            .iter()
            .filter(|param| named_type_name(&param.ty).is_some_and(|name| !name.contains("__mono__")))
            .map(|param| param.binding.id)
            .collect::<BTreeSet<_>>();
        let mut param_type_hash_ids = BTreeSet::new();
        for block in &body.blocks {
            for instruction in &block.instructions {
                if let IrInstruction::TypeHash { dest, operand: IrOperand::Var(var) } = instruction
                    && schema_param_ids.contains(&var.id)
                {
                    param_type_hash_ids.insert(var.id);
                    self.param_type_hash_sources.insert(dest.id, var.id);
                }
            }
        }

        let mut next_cell_slot = locals_size;
        let mut fixed_byte_locals = fixed_byte_locals.into_iter().collect::<Vec<_>>();
        fixed_byte_locals.sort_unstable_by_key(|(var_id, _)| *var_id);
        for (var_id, width) in fixed_byte_locals {
            next_cell_slot = align_up(next_cell_slot, 8);
            self.fixed_byte_local_offsets.insert(var_id, next_cell_slot);
            next_cell_slot += align_up(width, 8);
        }
        for name in named_vars {
            next_cell_slot = align_up(next_cell_slot, 8);
            self.named_var_offsets.insert(name, next_cell_slot);
            next_cell_slot += 8;
        }
        for param in params {
            if param.source == ParamSource::Output {
                self.output_param_ids.insert(param.name.clone(), param.binding.id);
                self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
                self.cell_buffer_size_offsets.insert(param.binding.id, next_cell_slot);
                self.cell_buffer_offsets.insert(param.binding.id, next_cell_slot + 8);
                next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                continue;
            }
            if is_ckb_temporal_scalar_ir_type(&param.ty) || self.fieldless_enum_width(&param.ty).is_some() {
                continue;
            } else if named_type_name(&param.ty).is_some_and(|name| self.cell_type_names.contains(name)) {
                self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
                next_cell_slot += 8;
            } else if self.generic_value_type_width(&param.ty).is_some()
                || fixed_byte_pointer_param_width(&param.ty).is_some()
                || fixed_aggregate_pointer_param_width(&param.ty).is_some()
            {
                self.fixed_byte_param_size_offsets.insert(param.binding.id, next_cell_slot);
                next_cell_slot += 8;
            } else if named_type_name(&param.ty).is_some() {
                self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
                next_cell_slot += 8;
            }
        }
        for param in params {
            if param_type_hash_ids.contains(&param.binding.id) {
                self.param_type_hash_pointer_offsets.insert(param.binding.id, next_cell_slot);
                next_cell_slot += 8;
                self.param_type_hash_size_offsets.insert(param.binding.id, next_cell_slot);
                next_cell_slot += 8;
            }
        }

        if self.bind_readonly_schema_params {
            let consumed_param_names = body.consume_set.iter().map(|pattern| pattern.binding.as_str()).collect::<BTreeSet<_>>();
            let mutate_param_names = body.mutate_set.iter().map(|pattern| pattern.binding.as_str()).collect::<BTreeSet<_>>();
            for param in params {
                if matches!(param.source, ParamSource::Output | ParamSource::LockArgs) {
                    continue;
                }
                if !self.param_is_runtime_bound(param) {
                    continue;
                }
                if mutate_param_names.contains(param.name.as_str()) || consumed_param_names.contains(param.name.as_str()) {
                    continue;
                }
                self.read_ref_param_ids.insert(param.name.clone(), param.binding.id);
                if let Some(binding) = body.cell_binding_for_local(param.binding.id) {
                    match binding.source {
                        IrCellSource::CellDep => {
                            self.read_ref_param_dep_indices.insert(param.binding.id, binding.ordinal);
                        }
                        IrCellSource::Input | IrCellSource::GroupInput => {
                            self.read_ref_param_input_indices.insert(param.binding.id, binding.ordinal);
                        }
                        IrCellSource::Output | IrCellSource::GroupOutput => {}
                    }
                }
                self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
                self.cell_buffer_size_offsets.insert(param.binding.id, next_cell_slot);
                self.cell_buffer_offsets.insert(param.binding.id, next_cell_slot + 8);
                next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
            }
        }

        for pattern in &body.mutate_set {
            let Some(param) = params.iter().find(|param| param.name == pattern.binding) else {
                continue;
            };
            self.mutate_param_ids.insert(pattern.binding.clone(), param.binding.id);
            self.consume_type_names.insert(param.binding.id, pattern.ty.clone());
            self.consume_binding_ids.insert(pattern.binding.clone(), param.binding.id);
            if let Some(binding) = body.cell_binding(IrCellBindingRole::Input, &pattern.binding) {
                self.consume_indices.insert(param.binding.id, binding.ordinal);
            }
            self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
            self.cell_buffer_size_offsets.insert(param.binding.id, next_cell_slot);
            self.cell_buffer_offsets.insert(param.binding.id, next_cell_slot + 8);
            next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
        }

        let consume_pattern_indices = body
            .cell_bindings
            .iter()
            .filter(|binding| binding.role == IrCellBindingRole::Input)
            .map(|binding| (binding.binding.as_str(), binding.ordinal))
            .collect::<HashMap<_, _>>();
        for pattern in &body.consume_set {
            let Some(param) = params.iter().find(|param| param.name == pattern.binding) else {
                continue;
            };
            if self.consume_binding_ids.contains_key(&pattern.binding) {
                continue;
            }
            if let Some(type_name) = named_type_name(&param.ty) {
                self.consume_type_names.insert(param.binding.id, type_name.to_string());
            }
            self.consume_binding_ids.insert(pattern.binding.clone(), param.binding.id);
            self.schema_pointer_size_offsets.insert(param.binding.id, next_cell_slot);
            self.cell_buffer_size_offsets.insert(param.binding.id, next_cell_slot);
            self.cell_buffer_offsets.insert(param.binding.id, next_cell_slot + 8);
            self.consume_order.push(param.binding.id);
            self.consume_indices.insert(param.binding.id, consume_pattern_indices.get(pattern.binding.as_str()).copied().unwrap_or(0));
            next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
        }
        for block in &body.blocks {
            for instruction in &block.instructions {
                if let Some(var) = consumed_operand_var(instruction) {
                    if self.consume_binding_ids.contains_key(&var.name) {
                        continue;
                    }
                    if let Some(type_name) = named_type_name(&var.ty) {
                        self.consume_type_names.insert(var.id, type_name.to_string());
                    }
                    self.consume_binding_ids.insert(var.name.clone(), var.id);
                    self.schema_pointer_size_offsets.insert(var.id, next_cell_slot);
                    self.cell_buffer_size_offsets.insert(var.id, next_cell_slot);
                    self.cell_buffer_offsets.insert(var.id, next_cell_slot + 8);
                    self.consume_order.push(var.id);
                    self.consume_indices.insert(
                        var.id,
                        consume_pattern_indices.get(var.name.as_str()).copied().unwrap_or(self.consume_order.len() - 1),
                    );
                    next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                }
            }
        }

        for block in &body.blocks {
            for instruction in &block.instructions {
                if let IrInstruction::ReadRef { dest, .. } = instruction {
                    self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                    self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                    if let Some(binding) = body.cell_binding_for_local(dest.id)
                        && binding.source == IrCellSource::CellDep
                    {
                        self.read_ref_indices.insert(dest.id, binding.ordinal);
                    }
                    next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                }
            }
        }

        for block in &body.blocks {
            for instruction in &block.instructions {
                let IrInstruction::BoundedCellLoad { dest, .. } = instruction else {
                    continue;
                };
                if self.cell_buffer_offsets.contains_key(&dest.id) {
                    continue;
                }
                self.schema_pointer_size_offsets.insert(dest.id, next_cell_slot);
                self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
            }
        }

        for block in &body.blocks {
            for instruction in &block.instructions {
                let IrInstruction::BoundedPlanLoad { dest, .. } = instruction else {
                    continue;
                };
                if self.schema_pointer_size_offsets.contains_key(&dest.id) {
                    continue;
                }
                self.schema_pointer_size_offsets.insert(dest.id, next_cell_slot);
                next_cell_slot += 8;
            }
        }

        let mut create_dest_outputs = HashMap::new();
        for block in &body.blocks {
            for instruction in &block.instructions {
                match instruction {
                    IrInstruction::FieldAccess { dest, obj: IrOperand::Var(obj), field } => {
                        if named_type_name(&dest.ty).is_some()
                            && named_type_name(&obj.ty)
                                .and_then(|type_name| self.type_layouts.get(type_name))
                                .and_then(|fields| fields.get(field))
                                .is_some_and(|layout| {
                                    layout_fixed_byte_width(layout).is_none()
                                        && molecule_vector_element_fixed_width(
                                            &layout.ty,
                                            &self.type_fixed_sizes,
                                            &self.enum_fixed_sizes,
                                        )
                                        .is_some()
                                })
                        {
                            self.dynamic_value_size_offsets.insert(dest.id, next_cell_slot);
                            next_cell_slot += 8;
                        }
                    }
                    IrInstruction::Create { dest, pattern } => {
                        if let Some(binding) = body
                            .cell_binding_for_local(dest.id)
                            .or_else(|| body.cell_binding(IrCellBindingRole::Output, &pattern.binding))
                        {
                            let output_index = binding.ordinal;
                            self.cell_locations_by_local.insert(dest.id, (cell_source_value(binding.source), output_index));
                            create_dest_outputs.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::CreateUnique { dest, pattern, .. } | IrInstruction::ReplaceUnique { dest, pattern, .. } => {
                        if let Some(binding) = body
                            .cell_binding_for_local(dest.id)
                            .or_else(|| body.cell_binding(IrCellBindingRole::Output, &pattern.binding))
                        {
                            let output_index = binding.ordinal;
                            self.cell_locations_by_local.insert(dest.id, (cell_source_value(binding.source), output_index));
                            create_dest_outputs.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::Transfer { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "transfer", dest) {
                            create_dest_outputs.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::Claim { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "claim", dest) {
                            create_dest_outputs.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::Settle { dest, .. } => {
                        if let Some(output_index) = Self::create_output_index_for_dest(body, "settle", dest) {
                            create_dest_outputs.insert(dest.id, output_index);
                        }
                    }
                    IrInstruction::TypeHash { dest, operand: IrOperand::Var(var) } => {
                        if create_dest_outputs.contains_key(&var.id) {
                            if let Some(location) = self.cell_locations_by_local.get(&var.id).copied() {
                                self.output_type_hash_sources.insert(dest.id, location);
                            }
                            self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                            self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                            next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                        } else if self.consume_indices.contains_key(&var.id)
                            || self.read_ref_indices.contains_key(&var.id)
                            || self.read_ref_param_input_indices.contains_key(&var.id)
                        {
                            self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                            self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                            next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                        }
                    }
                    IrInstruction::Call { dest: Some(dest), func, args }
                        if matches!(func.as_str(), "__ckb_current_script_hash" | "__ckb_transaction_hash")
                            && args.is_empty()
                            && dest.ty == IrType::Hash =>
                    {
                        self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                        self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                        next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                    }
                    IrInstruction::Call { dest: Some(dest), func, args }
                        if matches!(
                            func.as_str(),
                            "__ckb_input_out_point_tx_hash"
                                | "__ckb_cell_lock_hash"
                                | "__ckb_cell_type_hash"
                                | "__ckb_cell_data_hash_field"
                                | "__ckb_cell_data_hash"
                                | "__ckb_cell_data_hash_at"
                                | "__ckb_cell_lock_code_hash"
                                | "__ckb_cell_type_code_hash"
                                | "__ckb_cell_lock_args_hash"
                                | "__ckb_cell_type_args_hash"
                        ) && (args.len() == 1 || (func == "__ckb_cell_data_hash_at" && args.len() == 2))
                            && dest.ty == IrType::Hash =>
                    {
                        self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                        self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                        next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                    }
                    IrInstruction::Call { dest: Some(dest), func, args }
                        if matches!(
                            func.as_str(),
                            "__ckb_witness_raw"
                                | "__ckb_witness_lock"
                                | "__ckb_witness_input_type"
                                | "__ckb_witness_output_type"
                                | "__ckb_witness_lock_exact32"
                                | "__ckb_witness_input_type_exact32"
                                | "__ckb_witness_output_type_exact32"
                        ) && args.len() == 1
                            && dest.ty == IrType::Hash =>
                    {
                        self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                        self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                        next_cell_slot += RUNTIME_CELL_SLOT_SIZE;
                    }
                    IrInstruction::Call { dest: Some(dest), func, args }
                        if ((matches!(func.as_str(), "__ckb_cell_data_blake2b_span" | "__ckb_witness_blake2b_span")
                            && args.len() == 3)
                            || (func == "__ckb_raw_transaction_hash_without_cell_deps" && args.is_empty())
                            || (func == "__ckb_transaction_blake2b_gather" && args.len() == 4)
                            || (func == "__ckb_witness_bytes32" && args.len() == 2)
                            || (func == "__ckb_witness_bounded_blake2b" && args.len() == 3)
                            || (func == "__ckb_witness_blake2b_select_chunks" && args.len() == 6))
                            && dest.ty == IrType::Hash =>
                    {
                        self.cell_buffer_size_offsets.insert(dest.id, next_cell_slot);
                        self.cell_buffer_offsets.insert(dest.id, next_cell_slot + 8);
                        // A digest needs a length word and 32 bytes, not a full
                        // runtime Cell buffer. Preserve all legacy allocations.
                        next_cell_slot += 40;
                    }
                    _ => {}
                }
            }
        }

        let mut u128_value_ids = BTreeSet::new();
        for param in params {
            if param.ty == IrType::U128 {
                u128_value_ids.insert(param.binding.id);
            }
        }
        for block in &body.blocks {
            for instruction in &block.instructions {
                self.collect_u128_instruction_vars(instruction, &mut u128_value_ids);
            }
            self.collect_u128_terminator_vars(&block.terminator, &mut u128_value_ids);
        }
        for var_id in u128_value_ids {
            self.u128_value_offsets.insert(var_id, next_cell_slot);
            next_cell_slot += 16;
        }

        if self.current_function_owns_exact_read_cache && self.module_uses_exact_read_cache {
            next_cell_slot = align_up(next_cell_slot, 8);
            self.exact_read_cache_offset = Some(next_cell_slot);
            next_cell_slot +=
                self.exact_read_cache_header_size() + RUNTIME_EXACT_READ_CACHE_WAYS * RUNTIME_EXACT_READ_CACHE_ENTRY_SIZE;
        }

        let collection_slot_size = 8 + RUNTIME_COLLECTION_BUFFER_SIZE;
        let collection_count = body
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|instruction| matches!(instruction, IrInstruction::CollectionNew { .. }))
            .count();
        self.collection_region_start = next_cell_slot;
        next_cell_slot += collection_count * collection_slot_size;

        self.frame_size = align_frame(next_cell_slot + RUNTIME_EXPR_TEMP_SIZE + RUNTIME_SCRATCH_SIZE + 16);
    }

    pub(super) fn exact_read_cache_header_size(&self) -> usize {
        if self.module_uses_exact_read_hot_cache {
            RUNTIME_EXACT_READ_CACHE_HOT_HEADER_SIZE
        } else {
            RUNTIME_EXACT_READ_CACHE_BASE_HEADER_SIZE
        }
    }

    pub(super) fn runtime_expr_temp_offset(&self, depth: usize) -> usize {
        debug_assert!(depth < RUNTIME_EXPR_TEMP_SLOTS);
        self.runtime_scratch_size_offset() - RUNTIME_EXPR_TEMP_SIZE + depth * 8
    }

    pub(super) fn checked_runtime_expr_temp_offset(&self, depth: usize) -> Option<usize> {
        (depth < RUNTIME_EXPR_TEMP_SLOTS).then(|| self.runtime_expr_temp_offset(depth))
    }

    pub(super) fn runtime_scratch_size_offset(&self) -> usize {
        self.frame_size - 16 - RUNTIME_SCRATCH_SIZE
    }

    pub(super) fn runtime_scratch_buffer_offset(&self) -> usize {
        self.runtime_scratch_size_offset() + 8
    }

    pub(super) fn runtime_scratch2_size_offset(&self) -> usize {
        self.runtime_scratch_size_offset() + RUNTIME_SCRATCH_SLOT_SIZE
    }

    pub(super) fn runtime_scratch2_buffer_offset(&self) -> usize {
        self.runtime_scratch2_size_offset() + 8
    }

    pub(super) fn emit_store_data_args_at(&mut self, max_bytes: usize, size_offset: usize, buffer_offset: usize) {
        self.emit(format!("li t0, {}", max_bytes));
        self.emit_schema_size_store("t0", size_offset);
        self.emit_sp_addi("a0", buffer_offset);
        self.emit_sp_addi("a1", size_offset);
        self.emit("li a2, 0");
    }

    pub(super) fn emit_schema_size_store(&mut self, src: &str, size_offset: usize) {
        self.invalidate_schema_size_facts(size_offset);
        self.emit_stack_store(src, size_offset);
    }

    pub(super) fn emit_load_cell_data_syscall(&mut self, reason: &str, source: u64, index: usize) {
        let size_offset = self.runtime_scratch_size_offset();
        let buffer_offset = self.runtime_scratch_buffer_offset();
        self.emit_load_cell_data_syscall_to_offsets(reason, source, index, size_offset, buffer_offset, RUNTIME_SCRATCH_BUFFER_SIZE);
    }

    pub(super) fn emit_load_cell_data_syscall_to_offsets(
        &mut self,
        reason: &str,
        source: u64,
        index: usize,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!("# cellscript abi: LOAD_CELL_DATA reason={} source={} index={}", reason, ckb_source_name(source), index));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("li a3, {}", index));
        self.emit(format!("li a4, {}", source));
        self.emit(format!("li a7, {}", self.runtime_abi().load_cell_data));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_load_cell_data_syscall_to_offsets_dynamic_index(
        &mut self,
        reason: &str,
        source: u64,
        index_reg: &str,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!(
            "# cellscript abi: LOAD_CELL_DATA reason={} source={} index={}",
            reason,
            ckb_source_name(source),
            index_reg
        ));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("addi a3, {}, 0", index_reg));
        self.emit(format!("li a4, {}", source));
        self.emit(format!("li a7, {}", self.runtime_abi().load_cell_data));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_load_witness_syscall_to_offsets(
        &mut self,
        reason: &str,
        source: u64,
        index: usize,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!("# cellscript abi: LOAD_WITNESS reason={} source={} index={}", reason, ckb_source_name(source), index));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("li a3, {}", index));
        self.emit(format!("li a4, {}", source));
        self.emit(format!("li a7, {}", self.runtime_abi().load_witness));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_load_script_syscall_to_offsets(
        &mut self,
        reason: &str,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!("# cellscript abi: LOAD_SCRIPT reason={}", reason));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("li a7, {}", self.runtime_abi().load_script));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_load_cell_by_field_syscall_to_offsets(
        &mut self,
        reason: &str,
        source: u64,
        index: usize,
        field: u64,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!(
            "# cellscript abi: LOAD_CELL_BY_FIELD reason={} source={} index={} field={}",
            reason,
            ckb_source_name(source),
            index,
            field
        ));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("li a3, {}", index));
        self.emit(format!("li a4, {}", source));
        self.emit(format!("li a5, {}", field));
        self.emit(format!("li a7, {}", self.runtime_abi().load_cell_by_field));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_load_cell_by_field_syscall_to_offsets_dynamic_index(
        &mut self,
        reason: &str,
        source: u64,
        index_reg: &str,
        field: u64,
        size_offset: usize,
        buffer_offset: usize,
        max_bytes: usize,
    ) {
        self.emit(format!(
            "# cellscript abi: LOAD_CELL_BY_FIELD reason={} source={} index={} field={}",
            reason,
            ckb_source_name(source),
            index_reg,
            field
        ));
        self.emit_store_data_args_at(max_bytes, size_offset, buffer_offset);
        self.emit(format!("addi a3, {}, 0", index_reg));
        self.emit(format!("li a4, {}", source));
        self.emit(format!("li a5, {}", field));
        self.emit(format!("li a7, {}", self.runtime_abi().load_cell_by_field));
        self.emit("ecall");
        self.emit("# a0 = CKB syscall return code");
    }

    pub(super) fn emit_return_on_syscall_error(&mut self, error: CellScriptRuntimeError) {
        let ok_label = self.fresh_label("ckb_syscall_ok");
        self.emit(format!("beqz a0, {}", ok_label));
        self.emit_fail(error);
        self.emit_label(&ok_label);
    }

    pub(super) fn emit_param_spills(&mut self, params: &[IrParam]) -> Result<()> {
        let mut abi_index = 0usize;
        for param in params {
            if is_ckb_temporal_scalar_ir_type(&param.ty) {
                self.emit(format!("# cellscript abi: temporal scalar param {} value={}", param.name, abi_arg_label(abi_index)));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                abi_index += 1;
            } else if let Some(width) = self.fieldless_enum_width(&param.ty) {
                self.emit(format!(
                    "# cellscript abi: fieldless enum param {} value={} width={}",
                    param.name,
                    abi_arg_label(abi_index),
                    width
                ));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                abi_index += 2;
            } else if let Some(width) = self.generic_value_type_width(&param.ty) {
                self.emit(format!(
                    "# cellscript abi: fixed named-value param {} pointer={} length={} size={}",
                    param.name,
                    abi_arg_label(abi_index),
                    abi_arg_label(abi_index + 1),
                    width
                ));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&param.binding.id).copied() {
                    self.emit_spill_abi_arg(abi_index + 1, size_offset);
                }
                abi_index += 2;
            } else if named_type_name(&param.ty).is_some() {
                self.emit(format!(
                    "# cellscript abi: schema param {} pointer={} length={}",
                    param.name,
                    abi_arg_label(abi_index),
                    abi_arg_label(abi_index + 1)
                ));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                if let Some(size_offset) = self.schema_pointer_size_offsets.get(&param.binding.id).copied() {
                    self.emit_spill_abi_arg(abi_index + 1, size_offset);
                }
                abi_index += 2;
                if let (Some(pointer_offset), Some(size_offset)) = (
                    self.param_type_hash_pointer_offsets.get(&param.binding.id).copied(),
                    self.param_type_hash_size_offsets.get(&param.binding.id).copied(),
                ) {
                    self.emit(format!(
                        "# cellscript abi: schema param {} type_hash pointer={} length={} size=32",
                        param.name,
                        abi_arg_label(abi_index),
                        abi_arg_label(abi_index + 1)
                    ));
                    self.emit_spill_abi_arg(abi_index, pointer_offset);
                    self.emit_spill_abi_arg(abi_index + 1, size_offset);
                    abi_index += 2;
                }
            } else if let Some(width) = fixed_byte_pointer_param_width(&param.ty) {
                self.emit(format!(
                    "# cellscript abi: fixed-byte param {} pointer={} length={} size={}",
                    param.name,
                    abi_arg_label(abi_index),
                    abi_arg_label(abi_index + 1),
                    width
                ));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&param.binding.id).copied() {
                    self.emit_spill_abi_arg(abi_index + 1, size_offset);
                }
                abi_index += 2;
            } else if let Some(width) = fixed_aggregate_pointer_param_width(&param.ty) {
                self.emit(format!(
                    "# cellscript abi: fixed-aggregate param {} pointer={} length={} size={}",
                    param.name,
                    abi_arg_label(abi_index),
                    abi_arg_label(abi_index + 1),
                    width
                ));
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&param.binding.id).copied() {
                    self.emit_spill_abi_arg(abi_index + 1, size_offset);
                }
                abi_index += 2;
            } else {
                self.emit_spill_abi_arg(abi_index, param.binding.id * 8);
                abi_index += 1;
            }
        }

        Ok(())
    }

    pub(super) fn emit_spill_abi_arg(&mut self, abi_index: usize, stack_offset: usize) {
        if abi_index < 8 {
            self.emit_stack_store(&format!("a{}", abi_index), stack_offset);
        } else {
            let caller_stack_offset = (abi_index - 8) * 8;
            self.emit(format!("# cellscript abi: arg{} loaded from caller stack +{}", abi_index, caller_stack_offset));
            self.emit(format!("ld t0, {}(fp)", caller_stack_offset));
            self.emit_stack_store("t0", stack_offset);
        }
    }

    pub(super) fn record_instruction_var(&self, instruction: &IrInstruction, max_var_id: &mut Option<usize>) {
        match instruction {
            IrInstruction::LoadConst { dest, .. }
            | IrInstruction::LoadVar { dest, .. }
            | IrInstruction::Unary { dest, .. }
            | IrInstruction::FieldAccess { dest, .. }
            | IrInstruction::Index { dest, .. }
            | IrInstruction::Length { dest, .. }
            | IrInstruction::TypeHash { dest, .. }
            | IrInstruction::Create { dest, .. }
            | IrInstruction::CreateUnique { dest, .. }
            | IrInstruction::ReadRef { dest, .. } => self.record_var(dest, max_var_id),
            IrInstruction::CollectionNew { dest, capacity, .. } => {
                self.record_var(dest, max_var_id);
                if let Some(capacity) = capacity {
                    self.record_operand(capacity, max_var_id);
                }
            }
            IrInstruction::Move { dest, src } => {
                self.record_var(dest, max_var_id);
                self.record_operand(src, max_var_id);
            }
            IrInstruction::Tuple { dest, fields } => {
                self.record_var(dest, max_var_id);
                for field in fields {
                    self.record_operand(field, max_var_id);
                }
            }
            IrInstruction::EnumConstruct { dest, fields, .. } => {
                self.record_var(dest, max_var_id);
                for field in fields {
                    self.record_operand(field, max_var_id);
                }
            }
            IrInstruction::EnumTag { dest, operand, .. } | IrInstruction::EnumPayload { dest, operand, .. } => {
                self.record_var(dest, max_var_id);
                self.record_operand(operand, max_var_id);
            }
            IrInstruction::Binary { dest, left, right, .. } => {
                self.record_var(dest, max_var_id);
                self.record_operand(left, max_var_id);
                self.record_operand(right, max_var_id);
            }
            IrInstruction::StoreVar { src, .. } => self.record_operand(src, max_var_id),
            IrInstruction::Call { dest, args, .. } => {
                if let Some(dest) = dest {
                    self.record_var(dest, max_var_id);
                }
                for arg in args {
                    self.record_operand(arg, max_var_id);
                }
            }
            IrInstruction::Consume { operand } | IrInstruction::Destroy { operand, policy: _ } => {
                self.record_operand(operand, max_var_id)
            }
            IrInstruction::Transfer { dest, operand, to } => {
                self.record_var(dest, max_var_id);
                self.record_operand(operand, max_var_id);
                self.record_operand(to, max_var_id);
            }
            IrInstruction::Claim { dest, receipt } => {
                self.record_var(dest, max_var_id);
                self.record_operand(receipt, max_var_id);
            }
            IrInstruction::Settle { dest, operand } => {
                self.record_var(dest, max_var_id);
                self.record_operand(operand, max_var_id)
            }
            IrInstruction::ReplaceUnique { dest, operand, .. } => {
                self.record_var(dest, max_var_id);
                self.record_operand(operand, max_var_id)
            }
            IrInstruction::CellMetadataEquality { left, right, .. } => {
                self.record_operand(left, max_var_id);
                self.record_operand(right, max_var_id);
            }
            IrInstruction::CollectionPush { collection, value } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(value, max_var_id);
            }
            IrInstruction::CollectionCapacity { dest, collection } => {
                self.record_var(dest, max_var_id);
                self.record_operand(collection, max_var_id);
            }
            IrInstruction::CollectionExtend { collection, slice } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(slice, max_var_id);
            }
            IrInstruction::CollectionClear { collection } => {
                self.record_operand(collection, max_var_id);
            }
            IrInstruction::CollectionReverse { collection } => {
                self.record_operand(collection, max_var_id);
            }
            IrInstruction::CollectionTruncate { collection, len } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(len, max_var_id);
            }
            IrInstruction::CollectionSwap { collection, left, right } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(left, max_var_id);
                self.record_operand(right, max_var_id);
            }
            IrInstruction::CollectionContains { dest, collection, value } => {
                self.record_var(dest, max_var_id);
                self.record_operand(collection, max_var_id);
                self.record_operand(value, max_var_id);
            }
            IrInstruction::CollectionRemove { dest, collection, index } => {
                self.record_var(dest, max_var_id);
                self.record_operand(collection, max_var_id);
                self.record_operand(index, max_var_id);
            }
            IrInstruction::CollectionInsert { collection, index, value } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(index, max_var_id);
                self.record_operand(value, max_var_id);
            }
            IrInstruction::CollectionSet { collection, index, value } => {
                self.record_operand(collection, max_var_id);
                self.record_operand(index, max_var_id);
                self.record_operand(value, max_var_id);
            }
            IrInstruction::CollectionPop { dest, collection } => {
                self.record_var(dest, max_var_id);
                self.record_operand(collection, max_var_id);
            }
            IrInstruction::BoundedCellLoad { dest, found, index, .. } => {
                self.record_var(dest, max_var_id);
                self.record_var(found, max_var_id);
                self.record_operand(index, max_var_id);
            }
            IrInstruction::BoundedPlanLoad { dest, found, plan, index, .. } => {
                self.record_var(dest, max_var_id);
                self.record_var(found, max_var_id);
                self.record_operand(plan, max_var_id);
                self.record_operand(index, max_var_id);
            }
            IrInstruction::BoundedOutputVerify { index, pattern, .. } => {
                self.record_operand(index, max_var_id);
                for (_, value) in &pattern.fields {
                    self.record_operand(value, max_var_id);
                }
                if let Some(lock) = &pattern.lock {
                    self.record_operand(lock, max_var_id);
                }
            }
            IrInstruction::BoundedOutputEnd { index } => self.record_operand(index, max_var_id),
        }
    }

    pub(super) fn record_instruction_fixed_byte_local(&self, instruction: &IrInstruction, offsets: &mut HashMap<usize, usize>) {
        let record = |offsets: &mut HashMap<usize, usize>, var: &IrVar| {
            if var.ty == IrType::U128 {
                offsets.insert(var.id, 16);
            }
            if let Some(width) = fixed_byte_width(&var.ty, type_static_length(&var.ty)).filter(|width| *width > 8) {
                offsets.insert(var.id, width);
            }
            if let Some(width) = fixed_aggregate_pointer_param_width(&var.ty).filter(|width| *width > 8) {
                offsets.insert(var.id, width);
            }
            if let Some(width) = self.fixed_named_type_width(&var.ty) {
                offsets.insert(var.id, width);
            }
        };

        match instruction {
            IrInstruction::LoadConst { dest, .. }
            | IrInstruction::LoadVar { dest, .. }
            | IrInstruction::Unary { dest, .. }
            | IrInstruction::FieldAccess { dest, .. }
            | IrInstruction::Index { dest, .. }
            | IrInstruction::Length { dest, .. }
            | IrInstruction::TypeHash { dest, .. }
            | IrInstruction::Create { dest, .. }
            | IrInstruction::CreateUnique { dest, .. }
            | IrInstruction::ReplaceUnique { dest, .. }
            | IrInstruction::Transfer { dest, .. }
            | IrInstruction::Claim { dest, .. }
            | IrInstruction::Settle { dest, .. }
            | IrInstruction::ReadRef { dest, .. }
            | IrInstruction::CollectionCapacity { dest, .. }
            | IrInstruction::CollectionContains { dest, .. }
            | IrInstruction::CollectionRemove { dest, .. }
            | IrInstruction::CollectionPop { dest, .. }
            | IrInstruction::CollectionNew { dest, .. }
            | IrInstruction::Move { dest, .. }
            | IrInstruction::Tuple { dest, .. }
            | IrInstruction::EnumConstruct { dest, .. }
            | IrInstruction::EnumTag { dest, .. }
            | IrInstruction::Binary { dest, .. } => record(offsets, dest),
            IrInstruction::EnumPayload { dest, enum_name, variant, field_index, .. } => {
                record(offsets, dest);
                if let Some(field) = self
                    .enum_layouts
                    .get(enum_name)
                    .and_then(|layout| layout.variants.iter().find(|candidate| candidate.name == *variant))
                    .and_then(|variant| variant.fields.get(*field_index))
                    && !field.linear
                    && !is_fixed_scalar_ir_type(&field.ty)
                    && field.width > 0
                {
                    offsets.insert(dest.id, field.width);
                }
            }
            IrInstruction::Call { dest, func, .. } => {
                if let Some(dest) = dest {
                    if is_ckb_fixed_hash_helper(func) && dest.ty == IrType::Hash {
                        offsets.insert(dest.id, 32);
                    }
                    record(offsets, dest);
                }
            }
            IrInstruction::StoreVar { .. }
            | IrInstruction::Consume { .. }
            | IrInstruction::Destroy { .. }
            | IrInstruction::CellMetadataEquality { .. }
            | IrInstruction::CollectionPush { .. }
            | IrInstruction::CollectionExtend { .. }
            | IrInstruction::CollectionClear { .. }
            | IrInstruction::CollectionReverse { .. }
            | IrInstruction::CollectionTruncate { .. }
            | IrInstruction::CollectionSwap { .. }
            | IrInstruction::CollectionInsert { .. }
            | IrInstruction::CollectionSet { .. } => {}
            IrInstruction::BoundedCellLoad { .. }
            | IrInstruction::BoundedPlanLoad { .. }
            | IrInstruction::BoundedOutputVerify { .. }
            | IrInstruction::BoundedOutputEnd { .. } => {}
        }
    }

    pub(super) fn record_terminator_var(&self, terminator: &IrTerminator, max_var_id: &mut Option<usize>) {
        match terminator {
            IrTerminator::Return(Some(operand)) | IrTerminator::Branch { cond: operand, .. } => {
                self.record_operand(operand, max_var_id)
            }
            IrTerminator::Return(None) | IrTerminator::Jump(_) => {}
        }
    }

    pub(super) fn collect_u128_instruction_vars(&self, instruction: &IrInstruction, out: &mut BTreeSet<usize>) {
        match instruction {
            IrInstruction::LoadConst { dest, .. }
            | IrInstruction::LoadVar { dest, .. }
            | IrInstruction::Unary { dest, .. }
            | IrInstruction::FieldAccess { dest, .. }
            | IrInstruction::Index { dest, .. }
            | IrInstruction::Length { dest, .. }
            | IrInstruction::TypeHash { dest, .. }
            | IrInstruction::Create { dest, .. }
            | IrInstruction::CreateUnique { dest, .. }
            | IrInstruction::ReplaceUnique { dest, .. }
            | IrInstruction::Claim { dest, .. }
            | IrInstruction::ReadRef { dest, .. }
            | IrInstruction::CollectionCapacity { dest, .. }
            | IrInstruction::CollectionContains { dest, .. }
            | IrInstruction::CollectionRemove { dest, .. }
            | IrInstruction::CollectionPop { dest, .. }
            | IrInstruction::Settle { dest, .. }
            | IrInstruction::Transfer { dest, .. }
            | IrInstruction::Move { dest, .. }
            | IrInstruction::Tuple { dest, .. }
            | IrInstruction::EnumConstruct { dest, .. }
            | IrInstruction::EnumTag { dest, .. }
            | IrInstruction::EnumPayload { dest, .. }
            | IrInstruction::Binary { dest, .. }
            | IrInstruction::Call { dest: Some(dest), .. } => {
                if dest.ty == IrType::U128 {
                    out.insert(dest.id);
                }
            }
            IrInstruction::CollectionNew { dest, .. } => {
                if dest.ty == IrType::U128 {
                    out.insert(dest.id);
                }
            }
            IrInstruction::StoreVar { .. }
            | IrInstruction::Call { dest: None, .. }
            | IrInstruction::Consume { .. }
            | IrInstruction::Destroy { .. }
            | IrInstruction::CellMetadataEquality { .. }
            | IrInstruction::CollectionPush { .. }
            | IrInstruction::CollectionExtend { .. }
            | IrInstruction::CollectionClear { .. }
            | IrInstruction::CollectionReverse { .. }
            | IrInstruction::CollectionTruncate { .. }
            | IrInstruction::CollectionSwap { .. }
            | IrInstruction::CollectionInsert { .. }
            | IrInstruction::CollectionSet { .. }
            | IrInstruction::BoundedCellLoad { .. }
            | IrInstruction::BoundedPlanLoad { .. }
            | IrInstruction::BoundedOutputVerify { .. }
            | IrInstruction::BoundedOutputEnd { .. } => {}
        }
    }

    pub(super) fn collect_u128_terminator_vars(&self, terminator: &IrTerminator, out: &mut BTreeSet<usize>) {
        if let IrTerminator::Return(Some(IrOperand::Var(var))) = terminator
            && var.ty == IrType::U128
        {
            out.insert(var.id);
        }
    }

    pub(super) fn record_operand(&self, operand: &IrOperand, max_var_id: &mut Option<usize>) {
        if let IrOperand::Var(var) = operand {
            self.record_var(var, max_var_id);
        }
    }

    pub(super) fn record_var(&self, var: &IrVar, max_var_id: &mut Option<usize>) {
        *max_var_id = Some(max_var_id.map(|current| current.max(var.id)).unwrap_or(var.id));
    }

    pub(super) fn const_as_u128(value: &IrConst) -> Option<u128> {
        match value {
            IrConst::U8(value) => Some((*value).into()),
            IrConst::U16(value) => Some((*value).into()),
            IrConst::U32(value) => Some((*value).into()),
            IrConst::U64(value) => Some((*value).into()),
            IrConst::U128(value) => Some(*value),
            _ => None,
        }
    }

    pub(super) fn expected_u128_source(&self, operand: &IrOperand) -> Option<ExpectedFixedByteSource> {
        match operand {
            IrOperand::Const(value) => {
                Self::const_as_u128(value).map(|value| ExpectedFixedByteSource::Const(value.to_le_bytes().to_vec()))
            }
            _ => self.expected_fixed_byte_source(operand, 16),
        }
    }

    pub(super) fn emit_store_byte_to_stack_offset(&mut self, src_reg: &str, offset: usize) {
        self.emit_stack_store_byte(src_reg, offset);
    }

    pub(super) fn emit_store_u128_const_to_stack_offset(&mut self, value: u128, offset: usize) {
        self.emit(format!("# cellscript abi: materialize u128 const at stack+{}", offset));
        for (index, byte) in value.to_le_bytes().iter().enumerate() {
            self.emit(format!("li t0, {}", byte));
            self.emit_store_byte_to_stack_offset("t0", offset + index);
        }
    }

    pub(super) fn emit_store_u128_pointer_for_var(&mut self, var_id: usize, offset: usize) {
        self.emit_sp_addi("t0", offset);
        self.emit_stack_store("t0", var_id * 8);
    }

    pub(super) fn emit_materialize_u128_operand_to_var(&mut self, dest: &IrVar, src: &IrOperand) -> bool {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 destination has no 16-byte storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return true;
        };
        if let IrOperand::Const(value) = src
            && let Some(value) = Self::const_as_u128(value)
        {
            self.emit_store_u128_const_to_stack_offset(value, dest_offset);
            self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
            return true;
        }
        if let IrOperand::Var(var) = src
            && matches!(var.ty, IrType::U8 | IrType::U16 | IrType::U32 | IrType::U64)
        {
            self.emit("# cellscript abi: zero-extend unsigned scalar into u128 storage");
            self.emit_operand_to_register("t0", src);
            self.emit_stack_store("t0", dest_offset);
            self.emit_stack_store("zero", dest_offset + 8);
            self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
            return true;
        }
        self.emit(format!("# cellscript abi: materialize u128 operand into var{}", dest.id));
        if !self.emit_u128_operand_limbs("t0", "t1", "t6", "t4", src, "u128 materialize") {
            return true;
        }
        self.emit_stack_store("t0", dest_offset);
        self.emit_stack_store("t1", dest_offset + 8);
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
        true
    }

    pub(super) fn emit_u64_le_from_fixed_byte_source(
        &mut self,
        dest_reg: &str,
        scratch_reg: &str,
        base_reg: &str,
        source: &ExpectedFixedByteSource,
        start: usize,
    ) {
        self.emit(format!("li {}, 0", dest_reg));
        for byte_offset in 0..8 {
            self.emit_fixed_byte_source_byte_to(scratch_reg, base_reg, source, start + byte_offset);
            if byte_offset != 0 {
                self.emit(format!("slli {}, {}, {}", scratch_reg, scratch_reg, byte_offset * 8));
            }
            self.emit(format!("or {}, {}, {}", dest_reg, dest_reg, scratch_reg));
        }
    }

    pub(super) fn emit_u128_operand_limbs(
        &mut self,
        low_reg: &str,
        high_reg: &str,
        scratch_reg: &str,
        base_reg: &str,
        operand: &IrOperand,
        context: &str,
    ) -> bool {
        let Some(source) = self.expected_u128_source(operand) else {
            self.emit(format!("# cellscript abi: {} u128 operand is not addressable; fail closed", context));
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return false;
        };
        self.emit_prepare_fixed_byte_source(&source, 16, context);
        if self.emit_fixed_byte_source_pointer_to(base_reg, &source) {
            // Resolve schema-backed pointers before either accumulator is
            // live. Dynamic Molecule bounds checks use t0..t5 internally, so
            // resolving the pointer for every byte would overwrite the limb
            // being assembled.
            self.emit_unaligned_scalar_load(base_reg, low_reg, scratch_reg, 0, 8);
            self.emit_unaligned_scalar_load(base_reg, high_reg, scratch_reg, 8, 8);
        } else {
            // Constants intentionally have no addressable storage.
            self.emit_u64_le_from_fixed_byte_source(low_reg, scratch_reg, base_reg, &source, 0);
            self.emit_u64_le_from_fixed_byte_source(high_reg, scratch_reg, base_reg, &source, 8);
        }
        true
    }

    pub(super) fn emit_u128_binary_operand_limbs(&mut self, left: &IrOperand, right: &IrOperand, context: &str) -> bool {
        if !self.emit_u128_operand_limbs("t0", "t1", "t6", "t4", left, &format!("{} left", context)) {
            return false;
        }
        let left_low_offset = self.runtime_expr_temp_offset(0);
        let left_high_offset = self.runtime_expr_temp_offset(1);
        self.emit_stack_store("t0", left_low_offset);
        self.emit_stack_store("t1", left_high_offset);
        if !self.emit_u128_operand_limbs("t2", "t3", "t6", "t5", right, &format!("{} right", context)) {
            return false;
        }
        // Loading a dynamic schema field runs Molecule validation that uses
        // t0/t1. Restore the left limbs only after the right operand is fully
        // materialized.
        self.emit_stack_load("t0", left_low_offset);
        self.emit_stack_load("t1", left_high_offset);
        true
    }

    pub(super) fn operand_is_u128_like(&self, operand: &IrOperand) -> bool {
        match operand {
            IrOperand::Var(var) => var.ty == IrType::U128,
            IrOperand::Const(IrConst::U128(_)) => true,
            _ => false,
        }
    }

    pub(super) fn emit_store_const_bytes_to_stack(&mut self, bytes: &[u8], offset: usize) {
        for (index, byte) in bytes.iter().enumerate() {
            self.emit(format!("li t0, {}", byte));
            self.emit_stack_store_byte("t0", offset + index);
        }
    }
}

#[cfg(test)]
mod verifier_failure_tests {
    use super::*;

    fn generator() -> CodeGenerator {
        CodeGenerator::new(CodegenOptions::default())
    }

    #[test]
    fn abort_helper_is_demand_driven_frame_free_and_non_returning() {
        let mut codegen = generator();
        codegen.emit_process_failure_helper();
        assert!(codegen.assembly.is_empty());

        codegen.emit_process_failure(CellScriptRuntimeError::AssertionFailed);
        codegen.emit_process_failure_helper();
        let assembly = codegen.assembly.join("\n");
        assert!(assembly.contains(
            ".Lverifier_failure_5_0:\n    # cellscript runtime error 5 assertion-failed\n    li a0, 5\n    j __cellscript_abort"
        ));
        assert!(assembly.ends_with("    li a7, 93\n    ecall\n    j __cellscript_abort"));
        assert!(!assembly.contains("ret"));
        assert!(!assembly.contains("(sp)"));
        assert_eq!(codegen.entry_frame_sizes.get("__cellscript_abort"), Some(&0));
    }

    #[test]
    fn scalar_context_helpers_are_demand_driven_and_keep_load_checks() {
        for (statement, expected) in [
            ("", None),
            ("let number = ckb::header_epoch_number()", Some("__ckb_header_epoch_number")),
            ("let since = ckb::input_since()", Some("__ckb_input_since")),
        ] {
            let source = format!("module scalar_context\naction main() -> u64 {{ verification\n{statement}\nreturn 0 }}");
            let ast = crate::frontend::parse(&source, crate::CellScriptEdition::Edition2026).unwrap();
            let ir = crate::ir::generate(&ast).unwrap();
            let generated = generator().generate(&ir, ArtifactFormat::RiscvAssembly).unwrap();
            let assembly = String::from_utf8(generated).unwrap();
            for name in [
                "__env_current_timepoint",
                "__ckb_header_epoch_number",
                "__ckb_header_epoch_start_block_number",
                "__ckb_header_epoch_length",
                "__ckb_input_since",
            ] {
                assert_eq!(assembly.contains(&format!("\n{name}:")), expected == Some(name));
            }
            if expected.is_some() {
                assert!(assembly.contains(".Lverifier_failure_1_"), "value getter must check syscall status");
                assert!(assembly.contains(".Lverifier_failure_4_"), "value getter must check exact returned width");
            } else {
                assert!(!assembly.contains("__cellscript_abort:"), "unused getters must not demand a terminal helper");
            }
        }
    }

    #[test]
    fn cold_error_handler_exits_instead_of_returning_a_value() {
        let mut codegen = generator();
        codegen.current_function = Some("checked".to_string());
        codegen.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
        codegen.emit_shared_epilogue();
        let assembly = codegen.assembly.join("\n");
        let (failure, ordinary_return) = assembly.split_once(".Lchecked_epilogue:").unwrap();
        assert!(failure.contains("j .Lchecked_fail_20"));
        assert!(failure.contains(".Lverifier_failure_20_0:"));
        assert!(failure.contains("li a0, 20\n    j __cellscript_abort"));
        assert!(!failure.contains("j .Lchecked_epilogue"));
        assert!(ordinary_return.contains("ret"));
    }

    #[test]
    fn structured_failure_marker_overrides_value_return() {
        for operand in [IrOperand::Const(IrConst::U64(5)), IrOperand::Const(IrConst::Bool(false))] {
            let mut codegen = generator();
            codegen.current_function = Some("check".to_string());
            let block = IrBlock {
                id: BlockId(3),
                instructions: Vec::new(),
                terminator: IrTerminator::Return(Some(operand)),
                runtime_error: Some(CellScriptRuntimeError::AssertionFailed),
            };
            codegen.generate_block(&block, None).unwrap();
            let assembly = codegen.assembly.join("\n");
            assert!(assembly.contains("li a0, 5\n    j __cellscript_abort"));
            assert!(!assembly.contains("epilogue"));
        }
    }

    #[test]
    fn ordinary_error_shaped_scalars_and_false_still_return_normally() {
        for value in [IrConst::U64(5), IrConst::U64(20), IrConst::U64(49), IrConst::Bool(false), IrConst::Unit] {
            let mut codegen = generator();
            codegen.current_function = Some("value".to_string());
            codegen.generate_terminator(&IrTerminator::Return(Some(IrOperand::Const(value))), None).unwrap();
            let assembly = codegen.assembly.join("\n");
            assert!(assembly.contains("j .Lvalue_epilogue"));
            assert!(!codegen.needs_process_failure_helper);
            assert!(!assembly.contains("verifier_failure"));
        }
    }

    #[test]
    fn deliberate_status_apis_do_not_acquire_implicit_failure_checks() {
        for name in ["__ckb_close", "__ckb_wait"] {
            let mut codegen = generator();
            codegen.current_function = Some("caller".to_string());
            codegen.emit_call(None, name, &[IrOperand::Const(IrConst::U64(99))]).unwrap();
            assert!(!codegen.needs_process_failure_helper, "{name}");
            assert!(!codegen.assembly.join("\n").contains("__cellscript_abort"));
        }
    }

    #[test]
    fn wide_value_return_keeps_both_payload_registers() {
        let mut codegen = generator();
        codegen.current_function = Some("wide".to_string());
        let value = (49u128 << 64) | 20;
        codegen.generate_terminator(&IrTerminator::Return(Some(IrOperand::Const(IrConst::U128(value)))), None).unwrap();
        let assembly = codegen.assembly.join("\n");
        assert!(assembly.contains("li a0, 0"));
        assert!(assembly.contains("li a1, 0"));
        assert!(assembly.contains("li t6, 20"));
        assert!(assembly.contains("li t6, 49"));
        assert!(assembly.contains("or a0, a0, t6"));
        assert!(assembly.contains("or a1, a1, t6"));
        assert!(assembly.contains("j .Lwide_epilogue"));
        assert!(!codegen.needs_process_failure_helper);
    }

    #[test]
    fn runtime_requirements_and_scalar_status_failures_exit_before_continuation() {
        for name in ["__ckb_require_time", "__ckb_cell_capacity"] {
            let mut codegen = generator();
            codegen.current_function = Some("caller".to_string());
            codegen.emit_call(None, name, &[IrOperand::Const(IrConst::U64(99))]).unwrap();
            let assembly = codegen.assembly.join("\n");
            assert!(codegen.needs_process_failure_helper, "{name}");
            assert!(assembly.contains("j __cellscript_abort"));
            assert!(!assembly.contains("j .Lcaller_epilogue"));
            assert!(!assembly.contains(".Lverifier_failure_"), "dynamic status must not fabricate a static error code");
        }
    }
}
