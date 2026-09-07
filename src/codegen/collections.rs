use super::*;

impl CodeGenerator {
    pub(super) fn emit_index(&mut self, dest: &IrVar, arr: &IrOperand, idx: &IrOperand) -> Result<()> {
        if self.emit_fixed_aggregate_index(dest, arr, idx) {
            return Ok(());
        }
        if self.emit_dynamic_molecule_vector_index(dest, arr, idx) {
            return Ok(());
        }
        if self.emit_stack_collection_index(dest, arr, idx) {
            return Ok(());
        }
        if self.emit_dynamic_index_access(dest, arr, idx) {
            return Ok(());
        }

        self.emit("# index access (unresolved)");
        self.emit("# cellscript abi: fail closed because element layout is not statically computable");
        self.emit_fail(CellScriptRuntimeError::TypeHashMismatch);
        Ok(())
    }

    fn emit_fixed_aggregate_index(&mut self, dest: &IrVar, arr: &IrOperand, idx: &IrOperand) -> bool {
        let (IrOperand::Var(arr_var), Some(index)) = (arr, const_usize_operand(idx)) else {
            return false;
        };
        if !self.aggregate_pointer_sources.contains_key(&arr_var.id) {
            return false;
        }
        let IrType::Array(inner, len) = &arr_var.ty else {
            return false;
        };
        if index >= *len {
            return false;
        }
        let Some(element_width) = type_static_length(inner) else {
            return false;
        };
        let Some(total_width) = type_static_length(&arr_var.ty) else {
            return false;
        };
        let offset = index * element_width;
        self.emit(format!("# index access [{}]", index));
        self.emit(format!("# cellscript abi: fixed aggregate index element_offset={} element_size={}", offset, element_width));
        if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&arr_var.id).copied() {
            self.emit_loaded_schema_exact_size_check(size_offset, total_width, "fixed aggregate param");
            self.emit_loaded_schema_bounds_check(size_offset, offset + element_width, "fixed aggregate index");
        }
        self.emit_stack_load("t4", arr_var.id * 8);
        if let Some(width) = fixed_scalar_width(inner, Some(element_width)) {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", offset, width);
        } else {
            self.emit(format!("addi t0, t4, {}", offset));
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_dynamic_molecule_vector_index(&mut self, dest: &IrVar, arr: &IrOperand, idx: &IrOperand) -> bool {
        let IrOperand::Var(arr_var) = arr else {
            return false;
        };
        let Some(size_offset) = self
            .dynamic_value_size_offsets
            .get(&arr_var.id)
            .copied()
            .or_else(|| self.schema_pointer_size_offsets.get(&arr_var.id).copied())
        else {
            return false;
        };
        let Some(element_width) = molecule_vector_element_fixed_width(&arr_var.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };

        self.emit("# index access");
        self.emit(format!(
            "# cellscript abi: dynamic Molecule vector index element_size={} size_offset={}",
            element_width, size_offset
        ));
        self.emit_loaded_schema_bounds_check(size_offset, 4, "dynamic Molecule vector index");
        self.emit_stack_load("t4", arr_var.id * 8);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, 4);

        self.emit_stack_load("t3", size_offset);
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t5, t0, t2");
        self.emit("addi t5, t5, 4");
        self.emit("sub t2, t3, t5");
        let size_ok = self.fresh_label("molecule_vector_index_size_ok");
        self.emit(format!("beqz t2, {}", size_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&size_ok);

        match idx {
            IrOperand::Var(v) => self.emit_stack_load("t1", v.id * 8),
            IrOperand::Const(IrConst::U8(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U16(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U32(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U64(n)) => self.emit(format!("li t1, {}", n)),
            _ => self.emit("li t1, 0"),
        }

        let bounds_ok = self.fresh_label("molecule_vector_index_bounds_ok");
        self.emit("sltu t2, t1, t0");
        self.emit(format!("bnez t2, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&bounds_ok);

        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t1, t1, t2");
        self.emit("addi t1, t1, 4");
        self.emit("add t4, t4, t1");
        if fixed_scalar_width(&dest.ty, Some(element_width)).is_some() {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, element_width.min(8));
        } else {
            self.emit("addi t0, t4, 0");
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_stack_collection_index(&mut self, dest: &IrVar, arr: &IrOperand, idx: &IrOperand) -> bool {
        let IrOperand::Var(arr_var) = arr else {
            return false;
        };
        if !self.stack_collection_vars.contains(&arr_var.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&arr_var.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        let dest_scalar = fixed_scalar_width(&dest.ty, Some(element_width)).is_some();
        let dest_fixed_bytes = self.fixed_byte_like_width(&dest.ty).is_some_and(|width| width == element_width);
        if !dest_scalar && !dest_fixed_bytes {
            return false;
        }

        self.emit("# index access");
        self.emit(format!("# cellscript abi: stack collection index element_size={}", element_width));
        self.emit_stack_load("t4", arr_var.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", idx);

        let bounds_ok = self.fresh_label("stack_collection_index_bounds_ok");
        self.emit("sltu t2, t1, t0");
        self.emit(format!("bnez t2, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&bounds_ok);

        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t1, t1, t2");
        self.emit("add t4, t4, t1");
        if dest_scalar {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, element_width);
        } else {
            self.emit("addi t0, t4, 0");
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    /// Dynamic index access: compute element offset from array type layout.
    /// Handles cases where the index is not a constant or the array is not in
    /// aggregate_pointer_sources, but the element size is still statically known.
    fn emit_dynamic_index_access(&mut self, dest: &IrVar, arr: &IrOperand, idx: &IrOperand) -> bool {
        let IrOperand::Var(arr_var) = arr else {
            return false;
        };
        let IrType::Array(inner, len) = &arr_var.ty else {
            return false;
        };
        let Some(element_width) = type_static_length(inner) else {
            return false;
        };
        let Some(total_width) = type_static_length(&arr_var.ty) else {
            return false;
        };

        self.emit("# index access");
        self.emit(format!("# cellscript abi: dynamic index element_size={}", element_width));

        // Bounds check: if we have a size offset, verify total data is large enough
        if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&arr_var.id).copied() {
            self.emit_loaded_schema_exact_size_check(size_offset, total_width, "dynamic index aggregate");
        }

        // Load array base pointer
        self.emit_stack_load("t4", arr_var.id * 8);

        // Load index value into t1
        match idx {
            IrOperand::Var(v) => self.emit_stack_load("t1", v.id * 8),
            IrOperand::Const(IrConst::U8(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U16(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U32(n)) => self.emit(format!("li t1, {}", n)),
            IrOperand::Const(IrConst::U64(n)) => self.emit(format!("li t1, {}", n)),
            _ => self.emit("li t1, 0"),
        }

        // Indexes are unsigned: high-bit u64 values must not compare as
        // negative and escape the upper bound before pointer arithmetic.
        let bounds_ok = self.fresh_label("idx_bounds_ok");
        self.emit(format!("li t2, {}", len));
        self.emit("sltu t3, t1, t2");
        self.emit(format!("bnez t3, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&bounds_ok);

        // Compute offset = index * element_width
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t1, t1, t2");

        if fixed_scalar_width(inner, Some(element_width)).is_some() {
            // Scalar element: load from base + offset
            self.emit("add t4, t4, t1");
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, element_width.min(8));
        } else {
            // Pointer-sized element: compute base + offset
            self.emit("add t0, t4, t1");
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    pub(super) fn emit_length(&mut self, dest: &IrVar, operand: &IrOperand) -> Result<()> {
        self.emit("# length");
        if let Some(static_len) = self.static_length(operand) {
            self.emit(format!("li t0, {}", static_len));
        } else if self.emit_stack_collection_length(operand) || self.emit_dynamic_molecule_vector_length(operand) {
        } else if let Some(size_offset) = self.dynamic_length_from_size_offset(operand) {
            // For schema-backed or fixed-byte params, the actual size word is already
            // stored at the size offset; load it directly.
            self.emit(format!("# cellscript abi: dynamic length from size word at offset={}", size_offset));
            self.emit_stack_load("t0", size_offset);
        } else {
            self.emit("# cellscript abi: fail closed because dynamic length is not available");
            self.emit_fail(CellScriptRuntimeError::CollectionRuntimeUnsupported);
            return Ok(());
        }
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_stack_collection_length(&mut self, operand: &IrOperand) -> bool {
        let IrOperand::Var(var) = operand else {
            return false;
        };
        if !self.stack_collection_vars.contains(&var.id) {
            return false;
        }
        self.emit("# cellscript abi: stack collection length");
        self.emit_stack_load("t4", var.id * 8);
        self.emit("ld t0, -8(t4)");
        true
    }

    fn emit_dynamic_molecule_vector_length(&mut self, operand: &IrOperand) -> bool {
        let IrOperand::Var(var) = operand else {
            return false;
        };
        let Some(size_offset) =
            self.dynamic_value_size_offsets.get(&var.id).copied().or_else(|| self.schema_pointer_size_offsets.get(&var.id).copied())
        else {
            return false;
        };
        let Some(element_width) = molecule_vector_element_fixed_width(&var.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes) else {
            return false;
        };

        self.emit(format!(
            "# cellscript abi: dynamic Molecule vector length element_size={} size_offset={}",
            element_width, size_offset
        ));
        self.emit_loaded_schema_bounds_check(size_offset, 4, "dynamic Molecule vector length");
        self.emit_stack_load("t4", var.id * 8);
        self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, 4);

        self.emit_stack_load("t1", size_offset);
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t0, t2");
        self.emit("addi t3, t3, 4");
        self.emit("sub t2, t1, t3");
        let size_ok = self.fresh_label("molecule_vector_size_ok");
        self.emit(format!("beqz t2, {}", size_ok));
        self.emit_fail(CellScriptRuntimeError::BoundsCheckFailed);
        self.emit_label(&size_ok);
        true
    }

    /// Try to obtain the size offset for a dynamically-sized operand.
    pub(super) fn dynamic_length_from_size_offset(&self, operand: &IrOperand) -> Option<usize> {
        let IrOperand::Var(var) = operand else {
            return None;
        };
        // Check schema pointer size offsets (named-type params, consumed inputs, read_refs)
        if let Some(size_offset) = self.schema_pointer_size_offsets.get(&var.id).copied() {
            return Some(size_offset);
        }
        // Check fixed-byte param size offsets
        if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&var.id).copied() {
            return Some(size_offset);
        }
        // Check cell buffer size offsets (consumed inputs, read_refs, type_hash)
        if let Some(size_offset) = self.cell_buffer_size_offsets.get(&var.id).copied() {
            return Some(size_offset);
        }
        None
    }

    pub(super) fn emit_type_hash(&mut self, dest: &IrVar, operand: &IrOperand) -> Result<()> {
        if let Some((source, output_index)) = self.output_type_hash_sources.get(&dest.id).copied() {
            let Some(size_offset) = self.cell_buffer_size_offsets.get(&dest.id).copied() else {
                return Ok(());
            };
            let Some(buffer_offset) = self.cell_buffer_offsets.get(&dest.id).copied() else {
                return Ok(());
            };
            self.emit("# type_hash");
            self.emit_operand_comment("type_hash source", operand);
            self.emit_load_cell_by_field_syscall_to_offsets(
                "output_type_hash",
                source,
                output_index,
                CKB_CELL_FIELD_TYPE_HASH,
                size_offset,
                buffer_offset,
                32,
            );
            self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
            self.emit_loaded_schema_exact_size_check(size_offset, 32, "output type hash");
            self.emit_sp_addi("t0", buffer_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(());
        }
        if self.emit_runtime_type_hash(dest, operand) {
            return Ok(());
        }
        if let Some(param_id) = self.param_type_hash_sources.get(&dest.id).copied() {
            let Some(pointer_offset) = self.param_type_hash_pointer_offsets.get(&param_id).copied() else {
                return Ok(());
            };
            let Some(size_offset) = self.param_type_hash_size_offsets.get(&param_id).copied() else {
                return Ok(());
            };
            self.emit("# type_hash");
            self.emit_operand_comment("type_hash source", operand);
            self.emit_loaded_schema_exact_size_check(size_offset, 32, "param type hash");
            self.emit_stack_load("t0", pointer_offset);
            self.emit_stack_store("t0", dest.id * 8);
            return Ok(());
        }

        self.emit("# type_hash (unresolved)");
        self.emit("# cellscript abi: fail closed because type_hash source cell cannot be determined");
        self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
        Ok(())
    }

    /// Runtime type_hash: try to load the type hash from a cell identified by the operand's
    /// association with a consumed input, created output, or read_ref cell dep.
    fn emit_runtime_type_hash(&mut self, dest: &IrVar, operand: &IrOperand) -> bool {
        let Some((source, index)) = self.operand_cell_location(operand) else {
            return false;
        };

        let size_offset = self.cell_buffer_size_offsets.get(&dest.id).copied().unwrap_or_else(|| self.runtime_scratch_size_offset());
        let buffer_offset = self.cell_buffer_offsets.get(&dest.id).copied().unwrap_or_else(|| self.runtime_scratch_buffer_offset());

        self.emit("# type_hash");
        self.emit_operand_comment("type_hash source", operand);
        self.emit_load_cell_by_field_syscall_to_offsets(
            "runtime_type_hash",
            source,
            index,
            CKB_CELL_FIELD_TYPE_HASH,
            size_offset,
            buffer_offset,
            32,
        );
        self.emit_return_on_syscall_error(CellScriptRuntimeError::SyscallFailed);
        self.emit_loaded_schema_exact_size_check(size_offset, 32, "runtime type hash");
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    pub(super) fn emit_collection_new(&mut self, dest: &IrVar, ty: &str, capacity: Option<&IrOperand>) -> Result<()> {
        // Stack-allocated collection: the stack slot stores a pointer to the
        // collection buffer area, with the length word immediately before the buffer.
        // Layout: [length: u64][buffer: RUNTIME_COLLECTION_BUFFER_SIZE bytes]
        // We allocate space in the stack frame and initialize length to 0.
        let collection_slot_size = 8 + RUNTIME_COLLECTION_BUFFER_SIZE;
        let length_offset = self.collection_region_start + collection_slot_size * self.next_collection_slot;
        let buffer_offset = length_offset + 8;

        self.emit(format!("# collection new {}", ty));
        self.emit(format!(
            "# cellscript abi: stack collection buffer_offset={} max_size={}",
            buffer_offset, RUNTIME_COLLECTION_BUFFER_SIZE
        ));
        if let Some(capacity) = capacity {
            self.emit("# cellscript abi: stack collection with_capacity uses fixed backing buffer");
            self.emit_operand_comment("capacity", capacity);
        }

        // Initialize length to 0
        self.emit_stack_store("zero", length_offset);
        self.emit_sp_addi("t0", buffer_offset);
        self.emit_stack_store("t0", dest.id * 8);
        self.empty_molecule_vector_vars.insert(dest.id);
        self.stack_collection_vars.insert(dest.id);
        self.next_collection_slot += 1;
        Ok(())
    }

    pub(super) fn emit_collection_capacity(&mut self, dest: &IrVar, collection: &IrOperand) -> Result<()> {
        self.emit("# collection capacity");
        self.emit_operand_comment("collection", collection);
        if self.emit_stack_collection_capacity(dest, collection) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection capacity is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_capacity(&mut self, dest: &IrVar, collection: &IrOperand) -> bool {
        if dest.ty != IrType::U64 {
            return false;
        }
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        if element_width == 0 {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection capacity element_size={}", element_width));
        self.emit(format!("li t0, {}", RUNTIME_COLLECTION_BUFFER_SIZE / element_width));
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    pub(super) fn emit_collection_push(&mut self, collection: &IrOperand, value: &IrOperand) -> Result<()> {
        self.emit("# collection push");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("value", value);
        if matches!(value, IrOperand::Var(var) if self.verified_collection_push_values.contains(&var.id)) {
            self.emit("# cellscript abi: collection push is covered by mutate append verifier");
            return Ok(());
        }
        if matches!(collection, IrOperand::Var(var) if self.verified_collection_construction_vectors.contains(&var.id)) {
            self.emit("# cellscript abi: collection push is covered by create-output vector verifier");
            return Ok(());
        }
        if self.emit_stack_collection_push(collection, value) {
            return Ok(());
        }
        // In the verifier context, collection push is used for building output data.
        // The verifier doesn't need to actually build the data; it needs to verify
        // that the output cell data matches expectations. The collection operations
        // in the verifier body are vestigial from the source-level specification.
        // For now, emit a fail-closed trap because runtime collection mutation is not
        // needed in the verifier path – the prelude already verified the output.
        self.emit("# cellscript abi: collection push is not needed for verifier execution");
        self.emit("# cellscript abi: if this path is reached, the source program uses dynamic collections");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_push(&mut self, collection: &IrOperand, value: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(width) = self.constructed_byte_vector_part_width(value) else {
            return false;
        };
        if width > RUNTIME_COLLECTION_BUFFER_SIZE {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection push element_size={}", width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit(format!("li t1, {}", width));
        self.emit("mul t2, t0, t1");
        self.emit(format!("li t3, {}", RUNTIME_COLLECTION_BUFFER_SIZE));
        self.emit("sub t5, t3, t2");
        self.emit("sltu t5, t5, t1");
        let capacity_ok = self.fresh_label("stack_collection_push_capacity_ok");
        self.emit(format!("beqz t5, {}", capacity_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&capacity_ok);

        self.emit("add t5, t4, t2");
        if width <= 8 && fixed_scalar_operand_width(value).is_some() {
            self.emit_operand_to_register("t1", value);
            match width {
                1 => self.emit("sb t1, 0(t5)"),
                2 => self.emit("sh t1, 0(t5)"),
                4 => self.emit("sw t1, 0(t5)"),
                8 => self.emit("sd t1, 0(t5)"),
                _ => return false,
            }
        } else {
            let Some(source) = self.expected_fixed_byte_source(value, width) else {
                return false;
            };
            self.emit_prepare_fixed_byte_source(&source, width, "stack collection push");
            self.emit(format!("# cellscript abi: stack collection copy fixed bytes size={}", width));
            for byte_index in 0..width {
                self.emit_fixed_byte_source_byte_to("t1", "t6", &source, byte_index);
                self.emit_stack_load("t4", collection.id * 8);
                self.emit("ld t0, -8(t4)");
                self.emit(format!("li t2, {}", width));
                self.emit("mul t2, t0, t2");
                self.emit("add t4, t4, t2");
                if byte_index <= 2047 {
                    self.emit(format!("sb t1, {}(t4)", byte_index));
                } else {
                    self.emit_large_addi("t0", "t4", byte_index as i64);
                    self.emit("sb t1, 0(t0)");
                }
            }
        }
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit("addi t0, t0, 1");
        self.emit("sd t0, -8(t4)");
        true
    }

    pub(super) fn emit_collection_extend(&mut self, collection: &IrOperand, slice: &IrOperand) -> Result<()> {
        self.emit("# collection extend_from_slice");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("slice", slice);
        if matches!(collection, IrOperand::Var(var) if self.verified_collection_construction_vectors.contains(&var.id)) {
            self.emit("# cellscript abi: collection extend is covered by create-output vector verifier");
            return Ok(());
        }
        if self.emit_stack_collection_extend(collection, slice) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection extend is not needed for verifier execution");
        self.emit("# cellscript abi: if this path is reached, the source program uses dynamic collections");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_extend(&mut self, collection: &IrOperand, slice: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(width) = operand_fixed_byte_width(slice) else {
            return false;
        };
        let element_width =
            molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).unwrap_or(1);
        if element_width == 0 || width % element_width != 0 {
            return false;
        }
        let element_count = width / element_width;
        if width > RUNTIME_COLLECTION_BUFFER_SIZE {
            return false;
        }
        let Some(source) = self.expected_fixed_byte_source(slice, width) else {
            return false;
        };

        self.emit(format!(
            "# cellscript abi: stack collection extend bytes={} elements={} element_size={}",
            width, element_count, element_width
        ));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit(format!("li t1, {}", element_width));
        self.emit("mul t2, t0, t1");
        self.emit(format!("li t3, {}", RUNTIME_COLLECTION_BUFFER_SIZE));
        self.emit("sub t5, t3, t2");
        self.emit(format!("li t1, {}", width));
        self.emit("sltu t5, t5, t1");
        let capacity_ok = self.fresh_label("stack_collection_extend_capacity_ok");
        self.emit(format!("beqz t5, {}", capacity_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&capacity_ok);

        self.emit_prepare_fixed_byte_source(&source, width, "stack collection extend");
        self.emit(format!("# cellscript abi: stack collection extend copy fixed bytes size={}", width));
        for byte_index in 0..width {
            self.emit_fixed_byte_source_byte_to("t1", "t6", &source, byte_index);
            self.emit_stack_load("t4", collection.id * 8);
            self.emit("ld t0, -8(t4)");
            self.emit(format!("li t2, {}", element_width));
            self.emit("mul t2, t0, t2");
            self.emit("add t4, t4, t2");
            if byte_index <= 2047 {
                self.emit(format!("sb t1, {}(t4)", byte_index));
            } else {
                self.emit_large_addi("t0", "t4", byte_index as i64);
                self.emit("sb t1, 0(t0)");
            }
        }
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit(format!("addi t0, t0, {}", element_count));
        self.emit("sd t0, -8(t4)");
        true
    }

    pub(super) fn emit_collection_clear(&mut self, collection: &IrOperand) -> Result<()> {
        self.emit("# collection clear");
        self.emit_operand_comment("collection", collection);
        if matches!(collection, IrOperand::Var(var) if self.verified_collection_construction_vectors.contains(&var.id)) {
            self.emit("# cellscript abi: collection clear is covered by create-output vector verifier");
            return Ok(());
        }
        if self.emit_stack_collection_clear(collection) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection clear is not needed for verifier execution");
        self.emit("# cellscript abi: if this path is reached, the source program uses dynamic collections");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_clear(&mut self, collection: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        self.emit("# cellscript abi: stack collection clear");
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("sd zero, -8(t4)");
        true
    }

    pub(super) fn emit_collection_reverse(&mut self, collection: &IrOperand) -> Result<()> {
        self.emit("# collection reverse");
        self.emit_operand_comment("collection", collection);
        if self.emit_stack_collection_reverse(collection) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection reverse is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_reverse(&mut self, collection: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        if element_width == 0 || element_width > RUNTIME_COLLECTION_BUFFER_SIZE {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection reverse element_size={}", element_width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        let done_label = self.fresh_label("stack_collection_reverse_done");
        self.emit("li t1, 2");
        self.emit("sltu t2, t0, t1");
        self.emit(format!("bnez t2, {}", done_label));

        let left_offset = self.runtime_expr_temp_offset(0);
        let right_offset = self.runtime_expr_temp_offset(1);
        self.emit_stack_store("zero", left_offset);
        self.emit("addi t0, t0, -1");
        self.emit_stack_store("t0", right_offset);

        let loop_label = self.fresh_label("stack_collection_reverse_loop");
        self.emit_label(&loop_label);
        self.emit_stack_load("t0", left_offset);
        self.emit_stack_load("t1", right_offset);
        self.emit("sltu t2, t0, t1");
        self.emit(format!("beqz t2, {}", done_label));

        self.emit_stack_load("t4", collection.id * 8);
        self.emit(format!("li t3, {}", element_width));
        self.emit("mul t5, t0, t3");
        self.emit("add t5, t4, t5");
        self.emit("mul t6, t1, t3");
        self.emit("add t6, t4, t6");
        self.emit(format!("# cellscript abi: stack collection reverse swap element_size={}", element_width));
        for byte_index in 0..element_width {
            if byte_index <= 2047 {
                self.emit(format!("lbu t0, {}(t5)", byte_index));
                self.emit(format!("lbu t1, {}(t6)", byte_index));
                self.emit(format!("sb t1, {}(t5)", byte_index));
                self.emit(format!("sb t0, {}(t6)", byte_index));
            } else {
                self.emit_large_addi("t2", "t5", byte_index as i64);
                self.emit_large_addi("t3", "t6", byte_index as i64);
                self.emit("lbu t0, 0(t2)");
                self.emit("lbu t1, 0(t3)");
                self.emit("sb t1, 0(t2)");
                self.emit("sb t0, 0(t3)");
            }
        }
        self.emit_stack_load("t0", left_offset);
        self.emit("addi t0, t0, 1");
        self.emit_stack_store("t0", left_offset);
        self.emit_stack_load("t1", right_offset);
        self.emit("addi t1, t1, -1");
        self.emit_stack_store("t1", right_offset);
        self.emit(format!("j {}", loop_label));
        self.emit_label(&done_label);
        true
    }

    pub(super) fn emit_collection_truncate(&mut self, collection: &IrOperand, len: &IrOperand) -> Result<()> {
        self.emit("# collection truncate");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("len", len);
        if self.emit_stack_collection_truncate(collection, len) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection truncate is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_truncate(&mut self, collection: &IrOperand, len: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }

        self.emit("# cellscript abi: stack collection truncate");
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", len);
        let done_label = self.fresh_label("stack_collection_truncate_done");
        self.emit("sltu t2, t0, t1");
        self.emit(format!("bnez t2, {}", done_label));
        self.emit("sd t1, -8(t4)");
        self.emit_label(&done_label);
        true
    }

    pub(super) fn emit_collection_swap(&mut self, collection: &IrOperand, left: &IrOperand, right: &IrOperand) -> Result<()> {
        self.emit("# collection swap");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("left", left);
        self.emit_operand_comment("right", right);
        if self.emit_stack_collection_swap(collection, left, right) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection swap is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_swap(&mut self, collection: &IrOperand, left: &IrOperand, right: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        if element_width == 0 || element_width > RUNTIME_COLLECTION_BUFFER_SIZE {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection swap element_size={}", element_width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", left);
        self.emit_operand_to_register("t2", right);

        let left_ok = self.fresh_label("stack_collection_swap_left_ok");
        self.emit("sltu t3, t1, t0");
        self.emit(format!("bnez t3, {}", left_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&left_ok);

        let right_ok = self.fresh_label("stack_collection_swap_right_ok");
        self.emit("sltu t3, t2, t0");
        self.emit(format!("bnez t3, {}", right_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&right_ok);

        self.emit(format!("li t3, {}", element_width));
        self.emit("mul t5, t1, t3");
        self.emit("add t5, t4, t5");
        self.emit("mul t6, t2, t3");
        self.emit("add t6, t4, t6");
        self.emit(format!("# cellscript abi: stack collection swap bytes element_size={}", element_width));
        for byte_index in 0..element_width {
            if byte_index <= 2047 {
                self.emit(format!("lbu t0, {}(t5)", byte_index));
                self.emit(format!("lbu t1, {}(t6)", byte_index));
                self.emit(format!("sb t1, {}(t5)", byte_index));
                self.emit(format!("sb t0, {}(t6)", byte_index));
            } else {
                self.emit_large_addi("t2", "t5", byte_index as i64);
                self.emit_large_addi("t3", "t6", byte_index as i64);
                self.emit("lbu t0, 0(t2)");
                self.emit("lbu t1, 0(t3)");
                self.emit("sb t1, 0(t2)");
                self.emit("sb t0, 0(t3)");
            }
        }
        true
    }

    pub(super) fn emit_collection_contains(&mut self, dest: &IrVar, collection: &IrOperand, value: &IrOperand) -> Result<()> {
        self.emit("# collection contains");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("value", value);
        if self.emit_stack_collection_contains(dest, collection, value) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection contains is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_contains(&mut self, dest: &IrVar, collection: &IrOperand, value: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(value_width) = self.constructed_byte_vector_part_width(value) else {
            return false;
        };
        let element_width =
            molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).unwrap_or(value_width);
        if element_width == 0 || element_width != value_width {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection contains element_size={}", element_width));
        let index_offset = self.runtime_expr_temp_offset(0);
        self.emit_stack_store("zero", index_offset);
        self.emit_stack_store("zero", dest.id * 8);
        let loop_label = self.fresh_label("stack_collection_contains_loop");
        let next_label = self.fresh_label("stack_collection_contains_next");
        let found_label = self.fresh_label("stack_collection_contains_found");
        let done_label = self.fresh_label("stack_collection_contains_done");
        self.emit_label(&loop_label);
        self.emit_stack_load("t1", index_offset);
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t2, -8(t4)");
        self.emit(format!("beq t1, t2, {}", done_label));

        if element_width <= 8 && fixed_scalar_operand_width(value).is_some() {
            self.emit(format!("li t2, {}", element_width));
            self.emit("mul t3, t1, t2");
            self.emit("add t4, t4, t3");
            self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, element_width);
            self.emit_operand_to_register("t5", value);
            self.emit("sub t6, t0, t5");
            self.emit(format!("beqz t6, {}", found_label));
        } else {
            let Some(source) = self.expected_fixed_byte_source(value, element_width) else {
                return false;
            };
            self.emit_prepare_fixed_byte_source(&source, element_width, "stack collection contains");
            for byte_index in 0..element_width {
                self.emit_stack_load("t1", index_offset);
                self.emit_stack_load("t4", collection.id * 8);
                self.emit(format!("li t2, {}", element_width));
                self.emit("mul t3, t1, t2");
                self.emit("add t4, t4, t3");
                if byte_index <= 2047 {
                    self.emit(format!("lbu t0, {}(t4)", byte_index));
                } else {
                    self.emit_large_addi("t2", "t4", byte_index as i64);
                    self.emit("lbu t0, 0(t2)");
                }
                self.emit_fixed_byte_source_byte_to("t5", "t6", &source, byte_index);
                self.emit("sub t0, t0, t5");
                self.emit(format!("bnez t0, {}", next_label));
            }
            self.emit(format!("j {}", found_label));
        }

        self.emit_label(&next_label);
        self.emit_stack_load("t1", index_offset);
        self.emit("addi t1, t1, 1");
        self.emit_stack_store("t1", index_offset);
        self.emit(format!("j {}", loop_label));
        self.emit_label(&found_label);
        self.emit("li t0, 1");
        self.emit_stack_store("t0", dest.id * 8);
        self.emit_label(&done_label);
        true
    }

    pub(super) fn emit_collection_remove(&mut self, dest: &IrVar, collection: &IrOperand, index: &IrOperand) -> Result<()> {
        self.emit("# collection remove");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("index", index);
        if self.emit_stack_collection_remove(dest, collection, index) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection remove is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_remove(&mut self, dest: &IrVar, collection: &IrOperand, index: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        let dest_scalar = fixed_scalar_width(&dest.ty, Some(element_width)).is_some();
        let dest_fixed_bytes = self.fixed_byte_like_width(&dest.ty).is_some_and(|width| width == element_width);
        if !dest_scalar && !dest_fixed_bytes {
            return false;
        }
        let removed_value_slots = if dest_fixed_bytes { element_width.div_ceil(8) } else { 0 };
        if dest_fixed_bytes && removed_value_slots + 1 > RUNTIME_EXPR_TEMP_SLOTS {
            return false;
        }
        let Some(index_offset) = self.checked_runtime_expr_temp_offset(removed_value_slots) else {
            return false;
        };

        self.emit(format!("# cellscript abi: stack collection remove element_size={}", element_width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", index);

        let bounds_ok = self.fresh_label("stack_collection_remove_bounds_ok");
        self.emit("sltu t2, t1, t0");
        self.emit(format!("bnez t2, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&bounds_ok);

        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t1, t2");
        self.emit("add t5, t4, t3");
        if dest_scalar {
            self.emit_unaligned_scalar_load("t5", "t6", "t2", 0, element_width);
            self.emit_stack_store("t6", dest.id * 8);
        } else {
            let removed_offset = self.runtime_expr_temp_offset(0);
            self.emit(format!("# cellscript abi: stack collection remove snapshot fixed bytes size={}", element_width));
            for byte_index in 0..element_width {
                if byte_index <= 2047 {
                    self.emit(format!("lbu t6, {}(t5)", byte_index));
                } else {
                    self.emit_large_addi("t2", "t5", byte_index as i64);
                    self.emit("lbu t6, 0(t2)");
                }
                self.emit_sp_addi("t2", removed_offset + byte_index);
                self.emit("sb t6, 0(t2)");
            }
            self.emit_sp_addi("t6", removed_offset);
            self.emit_stack_store("t6", dest.id * 8);
        }

        self.emit_stack_store("t1", index_offset);
        let shift_loop = self.fresh_label("stack_collection_remove_shift_loop");
        let shift_done = self.fresh_label("stack_collection_remove_shift_done");
        self.emit(format!("# cellscript abi: stack collection remove shift element_size={}", element_width));
        self.emit_label(&shift_loop);
        self.emit_stack_load("t1", index_offset);
        self.emit("addi t2, t1, 1");
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit("sltu t3, t2, t0");
        self.emit(format!("beqz t3, {}", shift_done));
        self.emit(format!("li t3, {}", element_width));
        self.emit("mul t5, t1, t3");
        self.emit("add t5, t4, t5");
        self.emit("mul t6, t2, t3");
        self.emit("add t6, t4, t6");
        for byte_index in 0..element_width {
            if byte_index <= 2047 {
                self.emit(format!("lbu t0, {}(t6)", byte_index));
                self.emit(format!("sb t0, {}(t5)", byte_index));
            } else {
                self.emit_large_addi("t0", "t6", byte_index as i64);
                self.emit("lbu t0, 0(t0)");
                self.emit_large_addi("t2", "t5", byte_index as i64);
                self.emit("sb t0, 0(t2)");
            }
        }
        self.emit_stack_load("t1", index_offset);
        self.emit("addi t1, t1, 1");
        self.emit_stack_store("t1", index_offset);
        self.emit(format!("j {}", shift_loop));
        self.emit_label(&shift_done);
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit("addi t0, t0, -1");
        self.emit("sd t0, -8(t4)");
        true
    }

    pub(super) fn emit_collection_pop(&mut self, dest: &IrVar, collection: &IrOperand) -> Result<()> {
        self.emit("# collection pop");
        self.emit_operand_comment("collection", collection);
        if self.emit_stack_collection_pop(dest, collection) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection pop is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_pop(&mut self, dest: &IrVar, collection: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        let dest_scalar = fixed_scalar_width(&dest.ty, Some(element_width)).is_some();
        let dest_fixed_bytes = self.fixed_byte_like_width(&dest.ty).is_some_and(|width| width == element_width);
        if !dest_scalar && !dest_fixed_bytes {
            return false;
        }

        self.emit(format!("# cellscript abi: stack collection pop element_size={}", element_width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        let bounds_ok = self.fresh_label("stack_collection_pop_bounds_ok");
        self.emit(format!("bnez t0, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&bounds_ok);

        self.emit("addi t1, t0, -1");
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t1, t2");
        self.emit("add t5, t4, t3");
        if dest_scalar {
            self.emit_unaligned_scalar_load("t5", "t6", "t2", 0, element_width);
            self.emit_stack_store("t6", dest.id * 8);
        } else {
            self.emit("# cellscript abi: stack collection pop fixed bytes");
            self.emit_stack_store("t5", dest.id * 8);
        }
        self.emit("sd t1, -8(t4)");
        true
    }

    pub(super) fn emit_collection_insert(&mut self, collection: &IrOperand, index: &IrOperand, value: &IrOperand) -> Result<()> {
        self.emit("# collection insert");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("index", index);
        self.emit_operand_comment("value", value);
        if self.emit_stack_collection_insert(collection, index, value) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection insert is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_insert(&mut self, collection: &IrOperand, index: &IrOperand, value: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(value_width) = self.constructed_byte_vector_part_width(value) else {
            return false;
        };
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        if element_width != value_width {
            return false;
        }
        let value_scalar = element_width <= 8 && fixed_scalar_operand_width(value).is_some();
        let fixed_byte_source = if value_scalar {
            None
        } else {
            if element_width > (RUNTIME_EXPR_TEMP_SLOTS - 2) * 8 {
                return false;
            }
            let Some(source) = self.expected_fixed_byte_source(value, element_width) else {
                return false;
            };
            Some(source)
        };

        self.emit(format!("# cellscript abi: stack collection insert element_size={}", element_width));
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", index);

        let bounds_ok = self.fresh_label("stack_collection_insert_bounds_ok");
        self.emit("sltu t2, t0, t1");
        self.emit(format!("beqz t2, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&bounds_ok);

        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t0, t2");
        self.emit(format!("li t5, {}", RUNTIME_COLLECTION_BUFFER_SIZE));
        self.emit("sub t6, t5, t3");
        self.emit("sltu t6, t6, t2");
        let capacity_ok = self.fresh_label("stack_collection_insert_capacity_ok");
        self.emit(format!("beqz t6, {}", capacity_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&capacity_ok);

        let index_offset = self.runtime_expr_temp_offset(0);
        let current_offset = self.runtime_expr_temp_offset(1);
        self.emit_stack_store("t1", index_offset);
        self.emit_stack_store("t0", current_offset);
        if let Some(source) = fixed_byte_source.as_ref() {
            self.emit_prepare_fixed_byte_source(source, element_width, "stack collection insert");
            let value_offset = self.runtime_expr_temp_offset(2);
            self.emit(format!("# cellscript abi: stack collection insert snapshot fixed bytes size={}", element_width));
            for byte_index in 0..element_width {
                self.emit_fixed_byte_source_byte_to("t1", "t6", source, byte_index);
                self.emit_sp_addi("t6", value_offset + byte_index);
                self.emit("sb t1, 0(t6)");
            }
        }
        let shift_loop = self.fresh_label("stack_collection_insert_shift_loop");
        let shift_done = self.fresh_label("stack_collection_insert_shift_done");
        self.emit(format!("# cellscript abi: stack collection insert shift element_size={}", element_width));
        self.emit_label(&shift_loop);
        self.emit_stack_load("t0", current_offset);
        self.emit_stack_load("t1", index_offset);
        self.emit(format!("beq t0, t1, {}", shift_done));
        self.emit("addi t2, t0, -1");
        self.emit_stack_load("t4", collection.id * 8);
        self.emit(format!("li t3, {}", element_width));
        self.emit("mul t5, t0, t3");
        self.emit("add t5, t4, t5");
        self.emit("mul t6, t2, t3");
        self.emit("add t6, t4, t6");
        if element_width <= 8 {
            self.emit_unaligned_scalar_load("t6", "t0", "t2", 0, element_width);
            match element_width {
                1 => self.emit("sb t0, 0(t5)"),
                2 => self.emit("sh t0, 0(t5)"),
                4 => self.emit("sw t0, 0(t5)"),
                8 => self.emit("sd t0, 0(t5)"),
                _ => return false,
            }
        } else {
            for byte_index in 0..element_width {
                if byte_index <= 2047 {
                    self.emit(format!("lbu t0, {}(t6)", byte_index));
                    self.emit(format!("sb t0, {}(t5)", byte_index));
                } else {
                    self.emit_large_addi("t0", "t6", byte_index as i64);
                    self.emit("lbu t0, 0(t0)");
                    self.emit_large_addi("t2", "t5", byte_index as i64);
                    self.emit("sb t0, 0(t2)");
                }
            }
        }
        self.emit_stack_load("t0", current_offset);
        self.emit("addi t0, t0, -1");
        self.emit_stack_store("t0", current_offset);
        self.emit(format!("j {}", shift_loop));
        self.emit_label(&shift_done);

        self.emit_stack_load("t4", collection.id * 8);
        self.emit_stack_load("t0", index_offset);
        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t0, t2");
        self.emit("add t5, t4, t3");
        if value_scalar {
            self.emit_operand_to_register("t1", value);
            match element_width {
                1 => self.emit("sb t1, 0(t5)"),
                2 => self.emit("sh t1, 0(t5)"),
                4 => self.emit("sw t1, 0(t5)"),
                8 => self.emit("sd t1, 0(t5)"),
                _ => return false,
            }
        } else {
            let value_offset = self.runtime_expr_temp_offset(2);
            self.emit(format!("# cellscript abi: stack collection insert copy fixed bytes size={}", element_width));
            for byte_index in 0..element_width {
                self.emit_sp_addi("t6", value_offset + byte_index);
                self.emit("lbu t1, 0(t6)");
                if byte_index <= 2047 {
                    self.emit(format!("sb t1, {}(t5)", byte_index));
                } else {
                    self.emit_large_addi("t0", "t5", byte_index as i64);
                    self.emit("sb t1, 0(t0)");
                }
            }
        }
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit("addi t0, t0, 1");
        self.emit("sd t0, -8(t4)");
        true
    }

    pub(super) fn emit_collection_set(&mut self, collection: &IrOperand, index: &IrOperand, value: &IrOperand) -> Result<()> {
        self.emit("# collection set");
        self.emit_operand_comment("collection", collection);
        self.emit_operand_comment("index", index);
        self.emit_operand_comment("value", value);
        if self.emit_stack_collection_set(collection, index, value) {
            return Ok(());
        }
        self.emit("# cellscript abi: collection set is not available for this collection");
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        Ok(())
    }

    fn emit_stack_collection_set(&mut self, collection: &IrOperand, index: &IrOperand, value: &IrOperand) -> bool {
        let IrOperand::Var(collection) = collection else {
            return false;
        };
        if !self.stack_collection_vars.contains(&collection.id) {
            return false;
        }
        let Some(value_width) = self.constructed_byte_vector_part_width(value) else {
            return false;
        };
        let Some(element_width) = molecule_vector_element_fixed_width(&collection.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes)
        else {
            return false;
        };
        if element_width == 0 || element_width > RUNTIME_COLLECTION_BUFFER_SIZE || element_width != value_width {
            return false;
        }
        let value_scalar = element_width <= 8 && fixed_scalar_operand_width(value).is_some();
        let fixed_byte_source = if value_scalar {
            None
        } else {
            let Some(source) = self.expected_fixed_byte_source(value, element_width) else {
                return false;
            };
            Some(source)
        };

        self.emit(format!("# cellscript abi: stack collection set element_size={}", element_width));
        if let Some(source) = fixed_byte_source.as_ref() {
            self.emit_prepare_fixed_byte_source(source, element_width, "stack collection set");
        }
        self.emit_stack_load("t4", collection.id * 8);
        self.emit("ld t0, -8(t4)");
        self.emit_operand_to_register("t1", index);

        let bounds_ok = self.fresh_label("stack_collection_set_bounds_ok");
        self.emit("sltu t2, t1, t0");
        self.emit(format!("bnez t2, {}", bounds_ok));
        self.emit_fail(CellScriptRuntimeError::CollectionBoundsInvalid);
        self.emit_label(&bounds_ok);

        self.emit(format!("li t2, {}", element_width));
        self.emit("mul t3, t1, t2");
        self.emit("add t5, t4, t3");
        if value_scalar {
            self.emit_operand_to_register("t1", value);
            match element_width {
                1 => self.emit("sb t1, 0(t5)"),
                2 => self.emit("sh t1, 0(t5)"),
                4 => self.emit("sw t1, 0(t5)"),
                8 => self.emit("sd t1, 0(t5)"),
                _ => return false,
            }
        } else {
            let source = fixed_byte_source.as_ref().expect("fixed byte source");
            self.emit(format!("# cellscript abi: stack collection set copy fixed bytes size={}", element_width));
            for byte_index in 0..element_width {
                self.emit_fixed_byte_source_byte_to("t1", "t6", source, byte_index);
                if byte_index <= 2047 {
                    self.emit(format!("sb t1, {}(t5)", byte_index));
                } else {
                    self.emit_large_addi("t0", "t5", byte_index as i64);
                    self.emit("sb t1, 0(t0)");
                }
            }
        }
        true
    }
}
