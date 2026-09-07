use super::*;

impl CodeGenerator {
    pub(super) fn emit_load_const(&mut self, dest: &IrVar, value: &IrConst) -> Result<()> {
        if dest.ty == IrType::U128 {
            self.emit_materialize_u128_operand_to_var(dest, &IrOperand::Const(value.clone()));
            return Ok(());
        }
        match value {
            IrConst::Unit => self.emit("li t0, 0"),
            IrConst::U8(n) => self.emit(format!("li t0, {}", n)),
            IrConst::U16(n) => self.emit(format!("li t0, {}", n)),
            IrConst::U32(n) => self.emit(format!("li t0, {}", n)),
            IrConst::U64(n) => self.emit(format!("li t0, {}", n)),
            IrConst::U128(value) => {
                if let Some(offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() {
                    self.emit_store_const_bytes_to_stack(&value.to_le_bytes(), offset);
                    self.emit_sp_addi("t0", offset);
                    self.emit_stack_store("t0", dest.id * 8);
                    return Ok(());
                }
                let label = self.const_data_label_for_bytes(value.to_le_bytes().to_vec());
                self.emit(format!("la t0, {}", label));
            }
            IrConst::Bool(b) => self.emit(format!("li t0, {}", if *b { 1 } else { 0 })),
            IrConst::Address(_) | IrConst::Hash(_) | IrConst::Array(_) => {
                let Some(bytes) = fixed_byte_const_bytes(value) else {
                    self.emit("# cellscript abi: fail closed because fixed-byte constant bytes are not materializable");
                    self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                    self.emit("li t0, 0");
                    self.emit_stack_store("t0", dest.id * 8);
                    return Ok(());
                };
                let label = self.const_data_label_for_bytes(bytes);
                self.emit(format!("la t0, {}", label));
            }
        }
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    pub(super) fn emit_load_var(&mut self, dest: &IrVar, name: &str) -> Result<()> {
        self.emit(format!("# load var {}", name));
        let Some(offset) = self.named_var_offsets.get(name).copied() else {
            self.emit("# cellscript abi: fail closed because named variable slot was not allocated");
            self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
            return Ok(());
        };
        self.emit_stack_load("t0", offset);
        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    pub(super) fn emit_store_var(&mut self, name: &str, src: &IrOperand) -> Result<()> {
        self.emit(format!("# store var {}", name));
        let Some(offset) = self.named_var_offsets.get(name).copied() else {
            self.emit("# cellscript abi: fail closed because named variable slot was not allocated");
            self.emit_fail(CellScriptRuntimeError::ConsumeInvalidOperand);
            return Ok(());
        };
        self.emit_operand_to_register("t0", src);
        self.emit_stack_store("t0", offset);
        Ok(())
    }

    pub(super) fn emit_binary(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> Result<()> {
        if self.emit_u128_add_sub_with_u64(dest, op, left, right) {
            return Ok(());
        }
        if self.emit_u128_binary(dest, op, left, right) {
            return Ok(());
        }
        if matches!(op, BinaryOp::Eq | BinaryOp::Ne) && self.emit_dynamic_byte_comparison(dest, op, left, right) {
            return Ok(());
        }
        if matches!(op, BinaryOp::Eq | BinaryOp::Ne)
            && (operand_fixed_byte_width(left).is_some() || operand_fixed_byte_width(right).is_some())
        {
            if self.emit_fixed_byte_comparison(dest, op, left, right) {
                return Ok(());
            }
            if self.emit_generic_fixed_byte_comparison(dest, op, left, right) {
                return Ok(());
            }
            // Final fallback: emit a fail-closed trap with specific error code
            self.emit(format!("# binary {:?} over fixed-byte operands (unresolved)", op));
            self.emit("# cellscript abi: fail closed because fixed-byte operand sources are not available");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonMaterializationUnresolved);
            return Ok(());
        }

        if dest.ty == IrType::U128 || self.operand_is_u128(left) || self.operand_is_u128(right) {
            self.emit(format!("# binary {:?} over unsupported u128 operand shape", op));
            self.emit("# cellscript abi: fail closed because generic u128 arithmetic/comparison shape is not lowered");
            self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
            return Ok(());
        }

        // Both operands are already materialized by the typed IR at this
        // program point. Loading them directly avoids recursively rebuilding
        // expression provenance (which is reserved for prelude checks) and
        // avoids using the destination stack slot as a temporary.
        self.emit_operand_to_register("t0", left);
        self.emit_operand_to_register("t1", right);

        if matches!(op, BinaryOp::Div | BinaryOp::Mod) {
            let divisor_ok = self.fresh_label("scalar_divisor_nonzero");
            self.emit(format!("bnez t1, {}", divisor_ok));
            self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
            self.emit_label(&divisor_ok);
        }

        match op {
            BinaryOp::Add => self.emit("add t0, t0, t1"),
            BinaryOp::Sub => self.emit("sub t0, t0, t1"),
            BinaryOp::Mul => self.emit("mul t0, t0, t1"),
            BinaryOp::Div if binary_operands_signed_i32(left, right) => self.emit("div t0, t0, t1"),
            BinaryOp::Div => self.emit("divu t0, t0, t1"),
            BinaryOp::Mod if binary_operands_signed_i32(left, right) => self.emit("rem t0, t0, t1"),
            BinaryOp::Mod => self.emit("remu t0, t0, t1"),
            BinaryOp::Eq => {
                self.emit("sub t0, t0, t1");
                self.emit("seqz t0, t0");
            }
            BinaryOp::Ne => {
                self.emit("sub t0, t0, t1");
                self.emit("snez t0, t0");
            }
            BinaryOp::Lt if binary_operands_signed_i32(left, right) => self.emit("slt t0, t0, t1"),
            BinaryOp::Lt => self.emit("sltu t0, t0, t1"),
            BinaryOp::Le if binary_operands_signed_i32(left, right) => {
                self.emit("slt t0, t1, t0");
                self.emit("xori t0, t0, 1");
            }
            BinaryOp::Le => {
                self.emit("sltu t0, t1, t0");
                self.emit("xori t0, t0, 1");
            }
            BinaryOp::Gt if binary_operands_signed_i32(left, right) => self.emit("slt t0, t1, t0"),
            BinaryOp::Gt => self.emit("sltu t0, t1, t0"),
            BinaryOp::Ge if binary_operands_signed_i32(left, right) => {
                self.emit("slt t0, t0, t1");
                self.emit("xori t0, t0, 1");
            }
            BinaryOp::Ge => {
                self.emit("sltu t0, t0, t1");
                self.emit("xori t0, t0, 1");
            }
            BinaryOp::And => self.emit("and t0, t0, t1"),
            BinaryOp::Or => self.emit("or t0, t0, t1"),
            BinaryOp::BitAnd => self.emit("and t0, t0, t1"),
            BinaryOp::BitOr => self.emit("or t0, t0, t1"),
            BinaryOp::BitXor => self.emit("xor t0, t0, t1"),
            BinaryOp::Shl | BinaryOp::Shr => {
                let width = match dest.ty {
                    IrType::U8 => 8,
                    IrType::U16 => 16,
                    IrType::U32 | IrType::I32 => 32,
                    _ => 64,
                };
                let shift_ok = self.fresh_label("shift_amount_ok");
                self.emit(format!("li t2, {}", width));
                self.emit(format!("bltu t1, t2, {}", shift_ok));
                self.emit_fail(CellScriptRuntimeError::ShiftAmountInvalid);
                self.emit_label(&shift_ok);
                match op {
                    BinaryOp::Shl => self.emit("sll t0, t0, t1"),
                    BinaryOp::Shr if dest.ty == IrType::I32 => {
                        self.emit("slli t0, t0, 32");
                        self.emit("srai t0, t0, 32");
                        self.emit("sra t0, t0, t1");
                    }
                    BinaryOp::Shr => self.emit("srl t0, t0, t1"),
                    _ => unreachable!("shift operation only"),
                }
            }
        }

        match dest.ty {
            IrType::U8 => {
                self.emit("slli t0, t0, 56");
                self.emit("srli t0, t0, 56");
            }
            IrType::U16 => {
                self.emit("slli t0, t0, 48");
                self.emit("srli t0, t0, 48");
            }
            IrType::U32 => {
                self.emit("slli t0, t0, 32");
                self.emit("srli t0, t0, 32");
            }
            IrType::I32 => {
                self.emit("slli t0, t0, 32");
                self.emit("srai t0, t0, 32");
            }
            _ => {}
        }

        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    fn emit_u128_binary(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> bool {
        let arithmetic_u128 = dest.ty == IrType::U128 || self.operand_is_u128_like(left) || self.operand_is_u128_like(right);
        let comparison_u128 = matches!(op, BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge)
            && (self.operand_is_u128_like(left) || self.operand_is_u128_like(right));
        if !arithmetic_u128 && !comparison_u128 {
            return false;
        }

        match op {
            BinaryOp::Add | BinaryOp::Sub if dest.ty == IrType::U128 => {
                self.emit_u128_add_sub(dest, op, left, right);
                true
            }
            BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                self.emit_u128_compare(dest, op, left, right);
                true
            }
            BinaryOp::Mul if dest.ty == IrType::U128 => {
                self.emit_u128_mul(dest, left, right);
                true
            }
            BinaryOp::Div if dest.ty == IrType::U128 => {
                self.emit_u128_div(dest, left, right);
                true
            }
            BinaryOp::Mod if dest.ty == IrType::U128 => {
                self.emit_u128_mod(dest, left, right);
                true
            }
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor if dest.ty == IrType::U128 => {
                self.emit_u128_bitwise(dest, op, left, right);
                true
            }
            BinaryOp::Shl | BinaryOp::Shr if dest.ty == IrType::U128 => {
                self.emit_u128_shift(dest, op, left, right);
                true
            }
            BinaryOp::Add | BinaryOp::Sub if arithmetic_u128 => {
                self.emit(format!("# cellscript abi: u128 {:?} result is not materialized as u128; fail closed", op));
                self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
                true
            }
            _ => false,
        }
    }

    fn emit_u128_bitwise(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 bitwise destination has no storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return;
        };
        if !self.emit_u128_binary_operand_limbs(left, right, "u128 bitwise") {
            return;
        }
        let mnemonic = match op {
            BinaryOp::BitAnd => "and",
            BinaryOp::BitOr => "or",
            BinaryOp::BitXor => "xor",
            _ => unreachable!("u128 bitwise operation only"),
        };
        self.emit(format!("# cellscript abi: u128 bitwise {:?}", op));
        self.emit(format!("{} t4, t0, t2", mnemonic));
        self.emit(format!("{} t5, t1, t3", mnemonic));
        self.emit_stack_store("t4", dest_offset);
        self.emit_stack_store("t5", dest_offset + 8);
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
    }

    fn emit_u128_shift(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 shift destination has no storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return;
        };
        if !self.emit_u128_operand_limbs("t0", "t1", "t6", "t4", left, "u128 shift left") {
            return;
        }
        let left_low_offset = self.runtime_expr_temp_offset(0);
        let left_high_offset = self.runtime_expr_temp_offset(1);
        self.emit_stack_store("t0", left_low_offset);
        self.emit_stack_store("t1", left_high_offset);
        self.emit_expected_operand_to_t1(right);
        self.emit("addi t2, t1, 0");
        self.emit_stack_load("t0", left_low_offset);
        self.emit_stack_load("t1", left_high_offset);
        let amount_ok = self.fresh_label("u128_shift_amount_ok");
        let zero = self.fresh_label("u128_shift_zero");
        let under_64 = self.fresh_label("u128_shift_under_64");
        let at_least_64 = self.fresh_label("u128_shift_at_least_64");
        let store = self.fresh_label("u128_shift_store");
        self.emit("li t6, 128");
        self.emit(format!("bltu t2, t6, {}", amount_ok));
        self.emit_fail(CellScriptRuntimeError::ShiftAmountInvalid);
        self.emit_label(&amount_ok);
        self.emit(format!("beqz t2, {}", zero));
        self.emit("li t6, 64");
        self.emit(format!("bltu t2, t6, {}", under_64));
        self.emit(format!("j {}", at_least_64));

        self.emit_label(&zero);
        self.emit("addi t4, t0, 0");
        self.emit("addi t5, t1, 0");
        self.emit(format!("j {}", store));

        self.emit_label(&under_64);
        match op {
            BinaryOp::Shl => {
                self.emit("sll t4, t0, t2");
                self.emit("li t6, 64");
                self.emit("sub t6, t6, t2");
                self.emit("srl t6, t0, t6");
                self.emit("sll t5, t1, t2");
                self.emit("or t5, t5, t6");
            }
            BinaryOp::Shr => {
                self.emit("srl t4, t0, t2");
                self.emit("li t6, 64");
                self.emit("sub t6, t6, t2");
                self.emit("sll t6, t1, t6");
                self.emit("or t4, t4, t6");
                self.emit("srl t5, t1, t2");
            }
            _ => unreachable!("u128 shift operation only"),
        }
        self.emit(format!("j {}", store));

        self.emit_label(&at_least_64);
        self.emit("addi t6, t2, -64");
        match op {
            BinaryOp::Shl => {
                self.emit("li t4, 0");
                self.emit("sll t5, t0, t6");
            }
            BinaryOp::Shr => {
                self.emit("srl t4, t1, t6");
                self.emit("li t5, 0");
            }
            _ => unreachable!("u128 shift operation only"),
        }

        self.emit_label(&store);
        self.emit_stack_store("t4", dest_offset);
        self.emit_stack_store("t5", dest_offset + 8);
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
    }

    fn emit_u128_add_sub(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 arithmetic destination has no storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return;
        };
        if !self.emit_u128_binary_operand_limbs(left, right, "u128 arithmetic") {
            return;
        }
        let ok_label = self.fresh_label("u128_arithmetic_ok");
        let overflow_label = self.fresh_label("u128_arithmetic_overflow");
        match op {
            BinaryOp::Add => {
                self.emit("# cellscript abi: u128 add with carry");
                self.emit("add t4, t0, t2");
                self.emit("sltu t6, t4, t0");
                self.emit("add t5, t1, t3");
                self.emit("sltu a6, t5, t1");
                self.emit(format!("bnez a6, {}", overflow_label));
                self.emit("add t5, t5, t6");
                self.emit("sltu a6, t5, t6");
                self.emit(format!("bnez a6, {}", overflow_label));
            }
            BinaryOp::Sub => {
                self.emit("# cellscript abi: u128 sub with borrow");
                self.emit("sltu t6, t0, t2");
                self.emit("sltu a6, t1, t3");
                self.emit(format!("bnez a6, {}", overflow_label));
                self.emit("sub t4, t0, t2");
                self.emit("sub t5, t1, t3");
                self.emit(format!("beqz t6, {}", ok_label));
                self.emit(format!("beqz t5, {}", overflow_label));
                self.emit("addi t5, t5, -1");
            }
            _ => unreachable!("u128 add/sub only"),
        }
        self.emit_label(&ok_label);
        self.emit_stack_store("t4", dest_offset);
        self.emit_stack_store("t5", dest_offset + 8);
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
        let done_label = self.fresh_label("u128_arithmetic_done");
        self.emit(format!("j {}", done_label));
        self.emit_label(&overflow_label);
        self.emit_fail(CellScriptRuntimeError::AggregateAmountMismatch);
        self.emit_label(&done_label);
    }

    fn emit_u128_compare(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) {
        if !self.emit_u128_binary_operand_limbs(left, right, "u128 compare") {
            return;
        }
        self.emit("# cellscript abi: u128 compare high limb first");
        let high_lt = self.fresh_label("u128_compare_high_lt");
        let high_gt = self.fresh_label("u128_compare_high_gt");
        let same_high = self.fresh_label("u128_compare_same_high");
        let done = self.fresh_label("u128_compare_done");
        self.emit("sltu t4, t1, t3");
        self.emit(format!("bnez t4, {}", high_lt));
        self.emit("sltu t4, t3, t1");
        self.emit(format!("bnez t4, {}", high_gt));
        self.emit_label(&same_high);
        match op {
            BinaryOp::Eq => {
                self.emit("sub t4, t0, t2");
                self.emit("seqz t0, t4");
            }
            BinaryOp::Ne => {
                self.emit("sub t4, t0, t2");
                self.emit("snez t0, t4");
            }
            BinaryOp::Lt => self.emit("sltu t0, t0, t2"),
            BinaryOp::Le => {
                self.emit("sltu t0, t2, t0");
                self.emit("xori t0, t0, 1");
            }
            BinaryOp::Gt => self.emit("sltu t0, t2, t0"),
            BinaryOp::Ge => {
                self.emit("sltu t0, t0, t2");
                self.emit("xori t0, t0, 1");
            }
            _ => unreachable!("u128 compare only"),
        }
        self.emit(format!("j {}", done));
        self.emit_label(&high_lt);
        let high_lt_value = matches!(op, BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le);
        self.emit(format!("li t0, {}", u8::from(high_lt_value)));
        self.emit(format!("j {}", done));
        self.emit_label(&high_gt);
        let high_gt_value = matches!(op, BinaryOp::Ne | BinaryOp::Gt | BinaryOp::Ge);
        self.emit(format!("li t0, {}", u8::from(high_gt_value)));
        self.emit_label(&done);
        self.emit_stack_store("t0", dest.id * 8);
    }

    fn emit_u128_mul(&mut self, dest: &IrVar, left: &IrOperand, right: &IrOperand) {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 multiplication destination has no storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return;
        };
        if !self.emit_u128_binary_operand_limbs(left, right, "u128 multiplication") {
            return;
        }
        self.emit("# cellscript abi: checked u128 multiplication");
        let overflow_label = self.fresh_label("u128_mul_overflow");
        let high_left_zero = self.fresh_label("u128_mul_high_left_zero");
        let high_pair_ok = self.fresh_label("u128_mul_high_pair_ok");
        let done_label = self.fresh_label("u128_mul_done");

        self.emit(format!("beqz t1, {}", high_left_zero));
        self.emit(format!("bnez t3, {}", overflow_label));
        self.emit_label(&high_left_zero);
        self.emit(format!("beqz t3, {}", high_pair_ok));
        self.emit(format!("bnez t1, {}", overflow_label));
        self.emit_label(&high_pair_ok);

        self.emit("mul t4, t0, t2");
        self.emit("mulhu a2, t0, t2");

        self.emit("mul a3, t0, t3");
        self.emit("mulhu a4, t0, t3");
        self.emit(format!("bnez a4, {}", overflow_label));

        self.emit("mul a5, t1, t2");
        self.emit("mulhu a6, t1, t2");
        self.emit(format!("bnez a6, {}", overflow_label));

        self.emit("add t5, a2, a3");
        self.emit("sltu a7, t5, a2");
        self.emit(format!("bnez a7, {}", overflow_label));
        self.emit("add t5, t5, a5");
        self.emit("sltu a7, t5, a5");
        self.emit(format!("bnez a7, {}", overflow_label));

        self.emit_stack_store("t4", dest_offset);
        self.emit_stack_store("t5", dest_offset + 8);
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
        self.emit(format!("j {}", done_label));

        self.emit_label(&overflow_label);
        self.emit_fail(CellScriptRuntimeError::AggregateAmountMismatch);
        self.emit_label(&done_label);
    }

    fn emit_u128_div(&mut self, dest: &IrVar, left: &IrOperand, right: &IrOperand) {
        self.emit_u128_div_rem(dest, left, right, true);
    }

    fn emit_u128_mod(&mut self, dest: &IrVar, left: &IrOperand, right: &IrOperand) {
        self.emit_u128_div_rem(dest, left, right, false);
    }

    fn emit_u128_div_rem(&mut self, dest: &IrVar, left: &IrOperand, right: &IrOperand, quotient_result: bool) {
        let Some(dest_offset) = self.u128_value_offsets.get(&dest.id).copied() else {
            self.emit("# cellscript abi: u128 division/remainder destination has no storage; fail closed");
            self.emit_fail(CellScriptRuntimeError::FixedByteComparisonUnresolved);
            return;
        };
        if !self.emit_u128_binary_operand_limbs(left, right, "u128 division/remainder") {
            return;
        }
        self.emit(if quotient_result {
            "# cellscript abi: checked u128 division by restoring long division"
        } else {
            "# cellscript abi: checked u128 remainder by restoring long division"
        });
        let ok_label = self.fresh_label("u128_div_denominator_ok");
        let loop_label = self.fresh_label("u128_div_loop");
        let skip_sub_label = self.fresh_label("u128_div_skip_subtract");
        let subtract_label = self.fresh_label("u128_div_subtract");
        let done_label = self.fresh_label("u128_div_done");
        let fail_label = self.fresh_label("u128_div_zero_denominator");

        self.emit("or t4, t2, t3");
        self.emit(format!("bnez t4, {}", ok_label));
        self.emit(format!("j {}", fail_label));
        self.emit_label(&ok_label);
        self.emit("li t4, 0"); // remainder low
        self.emit("li t5, 0"); // remainder high
        self.emit("li a2, 0"); // quotient low
        self.emit("li a3, 0"); // quotient high
        self.emit("li a4, 128");
        self.emit_label(&loop_label);

        self.emit("slt a7, t5, zero"); // carry from remainder high (conceptual bit 128)
        self.emit("slt a5, t1, zero"); // next numerator bit
        self.emit("slt a6, t4, zero"); // carry from remainder low
        self.emit("slli t4, t4, 1");
        self.emit("or t4, t4, a5");
        self.emit("slli t5, t5, 1");
        self.emit("or t5, t5, a6");

        self.emit("slt a5, t0, zero"); // carry from numerator low
        self.emit("slli t0, t0, 1");
        self.emit("slli t1, t1, 1");
        self.emit("or t1, t1, a5");

        self.emit("slt a5, a2, zero"); // carry from quotient low
        self.emit("slli a2, a2, 1");
        self.emit("slli a3, a3, 1");
        self.emit("or a3, a3, a5");

        // A carry out of the 128-bit remainder means the conceptual 129-bit
        // value is certainly at least the denominator. Subtracting once
        // restores remainder < denominator and yields a 128-bit value.
        self.emit(format!("bnez a7, {}", subtract_label));
        self.emit("sltu a5, t5, t3");
        self.emit(format!("bnez a5, {}", skip_sub_label));
        self.emit("sltu a5, t3, t5");
        self.emit(format!("bnez a5, {}", subtract_label));
        self.emit("sltu a5, t4, t2");
        self.emit(format!("bnez a5, {}", skip_sub_label));

        self.emit_label(&subtract_label);
        self.emit("sltu a5, t4, t2");
        self.emit("sub t4, t4, t2");
        self.emit("sub t5, t5, t3");
        self.emit("sub t5, t5, a5");
        self.emit("addi a2, a2, 1");

        self.emit_label(&skip_sub_label);
        self.emit("addi a4, a4, -1");
        self.emit(format!("bnez a4, {}", loop_label));
        if quotient_result {
            self.emit_stack_store("a2", dest_offset);
            self.emit_stack_store("a3", dest_offset + 8);
        } else {
            self.emit_stack_store("t4", dest_offset);
            self.emit_stack_store("t5", dest_offset + 8);
        }
        self.emit_store_u128_pointer_for_var(dest.id, dest_offset);
        self.emit(format!("j {}", done_label));

        self.emit_label(&fail_label);
        self.emit_fail(CellScriptRuntimeError::NumericOrDiscriminantInvalid);
        self.emit_label(&done_label);
    }

    fn emit_dynamic_byte_comparison(&mut self, dest: &IrVar, op: BinaryOp, left: &IrOperand, right: &IrOperand) -> bool {
        let (IrOperand::Var(left_var), IrOperand::Var(right_var)) = (left, right) else {
            return false;
        };
        let Some(left_len_offset) = self.dynamic_value_size_offsets.get(&left_var.id).copied() else {
            return false;
        };
        let Some(right_len_offset) = self.dynamic_value_size_offsets.get(&right_var.id).copied() else {
            return false;
        };

        let equal_value = if matches!(op, BinaryOp::Eq) { 1 } else { 0 };
        let mismatch_value = if matches!(op, BinaryOp::Eq) { 0 } else { 1 };
        let len_equal_label = self.fresh_label("dynamic_bytes_len_equal");
        let bytes_equal_label = self.fresh_label("dynamic_bytes_equal");
        let done_label = self.fresh_label("dynamic_bytes_cmp_done");

        self.emit(format!("# binary {:?} over dynamic byte operands", op));
        self.emit_stack_load("t0", left_len_offset);
        self.emit_stack_load("t1", right_len_offset);
        self.emit("sub t2, t0, t1");
        self.emit(format!("beqz t2, {}", len_equal_label));
        self.emit(format!("li t0, {}", mismatch_value));
        self.emit_stack_store("t0", dest.id * 8);
        self.emit(format!("j {}", done_label));

        self.emit_label(&len_equal_label);
        self.emit_stack_load("a0", left_var.id * 8);
        self.emit_stack_load("a1", right_var.id * 8);
        self.emit_stack_load("a2", left_len_offset);
        self.emit("call __cellscript_memcmp_fixed");
        self.emit(format!("beqz a0, {}", bytes_equal_label));
        self.emit(format!("li t0, {}", mismatch_value));
        self.emit_stack_store("t0", dest.id * 8);
        self.emit(format!("j {}", done_label));

        self.emit_label(&bytes_equal_label);
        self.emit(format!("li t0, {}", equal_value));
        self.emit_stack_store("t0", dest.id * 8);
        self.emit_label(&done_label);
        true
    }

    pub(super) fn emit_unary(&mut self, dest: &IrVar, op: UnaryOp, operand: &IrOperand) -> Result<()> {
        match operand {
            IrOperand::Const(IrConst::U64(n)) => self.emit(format!("li t0, {}", n)),
            IrOperand::Var(v) => self.emit_stack_load("t0", v.id * 8),
            _ => self.emit("li t0, 0"),
        }

        match op {
            UnaryOp::Neg => self.emit("neg t0, t0"),
            UnaryOp::Not => self.emit("xori t0, t0, 1"),
            UnaryOp::Ref | UnaryOp::Deref => self.emit("# reference conversion (no-op in asm backend)"),
        }

        self.emit_stack_store("t0", dest.id * 8);
        Ok(())
    }

    pub(super) fn emit_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> Result<()> {
        // A tuple call returns register payloads, not the address of its
        // allocated (but uninitialized) fixed-byte local buffer.
        if self.emit_tuple_call_return_field_access(dest, obj, field) {
            return Ok(());
        }
        if self.emit_fixed_byte_field_access(dest, obj, field) {
            return Ok(());
        }
        if self.emit_schema_field_access(dest, obj, field) {
            return Ok(());
        }
        if self.emit_aggregate_field_access(dest, obj, field) {
            return Ok(());
        }
        if self.emit_generic_field_access(dest, obj, field) {
            return Ok(());
        }

        self.emit(format!("# field access .{} (unresolved)", field));
        self.emit("# cellscript abi: fail closed because field offset is not computable from available type layout");
        self.emit_fail(CellScriptRuntimeError::DynamicFieldBoundsInvalid);
        Ok(())
    }

    fn emit_fixed_byte_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> bool {
        let IrOperand::Var(var) = obj else {
            return false;
        };
        let layout = aggregate_field_layout(&var.ty, field).or_else(|| {
            named_type_name(&var.ty)
                .and_then(|type_name| self.type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned())
        });
        let Some(layout) = layout else {
            return false;
        };
        let Some(parent_width) = self.fixed_byte_like_width(&var.ty) else {
            return false;
        };
        let Some(source) = self.expected_fixed_byte_source(obj, parent_width) else {
            return false;
        };
        if let Some(width) = layout_fixed_scalar_width(&layout) {
            self.emit(format!("# field access .{field}"));
            self.emit(format!(
                "# cellscript abi: fixed aggregate field {}.{} offset={} size={}",
                aggregate_type_label(&var.ty),
                field,
                layout.offset,
                width
            ));
            self.emit(format!(
                "# cellscript abi: fixed-byte scalar field {}.{} offset={} size={}",
                aggregate_type_label(&var.ty),
                field,
                layout.offset,
                width
            ));
            self.emit_prepare_fixed_byte_source(&source, parent_width, "fixed-byte scalar field access");
            if !self.emit_fixed_byte_source_pointer_or_const_to("t4", &source) {
                return false;
            }
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
            if layout.ty == IrType::I32 {
                self.emit_sign_extend_i32("t0");
            }
            self.emit_stack_store("t0", dest.id * 8);
            if let ExpectedFixedByteSource::SchemaField(parent) = &source {
                let mut nested_layout = layout.clone();
                nested_layout.offset += parent.layout.offset;
                let nested_source = SchemaFieldValueSource {
                    obj_var_id: parent.obj_var_id,
                    type_name: parent.type_name.clone(),
                    field: format!("{}.{}", parent.field, field),
                    layout: nested_layout,
                };
                self.schema_field_value_sources.insert(dest.id, nested_source.clone());
                if dest.ty == IrType::U64 {
                    self.prelude_u64_value_sources.insert(dest.id, PreludeU64ValueSource::Field(nested_source));
                }
            }
            return true;
        }
        let Some(width) = layout_fixed_byte_width(&layout)
            .or_else(|| fixed_aggregate_pointer_param_width(&layout.ty))
            .or_else(|| self.fixed_named_type_width(&layout.ty))
        else {
            return false;
        };
        let Some(dest_offset) = self.fixed_byte_local_offsets.get(&dest.id).copied() else {
            return false;
        };

        self.emit(format!(
            "# cellscript abi: fixed-byte field {}.{} offset={} size={}",
            aggregate_type_label(&var.ty),
            field,
            layout.offset,
            width
        ));
        self.emit_prepare_fixed_byte_source(&source, parent_width, "fixed-byte field access");
        if !self.emit_fixed_byte_source_pointer_or_const_to("a0", &source) {
            return false;
        }
        self.emit(format!("addi a0, a0, {}", layout.offset));
        self.emit_sp_addi("a1", dest_offset);
        self.emit(format!("li a2, {}", width));
        self.emit("call __cellscript_memcpy_fixed");
        self.emit_sp_addi("t0", dest_offset);
        self.emit_stack_store("t0", dest.id * 8);
        if let ExpectedFixedByteSource::SchemaField(parent) = &source {
            let mut nested_layout = layout.clone();
            nested_layout.offset += parent.layout.offset;
            let nested_source = SchemaFieldValueSource {
                obj_var_id: parent.obj_var_id,
                type_name: parent.type_name.clone(),
                field: format!("{}.{}", parent.field, field),
                layout: nested_layout,
            };
            self.schema_field_value_sources.insert(dest.id, nested_source);
        }
        true
    }

    fn emit_schema_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> bool {
        let IrOperand::Var(var) = obj else {
            return false;
        };
        if !self.schema_pointer_vars.contains(&var.id) {
            return false;
        }
        let Some(type_name) = named_type_name(&var.ty) else {
            return false;
        };
        let Some(layout) = self.type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned() else {
            return false;
        };
        let Some(width) = layout_fixed_byte_width(&layout) else {
            return self.emit_dynamic_schema_field_access(dest, var, type_name, field, &layout);
        };

        self.emit(format!("# field access .{}", field));
        self.emit(format!("# cellscript abi: schema field {}.{} offset={} size={}", type_name, field, layout.offset, width));
        self.emit_stack_load("t4", var.id * 8);
        if let Some(size_offset) = self.schema_pointer_size_offsets.get(&var.id).copied() {
            if let Some(expected_size) = self.type_fixed_sizes.get(type_name).copied() {
                self.emit_loaded_schema_exact_size_check(size_offset, expected_size, type_name);
                self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, &format!("{}.{}", type_name, field));
                if layout_fixed_scalar_width(&layout).is_some() {
                    self.emit_schema_scalar_load(var.id, "t4", "t0", "t2", layout.offset, width);
                } else {
                    self.emit(format!("addi t0, t4, {}", layout.offset));
                }
            } else {
                self.emit_molecule_table_field_bounds_to_t5(
                    "t4",
                    size_offset,
                    layout.index,
                    width,
                    &format!("{}.{}", type_name, field),
                );
                self.emit("add t4, t4, t5");
                if layout_fixed_scalar_width(&layout).is_some() {
                    self.emit_unaligned_scalar_load("t4", "t0", "t2", 0, width);
                } else {
                    self.emit("addi t0, t4, 0");
                }
            }
        } else {
            if !self.type_fixed_sizes.contains_key(type_name) {
                return false;
            }
            if layout_fixed_scalar_width(&layout).is_some() {
                self.emit_schema_scalar_load(var.id, "t4", "t0", "t2", layout.offset, width);
            } else {
                self.emit(format!("addi t0, t4, {}", layout.offset));
            }
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_dynamic_schema_field_access(
        &mut self,
        dest: &IrVar,
        obj: &IrVar,
        type_name: &str,
        field: &str,
        layout: &SchemaFieldLayout,
    ) -> bool {
        if molecule_vector_element_fixed_width(&layout.ty, &self.type_fixed_sizes, &self.enum_fixed_sizes).is_none() {
            return false;
        }
        let Some(size_offset) = self.schema_pointer_size_offsets.get(&obj.id).copied() else {
            return false;
        };
        let Some(dest_size_offset) = self.dynamic_value_size_offsets.get(&dest.id).copied() else {
            return false;
        };
        let Some(field_count) = self.type_layouts.get(type_name).map(|fields| fields.len()) else {
            return false;
        };

        let context = format!("{}.{}", type_name, field);
        self.emit(format!("# field access .{}", field));
        self.emit(format!("# cellscript abi: dynamic schema field {} index={} as Molecule vector bytes", context, layout.index));
        self.emit_stack_load("t4", obj.id * 8);
        self.emit_molecule_table_field_span_to_t5_t6("t4", size_offset, layout.index, field_count, &context);
        self.emit("add t0, t4, t5");
        self.emit("sub t1, t6, t5");
        self.emit_stack_store("t0", dest.id * 8);
        self.emit_schema_size_store("t1", dest_size_offset);
        true
    }

    fn emit_aggregate_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> bool {
        let IrOperand::Var(var) = obj else {
            return false;
        };
        let Some(source) = self.aggregate_pointer_sources.get(&var.id) else {
            return false;
        };
        let source_ty = source.ty.clone();
        let Some(layout) = aggregate_field_layout(&source_ty, field) else {
            return false;
        };
        let Some(width) = layout_fixed_byte_width(&layout) else {
            return false;
        };

        self.emit(format!("# field access .{}", field));
        self.emit(format!(
            "# cellscript abi: fixed aggregate field {}.{} offset={} size={}",
            aggregate_type_label(&source_ty),
            field,
            layout.offset,
            width
        ));
        self.emit_stack_load("t4", var.id * 8);
        if layout_fixed_scalar_width(&layout).is_some() {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
            if layout.ty == IrType::I32 {
                self.emit_sign_extend_i32("t0");
            }
        } else {
            self.emit(format!("addi t0, t4, {}", layout.offset));
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }

    fn emit_tuple_call_return_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> bool {
        let IrOperand::Var(var) = obj else {
            return false;
        };
        let Some(slot_var_id) = self.tuple_call_return_field_slots.get(&(var.id, field.to_string())).copied() else {
            return false;
        };
        self.emit(format!("# field access .{}", field));
        self.emit(format!("# cellscript abi: tuple call return field .{} projected from return register", field));
        if slot_var_id != dest.id {
            self.emit_stack_load("t0", slot_var_id * 8);
            self.emit_stack_store("t0", dest.id * 8);
        }
        true
    }

    /// Generic field access: when specialized paths don't match, try to compute the
    /// field offset from type_layouts and emit an unaligned load from the pointer
    /// stored in the object's stack slot. This works for any named-type variable
    /// whose type has a registered layout, even if it wasn't classified as a
    /// schema_pointer_var or aggregate_pointer_source.
    fn emit_generic_field_access(&mut self, dest: &IrVar, obj: &IrOperand, field: &str) -> bool {
        let IrOperand::Var(var) = obj else {
            return false;
        };
        let Some(type_name) = named_type_name(&var.ty) else {
            return false;
        };
        if !self.type_fixed_sizes.contains_key(type_name) {
            return false;
        }
        let Some(layout) = self.type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned() else {
            return false;
        };
        let Some(width) = layout_fixed_byte_width(&layout) else {
            return false;
        };

        self.emit(format!("# field access .{}", field));
        self.emit(format!("# cellscript abi: generic field {}.{} offset={} size={}", type_name, field, layout.offset, width));

        // Bounds check: if the object has a known size offset, verify the data
        // is large enough to contain this field.
        if let Some(size_offset) = self.schema_pointer_size_offsets.get(&var.id).copied() {
            self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, &format!("{}.{}", type_name, field));
        } else if let Some(size_offset) = self.fixed_byte_param_size_offsets.get(&var.id).copied() {
            self.emit_loaded_schema_bounds_check(size_offset, layout.offset + width, &format!("{}.{}", type_name, field));
        }

        // Load the object pointer from the stack slot
        self.emit_stack_load("t4", var.id * 8);
        if layout_fixed_scalar_width(&layout).is_some() {
            self.emit_unaligned_scalar_load("t4", "t0", "t2", layout.offset, width);
        } else {
            self.emit(format!("addi t0, t4, {}", layout.offset));
        }
        self.emit_stack_store("t0", dest.id * 8);
        true
    }
}
