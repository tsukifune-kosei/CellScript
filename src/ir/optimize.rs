use std::collections::HashSet;

use super::{BinaryOp, BlockId, IrBlock, IrConst, IrInstruction, IrItem, IrModule, IrOperand, IrTerminator, IrType, IrVar};

const CELL_DATA_SIZE_HELPER: &str = "__ckb_cell_data_size";
const CELL_DATA_BYTE_HELPER: &str = "__ckb_cell_data_u8";
pub(crate) const CELL_DATA_EQUAL_HELPER: &str = "__ckb_cell_data_equal";
pub(crate) const SOURCE_BYTES_EQUAL_HELPER: &str = "__ckb_source_bytes_equal";
pub(crate) const SOURCE_BYTES_EQUAL_MEMORY_HELPER: &str = "__ckb_source_bytes_equal_memory";
pub(crate) const SOURCE_BYTES_ZERO_HELPER: &str = "__ckb_source_bytes_zero";

/// Replace the canonical exact Cell-data byte-comparison loop with one
/// semantically equivalent runtime operation. The matcher deliberately uses
/// only typed IR structure: callable names and source spelling are irrelevant,
/// and near-miss loops retain their original lowering.
pub(crate) fn optimize_exact_cell_data_equality(module: &mut IrModule) {
    for item in &mut module.items {
        let IrItem::PureFn(function) = item else {
            continue;
        };
        let Some(replacement) = match_exact_cell_data_equality(function) else {
            continue;
        };
        function.body.blocks = vec![replacement];
    }
}

/// Replace a canonical byte-for-byte equality loop over two CKB syscall
/// sources with one bounded chunk operation. This is deliberately an IR
/// pattern, not a callable-name convention: the loop must start at zero,
/// compare exactly one byte from each source at affine `base + index`
/// offsets, return false at the first mismatch, and return true on completion.
pub(crate) fn optimize_source_byte_equality(module: &mut IrModule) {
    for item in &mut module.items {
        let IrItem::PureFn(function) = item else {
            continue;
        };
        let Some((condition_id, replacement)) = match_source_byte_equality_loop(function) else {
            continue;
        };
        let Some(condition) = function.body.blocks.iter_mut().find(|block| block.id == condition_id) else {
            continue;
        };
        *condition = replacement;
        prune_unreachable_blocks(&mut function.body.blocks);

        // A function can contain more than one independent canonical loop,
        // but every rewrite changes reachability. Re-run the two other exact
        // byte-loop matchers against the resulting body below.
    }
    for item in &mut module.items {
        let IrItem::PureFn(function) = item else {
            continue;
        };
        if let Some((condition_id, replacement)) = match_source_memory_equality_loop(function)
            && let Some(condition) = function.body.blocks.iter_mut().find(|block| block.id == condition_id)
        {
            *condition = replacement;
            prune_unreachable_blocks(&mut function.body.blocks);
        }
        if let Some((condition_id, replacement)) = match_source_zero_loop(function)
            && let Some(condition) = function.body.blocks.iter_mut().find(|block| block.id == condition_id)
        {
            *condition = replacement;
            prune_unreachable_blocks(&mut function.body.blocks);
        }
    }
}

struct EqualityLoop<'a> {
    condition: &'a IrBlock,
    result: &'a IrVar,
    index: &'a IrVar,
    length: &'a IrOperand,
    prefix: &'a [IrInstruction],
    left: &'a IrOperand,
    right: &'a IrOperand,
}

fn equality_loop_at<'a>(function: &'a super::IrPureFn, condition: &'a IrBlock) -> Option<EqualityLoop<'a>> {
    let [IrInstruction::Binary { dest: result, op: BinaryOp::Lt, left: IrOperand::Var(index), right: length }] =
        condition.instructions.as_slice()
    else {
        return None;
    };
    let IrTerminator::Branch { cond, then_block: compare_id, else_block: complete_id } = &condition.terminator else {
        return None;
    };
    if !operand_is_var(cond, result) || !is_const_return(block(&function.body.blocks, *complete_id)?, true) {
        return None;
    }
    let compare = block(&function.body.blocks, *compare_id)?;
    let (last, prefix) = compare.instructions.split_last()?;
    let IrInstruction::Binary { dest: differs, op: BinaryOp::Ne, left, right } = last else {
        return None;
    };
    let IrTerminator::Branch { cond, then_block: mismatch_id, else_block: continue_id } = &compare.terminator else {
        return None;
    };
    if !operand_is_var(cond, differs) || !is_const_return(block(&function.body.blocks, *mismatch_id)?, false) {
        return None;
    }
    let increment_id = empty_jump(block(&function.body.blocks, *continue_id)?)?;
    let increment = block(&function.body.blocks, increment_id)?;
    let [IrInstruction::Binary { dest: next_index, op: BinaryOp::Add, left: increment_left, right: IrOperand::Const(IrConst::U64(1)) }, IrInstruction::Move { dest: moved_index, src: next_index_operand }] =
        increment.instructions.as_slice()
    else {
        return None;
    };
    if !operand_is_var(increment_left, index)
        || moved_index.id != index.id
        || !operand_is_var(next_index_operand, next_index)
        || empty_jump_target(&increment.terminator)? != condition.id
    {
        return None;
    }
    let initialized_from_zero =
        function.body.blocks.iter().any(|candidate| {
            candidate.instructions.iter().any(
                |instruction| matches!(instruction, IrInstruction::LoadConst { dest, value: IrConst::U64(0) } if dest.id == index.id),
            ) && empty_jump_target(&candidate.terminator) == Some(condition.id)
        });
    initialized_from_zero.then_some(EqualityLoop { condition, result, index, length, prefix, left, right })
}

struct SourceByte<'a> {
    view: &'a IrOperand,
    offset: &'a IrOperand,
    kind: u64,
    scratch: &'a IrVar,
}

fn source_byte<'a>(operand: &'a IrOperand, instructions: &'a [IrInstruction]) -> Option<SourceByte<'a>> {
    let resolved = resolve_moves(operand, instructions, instructions.len() + 1)?;
    let IrOperand::Var(value) = resolved else {
        return None;
    };
    let IrInstruction::Call { dest: Some(dest), func, args } = definition_for(value.id, instructions)? else {
        return None;
    };
    let [view, offset] = args.as_slice() else {
        return None;
    };
    Some(SourceByte { view, offset, kind: runtime_byte_source_kind(func)?, scratch: dest })
}

struct MemoryByte<'a> {
    pointer: &'a IrVar,
    index: &'a IrOperand,
}

fn memory_byte<'a>(operand: &'a IrOperand, instructions: &'a [IrInstruction]) -> Option<MemoryByte<'a>> {
    let resolved = resolve_moves(operand, instructions, instructions.len() + 1)?;
    let IrOperand::Var(value) = resolved else {
        return None;
    };
    let IrInstruction::Index { arr: IrOperand::Var(pointer), idx, .. } = definition_for(value.id, instructions)? else {
        return None;
    };
    matches!(pointer.ty, IrType::Array(ref inner, _) if inner.as_ref() == &IrType::U8).then_some(MemoryByte { pointer, index: idx })
}

fn resolve_moves<'a>(operand: &'a IrOperand, instructions: &'a [IrInstruction], remaining_depth: usize) -> Option<&'a IrOperand> {
    if remaining_depth == 0 {
        return None;
    }
    let IrOperand::Var(var) = operand else {
        return Some(operand);
    };
    match definition_for(var.id, instructions) {
        Some(IrInstruction::Move { src, .. }) => resolve_moves(src, instructions, remaining_depth - 1),
        _ => Some(operand),
    }
}

fn definition_for(var_id: usize, instructions: &[IrInstruction]) -> Option<&IrInstruction> {
    instructions.iter().rev().find(|instruction| match instruction {
        IrInstruction::LoadConst { dest, .. }
        | IrInstruction::LoadVar { dest, .. }
        | IrInstruction::Binary { dest, .. }
        | IrInstruction::Unary { dest, .. }
        | IrInstruction::FieldAccess { dest, .. }
        | IrInstruction::Index { dest, .. }
        | IrInstruction::Length { dest, .. }
        | IrInstruction::TypeHash { dest, .. }
        | IrInstruction::CollectionNew { dest, .. }
        | IrInstruction::CollectionCapacity { dest, .. }
        | IrInstruction::CollectionPop { dest, .. }
        | IrInstruction::CollectionContains { dest, .. }
        | IrInstruction::CollectionRemove { dest, .. }
        | IrInstruction::BoundedCellLoad { dest, .. }
        | IrInstruction::BoundedPlanLoad { dest, .. }
        | IrInstruction::Call { dest: Some(dest), .. }
        | IrInstruction::ReadRef { dest, .. }
        | IrInstruction::Move { dest, .. }
        | IrInstruction::Tuple { dest, .. }
        | IrInstruction::EnumConstruct { dest, .. }
        | IrInstruction::EnumTag { dest, .. }
        | IrInstruction::EnumPayload { dest, .. }
        | IrInstruction::Create { dest, .. }
        | IrInstruction::CreateUnique { dest, .. }
        | IrInstruction::Transfer { dest, .. }
        | IrInstruction::ReplaceUnique { dest, .. }
        | IrInstruction::Claim { dest, .. }
        | IrInstruction::Settle { dest, .. } => dest.id == var_id,
        IrInstruction::StoreVar { .. }
        | IrInstruction::CollectionPush { .. }
        | IrInstruction::CollectionExtend { .. }
        | IrInstruction::CollectionClear { .. }
        | IrInstruction::CollectionReverse { .. }
        | IrInstruction::CollectionTruncate { .. }
        | IrInstruction::CollectionSwap { .. }
        | IrInstruction::CollectionInsert { .. }
        | IrInstruction::CollectionSet { .. }
        | IrInstruction::BoundedOutputVerify { .. }
        | IrInstruction::BoundedOutputEnd { .. }
        | IrInstruction::CellMetadataEquality { .. }
        | IrInstruction::Consume { .. }
        | IrInstruction::Destroy { .. }
        | IrInstruction::Call { dest: None, .. } => false,
    })
}

fn match_source_memory_equality_loop(function: &super::IrPureFn) -> Option<(BlockId, IrBlock)> {
    if function.return_type != Some(IrType::Bool) {
        return None;
    }
    for condition in &function.body.blocks {
        let Some(loop_shape) = equality_loop_at(function, condition) else {
            continue;
        };
        let pair = source_byte(loop_shape.left, loop_shape.prefix)
            .zip(memory_byte(loop_shape.right, loop_shape.prefix))
            .or_else(|| source_byte(loop_shape.right, loop_shape.prefix).zip(memory_byte(loop_shape.left, loop_shape.prefix)));
        let Some((source, memory)) = pair else {
            continue;
        };
        if !operand_is_var(memory.index, loop_shape.index) {
            continue;
        }
        let IrOperand::Const(IrConst::U64(length)) = loop_shape.length else {
            continue;
        };
        let IrType::Array(inner, width) = &memory.pointer.ty else {
            continue;
        };
        if inner.as_ref() != &IrType::U8 || *length as usize > *width {
            continue;
        }
        let source_form = decompose_indexed_offset(source.offset, loop_shape.index, loop_shape.prefix, loop_shape.prefix.len() + 1)?;
        if source_form.index_count != 1
            || source_form.terms.len() > 1
            || operand_depends_on_prefix_or_index(source.view, loop_shape.index, loop_shape.prefix)
        {
            continue;
        }
        let mut instructions = Vec::new();
        let source_base = materialize_offset_base(source_form, source.scratch, &mut instructions);
        instructions.push(IrInstruction::Call {
            dest: Some(loop_shape.result.clone()),
            func: SOURCE_BYTES_EQUAL_MEMORY_HELPER.to_string(),
            args: vec![
                source.view.clone(),
                source_base,
                IrOperand::Var(memory.pointer.clone()),
                loop_shape.length.clone(),
                IrOperand::Const(IrConst::U64(source.kind)),
            ],
        });
        return Some((
            loop_shape.condition.id,
            IrBlock {
                id: loop_shape.condition.id,
                instructions,
                terminator: IrTerminator::Return(Some(IrOperand::Var(loop_shape.result.clone()))),
                runtime_error: None,
            },
        ));
    }
    None
}

fn match_source_zero_loop(function: &super::IrPureFn) -> Option<(BlockId, IrBlock)> {
    if function.return_type != Some(IrType::Bool) {
        return None;
    }
    for condition in &function.body.blocks {
        let Some(loop_shape) = equality_loop_at(function, condition) else {
            continue;
        };
        let source = match (loop_shape.left, loop_shape.right) {
            (IrOperand::Const(IrConst::U64(0)), other) | (other, IrOperand::Const(IrConst::U64(0))) => {
                source_byte(other, loop_shape.prefix)
            }
            _ => None,
        };
        let Some(source) = source else {
            continue;
        };
        let source_form = decompose_indexed_offset(source.offset, loop_shape.index, loop_shape.prefix, loop_shape.prefix.len() + 1)?;
        if source_form.index_count != 1
            || source_form.terms.len() > 1
            || operand_depends_on_prefix_or_index(source.view, loop_shape.index, loop_shape.prefix)
            || operand_depends_on_prefix_or_index(loop_shape.length, loop_shape.index, loop_shape.prefix)
        {
            continue;
        }
        let mut instructions = Vec::new();
        let source_base = materialize_offset_base(source_form, source.scratch, &mut instructions);
        instructions.push(IrInstruction::Call {
            dest: Some(loop_shape.result.clone()),
            func: SOURCE_BYTES_ZERO_HELPER.to_string(),
            args: vec![source.view.clone(), source_base, loop_shape.length.clone(), IrOperand::Const(IrConst::U64(source.kind))],
        });
        return Some((
            loop_shape.condition.id,
            IrBlock {
                id: loop_shape.condition.id,
                instructions,
                terminator: IrTerminator::Return(Some(IrOperand::Var(loop_shape.result.clone()))),
                runtime_error: None,
            },
        ));
    }
    None
}

fn match_source_byte_equality_loop(function: &super::IrPureFn) -> Option<(BlockId, IrBlock)> {
    if function.return_type != Some(IrType::Bool) {
        return None;
    }
    for condition in &function.body.blocks {
        let [IrInstruction::Binary { dest: result, op: BinaryOp::Lt, left: IrOperand::Var(index), right: length }] =
            condition.instructions.as_slice()
        else {
            continue;
        };
        let IrTerminator::Branch { cond, then_block: compare_id, else_block: complete_id } = &condition.terminator else {
            continue;
        };
        if !operand_is_var(cond, result) || !is_const_return(block(&function.body.blocks, *complete_id)?, true) {
            continue;
        }

        let compare = block(&function.body.blocks, *compare_id)?;
        if compare.instructions.len() < 3 {
            continue;
        }
        let split = compare.instructions.len() - 3;
        let prefix = &compare.instructions[..split];
        let [IrInstruction::Call { dest: Some(left_byte), func: left_func, args: left_args }, IrInstruction::Call { dest: Some(right_byte), func: right_func, args: right_args }, IrInstruction::Binary { dest: differs, op: BinaryOp::Ne, left, right }] =
            &compare.instructions[split..]
        else {
            continue;
        };
        let Some(left_kind) = runtime_byte_source_kind(left_func) else {
            continue;
        };
        let Some(right_kind) = runtime_byte_source_kind(right_func) else {
            continue;
        };
        let ([left_view, left_offset], [right_view, right_offset]) = (left_args.as_slice(), right_args.as_slice()) else {
            continue;
        };
        if !(operand_is_var(left, left_byte) && operand_is_var(right, right_byte)
            || operand_is_var(left, right_byte) && operand_is_var(right, left_byte))
        {
            continue;
        }
        let IrTerminator::Branch { cond, then_block: mismatch_id, else_block: continue_id } = &compare.terminator else {
            continue;
        };
        if !operand_is_var(cond, differs) || !is_const_return(block(&function.body.blocks, *mismatch_id)?, false) {
            continue;
        }

        let increment_id = empty_jump(block(&function.body.blocks, *continue_id)?)?;
        let increment = block(&function.body.blocks, increment_id)?;
        let [IrInstruction::Binary {
            dest: next_index,
            op: BinaryOp::Add,
            left: increment_left,
            right: IrOperand::Const(IrConst::U64(1)),
        }, IrInstruction::Move { dest: moved_index, src: next_index_operand }] = increment.instructions.as_slice()
        else {
            continue;
        };
        if !operand_is_var(increment_left, index)
            || moved_index.id != index.id
            || !operand_is_var(next_index_operand, next_index)
            || empty_jump_target(&increment.terminator)? != condition.id
        {
            continue;
        }

        let initialized_from_zero = function.body.blocks.iter().any(|candidate| {
            matches!(
                candidate.instructions.as_slice(),
                [IrInstruction::LoadConst { dest, value: IrConst::U64(0) }]
                    if dest.id == index.id && empty_jump_target(&candidate.terminator) == Some(condition.id)
            )
        });
        if !initialized_from_zero {
            continue;
        }

        let left_form = decompose_indexed_offset(left_offset, index, prefix, prefix.len() + 1)?;
        let right_form = decompose_indexed_offset(right_offset, index, prefix, prefix.len() + 1)?;
        if left_form.index_count != 1
            || right_form.index_count != 1
            || left_form.terms.len() > 1
            || right_form.terms.len() > 1
            || operand_depends_on_prefix_or_index(left_view, index, prefix)
            || operand_depends_on_prefix_or_index(right_view, index, prefix)
            || operand_depends_on_prefix_or_index(length, index, prefix)
        {
            continue;
        }

        let mut instructions = Vec::new();
        let left_base = materialize_offset_base(left_form, left_byte, &mut instructions);
        let right_base = materialize_offset_base(right_form, right_byte, &mut instructions);
        instructions.push(IrInstruction::Call {
            dest: Some(result.clone()),
            func: SOURCE_BYTES_EQUAL_HELPER.to_string(),
            args: vec![
                left_view.clone(),
                left_base,
                right_view.clone(),
                right_base,
                length.clone(),
                IrOperand::Const(IrConst::U64(left_kind)),
                IrOperand::Const(IrConst::U64(right_kind)),
            ],
        });
        return Some((
            condition.id,
            IrBlock {
                id: condition.id,
                instructions,
                terminator: IrTerminator::Return(Some(IrOperand::Var(result.clone()))),
                runtime_error: None,
            },
        ));
    }
    None
}

#[derive(Debug)]
struct IndexedOffset {
    index_count: usize,
    terms: Vec<IrOperand>,
    constant: u64,
}

fn decompose_indexed_offset(
    operand: &IrOperand,
    index: &IrVar,
    definitions: &[IrInstruction],
    remaining_depth: usize,
) -> Option<IndexedOffset> {
    if remaining_depth == 0 {
        return None;
    }
    match operand {
        IrOperand::Var(var) if var.id == index.id => Some(IndexedOffset { index_count: 1, terms: Vec::new(), constant: 0 }),
        IrOperand::Const(IrConst::U64(value)) => Some(IndexedOffset { index_count: 0, terms: Vec::new(), constant: *value }),
        IrOperand::Var(var) => {
            let definition = definitions
                .iter()
                .rev()
                .find(|instruction| matches!(instruction, IrInstruction::Binary { dest, .. } if dest.id == var.id));
            let Some(IrInstruction::Binary { op: BinaryOp::Add, left, right, .. }) = definition else {
                return Some(IndexedOffset { index_count: 0, terms: vec![operand.clone()], constant: 0 });
            };
            let mut left = decompose_indexed_offset(left, index, definitions, remaining_depth - 1)?;
            let right = decompose_indexed_offset(right, index, definitions, remaining_depth - 1)?;
            left.index_count += right.index_count;
            left.constant = left.constant.wrapping_add(right.constant);
            left.terms.extend(right.terms);
            Some(left)
        }
        _ => None,
    }
}

fn operand_depends_on_prefix_or_index(operand: &IrOperand, index: &IrVar, definitions: &[IrInstruction]) -> bool {
    match operand {
        IrOperand::Var(var) if var.id == index.id => true,
        IrOperand::Var(var) => {
            definitions.iter().any(|instruction| matches!(instruction, IrInstruction::Binary { dest, .. } if dest.id == var.id))
        }
        _ => false,
    }
}

fn materialize_offset_base(form: IndexedOffset, scratch: &IrVar, instructions: &mut Vec<IrInstruction>) -> IrOperand {
    match (form.terms.into_iter().next(), form.constant) {
        (None, constant) => IrOperand::Const(IrConst::U64(constant)),
        (Some(term), 0) => term,
        (Some(term), constant) => {
            let dest = IrVar { id: scratch.id, name: "byte_range_base".to_string(), ty: IrType::U64 };
            instructions.push(IrInstruction::Binary {
                dest: dest.clone(),
                op: BinaryOp::Add,
                left: term,
                right: IrOperand::Const(IrConst::U64(constant)),
            });
            IrOperand::Var(dest)
        }
    }
}

fn runtime_byte_source_kind(func: &str) -> Option<u64> {
    match func {
        "__ckb_cell_data_u8" => Some(0),
        "__ckb_witness_u8" => Some(1),
        "__ckb_cell_lock_u8" => Some(2),
        "__ckb_cell_type_u8" => Some(3),
        _ => None,
    }
}

fn prune_unreachable_blocks(blocks: &mut Vec<IrBlock>) {
    let Some(entry) = blocks.first().map(|block| block.id) else {
        return;
    };
    let mut reachable = HashSet::new();
    let mut pending = vec![entry];
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let Some(block) = blocks.iter().find(|block| block.id == id) else {
            continue;
        };
        match block.terminator {
            IrTerminator::Jump(target) => pending.push(target),
            IrTerminator::Branch { then_block, else_block, .. } => {
                pending.push(then_block);
                pending.push(else_block);
            }
            IrTerminator::Return(_) => {}
        }
    }
    blocks.retain(|block| reachable.contains(&block.id));
}

fn match_exact_cell_data_equality(function: &super::IrPureFn) -> Option<IrBlock> {
    if function.params.len() != 2
        || function.params.iter().any(|param| param.ty != IrType::U64)
        || function.return_type != Some(IrType::Bool)
        || function.body.blocks.len() != 10
        || !function.body.cell_bindings.is_empty()
        || !function.body.consume_set.is_empty()
        || !function.body.read_refs.is_empty()
        || !function.body.create_set.is_empty()
        || !function.body.mutate_set.is_empty()
        || !function.body.write_intents.is_empty()
        || !function.body.bounded_collection_ops.is_empty()
        || !function.body.borrow_regions.is_empty()
        || !function.body.trusted_external_calls.is_empty()
        || !function.body.enforced_claims.is_empty()
    {
        return None;
    }

    let entry = function.body.blocks.first()?;
    let [IrInstruction::Call { dest: Some(size_a), func: size_a_func, args: size_a_args }, IrInstruction::Call { dest: Some(size_b), func: size_b_func, args: size_b_args }, IrInstruction::Binary { dest: sizes_differ, op: BinaryOp::Ne, left: size_left, right: size_right }] =
        entry.instructions.as_slice()
    else {
        return None;
    };
    if size_a_func != CELL_DATA_SIZE_HELPER
        || size_b_func != CELL_DATA_SIZE_HELPER
        || !single_var_arg_is(size_a_args, &function.params[0].binding)
        || !single_var_arg_is(size_b_args, &function.params[1].binding)
        || !operand_is_var(size_left, size_a)
        || !operand_is_var(size_right, size_b)
    {
        return None;
    }
    let IrTerminator::Branch { cond, then_block: size_mismatch_id, else_block: sizes_equal_id } = &entry.terminator else {
        return None;
    };
    if !operand_is_var(cond, sizes_differ) || !is_const_return(block(&function.body.blocks, *size_mismatch_id)?, false) {
        return None;
    }

    let sizes_equal = empty_jump(block(&function.body.blocks, *sizes_equal_id)?)?;
    let init = block(&function.body.blocks, sizes_equal)?;
    let [IrInstruction::LoadConst { dest: index, value: IrConst::U64(0) }] = init.instructions.as_slice() else {
        return None;
    };
    let condition_id = empty_jump_target(&init.terminator)?;
    let condition = block(&function.body.blocks, condition_id)?;
    let [IrInstruction::Binary { dest: in_bounds, op: BinaryOp::Lt, left: index_left, right: length_right }] =
        condition.instructions.as_slice()
    else {
        return None;
    };
    if !operand_is_var(index_left, index) || !operand_is_var(length_right, size_a) {
        return None;
    }
    let IrTerminator::Branch { cond, then_block: compare_id, else_block: complete_id } = &condition.terminator else {
        return None;
    };
    if !operand_is_var(cond, in_bounds) || !is_const_return(block(&function.body.blocks, *complete_id)?, true) {
        return None;
    }

    let compare = block(&function.body.blocks, *compare_id)?;
    let [IrInstruction::Call { dest: Some(byte_a), func: byte_a_func, args: byte_a_args }, IrInstruction::Call { dest: Some(byte_b), func: byte_b_func, args: byte_b_args }, IrInstruction::Binary { dest: bytes_differ, op: BinaryOp::Ne, left: byte_left, right: byte_right }] =
        compare.instructions.as_slice()
    else {
        return None;
    };
    if byte_a_func != CELL_DATA_BYTE_HELPER
        || byte_b_func != CELL_DATA_BYTE_HELPER
        || !two_var_args_are(byte_a_args, &function.params[0].binding, index)
        || !two_var_args_are(byte_b_args, &function.params[1].binding, index)
        || !operand_is_var(byte_left, byte_a)
        || !operand_is_var(byte_right, byte_b)
    {
        return None;
    }
    let IrTerminator::Branch { cond, then_block: byte_mismatch_id, else_block: continue_id } = &compare.terminator else {
        return None;
    };
    if !operand_is_var(cond, bytes_differ) || !is_const_return(block(&function.body.blocks, *byte_mismatch_id)?, false) {
        return None;
    }

    let increment_id = empty_jump(block(&function.body.blocks, *continue_id)?)?;
    let increment = block(&function.body.blocks, increment_id)?;
    let [IrInstruction::Binary { dest: next_index, op: BinaryOp::Add, left: increment_left, right: IrOperand::Const(IrConst::U64(1)) }, IrInstruction::Move { dest: moved_index, src: next_index_operand }] =
        increment.instructions.as_slice()
    else {
        return None;
    };
    if !operand_is_var(increment_left, index)
        || moved_index.id != index.id
        || !operand_is_var(next_index_operand, next_index)
        || empty_jump_target(&increment.terminator)? != condition_id
    {
        return None;
    }

    Some(IrBlock {
        id: entry.id,
        instructions: vec![IrInstruction::Call {
            dest: Some(IrVar { id: bytes_differ.id, name: bytes_differ.name.clone(), ty: IrType::Bool }),
            func: CELL_DATA_EQUAL_HELPER.to_string(),
            args: vec![IrOperand::Var(function.params[0].binding.clone()), IrOperand::Var(function.params[1].binding.clone())],
        }],
        terminator: IrTerminator::Return(Some(IrOperand::Var(IrVar {
            id: bytes_differ.id,
            name: bytes_differ.name.clone(),
            ty: IrType::Bool,
        }))),
        runtime_error: None,
    })
}

fn block(blocks: &[IrBlock], id: BlockId) -> Option<&IrBlock> {
    blocks.iter().find(|block| block.id == id)
}

fn operand_is_var(operand: &IrOperand, var: &IrVar) -> bool {
    matches!(operand, IrOperand::Var(candidate) if candidate.id == var.id)
}

fn single_var_arg_is(args: &[IrOperand], var: &IrVar) -> bool {
    matches!(args, [operand] if operand_is_var(operand, var))
}

fn two_var_args_are(args: &[IrOperand], first: &IrVar, second: &IrVar) -> bool {
    matches!(args, [left, right] if operand_is_var(left, first) && operand_is_var(right, second))
}

fn is_const_return(block: &IrBlock, value: bool) -> bool {
    block.instructions.is_empty()
        && matches!(&block.terminator, IrTerminator::Return(Some(IrOperand::Const(IrConst::Bool(actual)))) if *actual == value)
}

fn empty_jump(block: &IrBlock) -> Option<BlockId> {
    block.instructions.is_empty().then(|| empty_jump_target(&block.terminator)).flatten()
}

fn empty_jump_target(terminator: &IrTerminator) -> Option<BlockId> {
    match terminator {
        IrTerminator::Jump(target) => Some(*target),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frontend, generics, CellScriptEdition};

    fn lower(source: &str) -> IrModule {
        let ast = frontend::parse(source, CellScriptEdition::Edition2026).unwrap();
        let ast = generics::monomorphize(&ast).unwrap();
        crate::ir::generate(&ast).unwrap()
    }

    fn canonical_source(byte_index: &str) -> String {
        format!(
            r#"
            module test
            #[effect(ReadOnly)]
            fn same_data(a: u64, b: u64) -> bool {{
                let length = ckb::cell_data_size(a)
                if length != ckb::cell_data_size(b) {{ return false }}
                let mut index = 0
                while index < length {{
                    if ckb::cell_data_u8(a, {byte_index}) != ckb::cell_data_u8(b, index) {{ return false }}
                    index += 1
                }}
                return true
            }}
            "#
        )
    }

    #[test]
    fn folds_canonical_exact_cell_data_equality_loop() {
        let mut module = lower(&canonical_source("index"));
        optimize_exact_cell_data_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) if function.name == "same_data" => Some(function),
            _ => None,
        });
        let function = function.unwrap();
        assert_eq!(function.body.blocks.len(), 1);
        assert!(matches!(
            function.body.blocks[0].instructions.as_slice(),
            [IrInstruction::Call { func, .. }] if func == CELL_DATA_EQUAL_HELPER
        ));
    }

    #[test]
    fn leaves_near_miss_indexing_loop_unchanged() {
        let mut module = lower(&canonical_source("0"));
        optimize_exact_cell_data_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) if function.name == "same_data" => Some(function),
            _ => None,
        });
        assert!(function.unwrap().body.blocks.len() > 1);
    }

    #[test]
    fn folds_affine_mixed_source_byte_equality_loop() {
        let mut module = lower(
            r#"
            module test
            #[effect(ReadOnly)]
            fn same(a: u64, start: u64, b: u64, length: u64) -> bool {
                let mut index: u64 = 0
                while index < length {
                    if witness::byte(a, start + 4 + index) != ckb::cell_lock_u8(b, index) { return false }
                    index += 1
                }
                return true
            }
            "#,
        );
        optimize_source_byte_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) => Some(function),
            _ => None,
        });
        let function = function.unwrap();
        assert_eq!(function.body.blocks.len(), 2);
        assert!(function.body.blocks.iter().any(|block| {
            matches!(block.instructions.last(), Some(IrInstruction::Call { func, .. }) if func == SOURCE_BYTES_EQUAL_HELPER)
        }));
    }

    #[test]
    fn leaves_non_affine_byte_index_loop_unchanged() {
        let mut module = lower(
            r#"
            module test
            #[effect(ReadOnly)]
            fn same(a: u64, b: u64, length: u64) -> bool {
                let mut index: u64 = 0
                while index < length {
                    if witness::byte(a, 0) != ckb::cell_lock_u8(b, index) { return false }
                    index += 1
                }
                return true
            }
            "#,
        );
        optimize_source_byte_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) => Some(function),
            _ => None,
        });
        assert!(function.unwrap().body.blocks.len() > 2);
    }

    #[test]
    fn folds_source_to_fixed_memory_byte_equality_loop() {
        let mut module = lower(
            r#"
            module test
            #[effect(ReadOnly)]
            fn same(a: u64, start: u64, value: Hash) -> bool {
                let bytes = value.0
                let mut index: u64 = 0
                while index < 20 {
                    if witness::byte(a, start + index) != bytes[index] as u64 { return false }
                    index += 1
                }
                return true
            }
            "#,
        );
        optimize_source_byte_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) => Some(function),
            _ => None,
        });
        assert!(function.unwrap().body.blocks.iter().any(|block| {
            matches!(block.instructions.last(), Some(IrInstruction::Call { func, .. }) if func == SOURCE_BYTES_EQUAL_MEMORY_HELPER)
        }));
    }

    #[test]
    fn folds_source_zero_byte_loop() {
        let mut module = lower(
            r#"
            module test
            #[effect(ReadOnly)]
            fn zero(a: u64, start: u64) -> bool {
                let mut index: u64 = 0
                while index < 36 {
                    if witness::byte(a, start + index) != 0 { return false }
                    index += 1
                }
                return true
            }
            "#,
        );
        optimize_source_byte_equality(&mut module);
        let function = module.items.iter().find_map(|item| match item {
            IrItem::PureFn(function) => Some(function),
            _ => None,
        });
        assert!(function.unwrap().body.blocks.iter().any(|block| {
            matches!(block.instructions.last(), Some(IrInstruction::Call { func, .. }) if func == SOURCE_BYTES_ZERO_HELPER)
        }));
    }
}
