use super::*;

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_SECTION_HEADER_SIZE: usize = 64;
/// The load segment keeps `p_vaddr ≡ p_offset (mod align)` like lld-emitted
/// CKB contracts, but only needs enough room for the payload start: the
/// headers end at byte 120 and the payload begins at 128. The previous 4 KiB
/// alignment inserted 3,976 zero bytes into every deployed artifact.
const ELF_SEGMENT_ALIGN: usize = 0x80;
const ELF_PF_X: u32 = 1;
#[cfg(test)]
const ELF_PF_W: u32 = 2;
const ELF_PF_R: u32 = 4;
const ELF_BASE_ADDR: u64 = 0x10000;
const START_TRAMPOLINE_SIZE: usize = 20;
const EXIT_SYSCALL_NUMBER: i64 = 93;
const ELF_SECTION_NAMES: &[u8] = b"\0.text\0.rodata\0.shstrtab\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SectionKind {
    Text,
    Rodata,
}

#[derive(Debug, Clone)]
enum AsmOp {
    Label(String),
    Instruction(Instruction),
    Word(u32),
    Byte(u8),
    Ascii(Vec<u8>),
    Align(usize),
}

#[derive(Debug, Clone, Copy)]
struct SymbolDef {
    section: SectionKind,
    offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct SectionLayout {
    text_base: u64,
    text_user_base: u64,
    rodata_base: u64,
}

impl SectionLayout {
    fn for_text_user_size(text_user_size: usize) -> Self {
        let rodata_offset = align_up(START_TRAMPOLINE_SIZE + text_user_size, 8);
        Self {
            text_base: ELF_BASE_ADDR,
            text_user_base: ELF_BASE_ADDR + START_TRAMPOLINE_SIZE as u64,
            rodata_base: ELF_BASE_ADDR + rodata_offset as u64,
        }
    }

    fn rodata_offset(&self) -> Result<usize> {
        usize::try_from(self.rodata_base - self.text_base)
            .map_err(|_| CompileError::new("ELF rodata offset does not fit usize", crate::error::Span::default()))
    }
}

#[derive(Debug)]
pub(super) struct MachineLayoutPlan {
    parsed: ParsedAssembly,
    layout: SectionLayout,
    cfg: MachineCfg,
    order: MachineLayoutOrder,
    pub(super) metrics: BackendLayoutMetrics,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct BackendLayoutMetrics {
    text_size: usize,
    rodata_size: usize,
    executable_text_op_count: usize,
    covered_text_op_count: usize,
    relaxed_branch_count: usize,
    max_cond_branch_abs_distance: u64,
    machine_block_count: usize,
    max_machine_block_size: usize,
    conditional_branch_block_count: usize,
    labeled_machine_block_count: usize,
    machine_cfg_edge_count: usize,
    machine_call_edge_count: usize,
    unreachable_machine_block_count: usize,
    layout_order_block_count: usize,
    layout_order_text_size: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct BackendShapeMetrics {
    pub text_size: usize,
    pub rodata_size: usize,
    pub executable_text_op_count: usize,
    pub covered_text_op_count: usize,
    pub relaxed_branch_count: usize,
    pub max_cond_branch_abs_distance: u64,
    pub machine_block_count: usize,
    pub max_machine_block_size: usize,
    pub conditional_branch_block_count: usize,
    pub labeled_machine_block_count: usize,
    pub machine_cfg_edge_count: usize,
    pub machine_call_edge_count: usize,
    pub unreachable_machine_block_count: usize,
    pub layout_order_block_count: usize,
    pub layout_order_text_size: usize,
}

impl From<BackendLayoutMetrics> for BackendShapeMetrics {
    fn from(metrics: BackendLayoutMetrics) -> Self {
        Self {
            text_size: metrics.text_size,
            rodata_size: metrics.rodata_size,
            executable_text_op_count: metrics.executable_text_op_count,
            covered_text_op_count: metrics.covered_text_op_count,
            relaxed_branch_count: metrics.relaxed_branch_count,
            max_cond_branch_abs_distance: metrics.max_cond_branch_abs_distance,
            machine_block_count: metrics.machine_block_count,
            max_machine_block_size: metrics.max_machine_block_size,
            conditional_branch_block_count: metrics.conditional_branch_block_count,
            labeled_machine_block_count: metrics.labeled_machine_block_count,
            machine_cfg_edge_count: metrics.machine_cfg_edge_count,
            machine_call_edge_count: metrics.machine_call_edge_count,
            unreachable_machine_block_count: metrics.unreachable_machine_block_count,
            layout_order_block_count: metrics.layout_order_block_count,
            layout_order_text_size: metrics.layout_order_text_size,
        }
    }
}

#[derive(Debug, Clone)]
enum Instruction {
    Addi { rd: u8, rs1: u8, imm: i64 },
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    And { rd: u8, rs1: u8, rs2: u8 },
    Andi { rd: u8, rs1: u8, imm: i64 },
    Or { rd: u8, rs1: u8, rs2: u8 },
    Xor { rd: u8, rs1: u8, rs2: u8 },
    Mul { rd: u8, rs1: u8, rs2: u8 },
    Mulhu { rd: u8, rs1: u8, rs2: u8 },
    Div { rd: u8, rs1: u8, rs2: u8 },
    Divu { rd: u8, rs1: u8, rs2: u8 },
    Rem { rd: u8, rs1: u8, rs2: u8 },
    Remu { rd: u8, rs1: u8, rs2: u8 },
    Slt { rd: u8, rs1: u8, rs2: u8 },
    Sltu { rd: u8, rs1: u8, rs2: u8 },
    Sgt { rd: u8, rs1: u8, rs2: u8 },
    Xori { rd: u8, rs1: u8, imm: i64 },
    Seqz { rd: u8, rs: u8 },
    Snez { rd: u8, rs: u8 },
    Neg { rd: u8, rs: u8 },
    Ld { rd: u8, rs1: u8, imm: i64 },
    Lbu { rd: u8, rs1: u8, imm: i64 },
    Sb { rs2: u8, rs1: u8, imm: i64 },
    Sh { rs2: u8, rs1: u8, imm: i64 },
    Sw { rs2: u8, rs1: u8, imm: i64 },
    Sd { rs2: u8, rs1: u8, imm: i64 },
    Slli { rd: u8, rs1: u8, shamt: i64 },
    Srai { rd: u8, rs1: u8, shamt: i64 },
    Srli { rd: u8, rs1: u8, shamt: i64 },
    Rori { rd: u8, rs1: u8, shamt: i64 },
    Roriw { rd: u8, rs1: u8, shamt: i64 },
    Sll { rd: u8, rs1: u8, rs2: u8 },
    Srl { rd: u8, rs1: u8, rs2: u8 },
    Sra { rd: u8, rs1: u8, rs2: u8 },
    Li { rd: u8, imm: i128 },
    La { rd: u8, label: String },
    Call { label: String },
    Jump { label: String },
    Beq { rs1: u8, rs2: u8, label: String },
    Bne { rs1: u8, rs2: u8, label: String },
    Blt { rs1: u8, rs2: u8, label: String },
    Bge { rs1: u8, rs2: u8, label: String },
    Bltu { rs1: u8, rs2: u8, label: String },
    Bgeu { rs1: u8, rs2: u8, label: String },
    Beqz { rs: u8, label: String },
    Bnez { rs: u8, label: String },
    Ret,
    Ecall,
}

fn reject_unresolved_calls(lines: &[String]) -> Result<()> {
    let mut labels = BTreeSet::new();
    let mut calls = BTreeSet::new();

    for line in lines {
        let Some(clean) = strip_comment(line) else {
            continue;
        };
        if let Some(label) = clean.strip_suffix(':') {
            labels.insert(label.trim().to_string());
            continue;
        }
        if let Some(target) = clean.strip_prefix("call ") {
            let target = target.trim();
            if !target.is_empty() {
                calls.insert(target.to_string());
            }
        }
    }

    let missing = calls.difference(&labels).cloned().collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    Err(CompileError::without_span(format!(
        "unresolved call target(s) in generated assembly: {}; production ELF emission requires all call targets to be lowered",
        missing.join(", ")
    )))
}

fn entry_requires_explicit_parameter_abi(lines: &[String], entry_label: &str) -> bool {
    let marker = format!("# cellscript entry abi: {} requires-explicit-parameter-abi", entry_label);
    lines.iter().any(|line| line.trim() == marker)
}

pub(super) fn assemble_generated_elf(lines: &[String]) -> Result<Vec<u8>> {
    reject_unresolved_calls(lines).map_err(|error| with_codegen_code(error, "E2200"))?;
    assemble_elf_internal(lines)
}

fn assemble_elf_internal(lines: &[String]) -> Result<Vec<u8>> {
    let plan = MachineLayoutPlan::build(lines).map_err(|error| with_codegen_code(error, "E2201"))?;
    let parsed = &plan.parsed;
    let layout = plan.layout;
    let _layout_control_metrics = (
        plan.metrics.executable_text_op_count,
        plan.metrics.covered_text_op_count,
        plan.metrics.relaxed_branch_count,
        plan.metrics.max_cond_branch_abs_distance,
        plan.metrics.machine_block_count,
        plan.metrics.max_machine_block_size,
        plan.metrics.conditional_branch_block_count,
        plan.metrics.labeled_machine_block_count,
        plan.metrics.machine_cfg_edge_count,
        plan.metrics.machine_call_edge_count,
        plan.metrics.unreachable_machine_block_count,
        plan.metrics.layout_order_block_count,
        plan.metrics.layout_order_text_size,
        plan.cfg.blocks.len(),
        plan.cfg.edges.len(),
        plan.order.block_order.len(),
        plan.order.placed_blocks.len(),
        plan.order.text_size,
    );
    let entry_label = parsed.entry_label.as_deref().ok_or_else(|| {
        CompileError::new("ELF target requires at least one action or lock entry point", crate::error::Span::default())
    })?;
    let text_user_size = plan.metrics.text_size;
    let rodata_size = plan.metrics.rodata_size;
    let rodata_offset = layout.rodata_offset()?;
    let mut text_bytes = Vec::with_capacity(START_TRAMPOLINE_SIZE + text_user_size);
    // The trampoline is a fixed-size ABI surface: both paths must encode to
    // exactly START_TRAMPOLINE_SIZE, so its `li` keeps the two-instruction
    // form regardless of the immediates. User code uses the optimal forms.
    if entry_requires_explicit_parameter_abi(lines, entry_label) {
        encode_fixed_li_sequence(&mut text_bytes, 10, 25)?;
    } else {
        let entry_addr = parsed.symbol_address(entry_label, &layout)?;
        encode_call_sequence(&mut text_bytes, layout.text_base, entry_addr)?;
    }
    encode_fixed_li_sequence(&mut text_bytes, 17, i128::from(EXIT_SYSCALL_NUMBER))?;
    text_bytes.extend_from_slice(&encode_ecall().to_le_bytes());
    debug_assert_eq!(text_bytes.len(), START_TRAMPOLINE_SIZE);
    parsed
        .encode_section(SectionKind::Text, &mut text_bytes, &layout, START_TRAMPOLINE_SIZE)
        .map_err(|error| with_codegen_code(error, "E2202"))?;

    let mut rodata_bytes = Vec::with_capacity(rodata_size);
    parsed.encode_section(SectionKind::Rodata, &mut rodata_bytes, &layout, 0).map_err(|error| with_codegen_code(error, "E2202"))?;

    let segment_file_payload_size = rodata_offset + rodata_bytes.len();
    let segment_file_offset = align_up(ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE, ELF_SEGMENT_ALIGN);
    let load_segment_offset = 0u64;
    let load_segment_vaddr = layout.text_base.checked_sub(segment_file_offset as u64).ok_or_else(|| {
        CompileError::new("ELF text base is smaller than the load segment file offset", crate::error::Span::default())
    })?;
    let load_segment_file_size = segment_file_offset + segment_file_payload_size;
    let section_names_offset = align_up(load_segment_file_size, 8);
    let section_header_offset = align_up(section_names_offset + ELF_SECTION_NAMES.len(), 8);
    let section_count = 4usize;
    let elf_size = section_header_offset + section_count * ELF_SECTION_HEADER_SIZE;
    let mut elf = vec![0u8; elf_size];
    write_elf_header(&mut elf[..ELF_HEADER_SIZE], layout.text_base, 1, section_header_offset as u64, section_count as u16, 3)?;
    write_program_header(
        &mut elf[ELF_HEADER_SIZE..ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE],
        ELF_PF_R | ELF_PF_X,
        load_segment_offset,
        load_segment_vaddr,
        load_segment_file_size as u64,
        load_segment_file_size as u64,
    )?;

    let segment = &mut elf[segment_file_offset..segment_file_offset + segment_file_payload_size];
    segment[..text_bytes.len()].copy_from_slice(&text_bytes);
    segment[rodata_offset..rodata_offset + rodata_bytes.len()].copy_from_slice(&rodata_bytes);
    elf[section_names_offset..section_names_offset + ELF_SECTION_NAMES.len()].copy_from_slice(ELF_SECTION_NAMES);
    let section_headers = &mut elf[section_header_offset..section_header_offset + section_count * ELF_SECTION_HEADER_SIZE];
    write_section_header(
        &mut section_headers[ELF_SECTION_HEADER_SIZE..2 * ELF_SECTION_HEADER_SIZE],
        1,
        1,
        0x2 | 0x4,
        layout.text_base,
        segment_file_offset as u64,
        text_bytes.len() as u64,
        4,
    )?;
    write_section_header(
        &mut section_headers[2 * ELF_SECTION_HEADER_SIZE..3 * ELF_SECTION_HEADER_SIZE],
        7,
        1,
        0x2,
        layout.rodata_base,
        (segment_file_offset + rodata_offset) as u64,
        rodata_bytes.len() as u64,
        8,
    )?;
    write_section_header(
        &mut section_headers[3 * ELF_SECTION_HEADER_SIZE..4 * ELF_SECTION_HEADER_SIZE],
        15,
        3,
        0,
        0,
        section_names_offset as u64,
        ELF_SECTION_NAMES.len() as u64,
        1,
    )?;
    Ok(elf)
}

#[derive(Debug, Default)]
struct ParsedAssembly {
    text_ops: Vec<AsmOp>,
    rodata_ops: Vec<AsmOp>,
    text_size: usize,
    rodata_size: usize,
    symbols: HashMap<String, SymbolDef>,
    globals: BTreeSet<String>,
    entry_label: Option<String>,
    relaxed_text_branches: BTreeSet<usize>,
}

impl ParsedAssembly {
    fn from_lines_relaxed(lines: &[String], layout: &SectionLayout) -> Result<Self> {
        let conservative = Self::from_lines_with_branch_mode(lines, BranchSizeMode::Conservative)?;
        let relaxed_text_branches = conservative.relaxed_branch_indices(layout)?;
        Self::from_lines_with_branch_mode(lines, BranchSizeMode::Exact(&relaxed_text_branches))
    }

    fn from_lines_with_branch_mode(lines: &[String], branch_size_mode: BranchSizeMode<'_>) -> Result<Self> {
        let mut current_section = SectionKind::Text;
        let mut text_size = 0usize;
        let mut rodata_size = 0usize;
        let mut text_ops = Vec::new();
        let mut rodata_ops = Vec::new();
        let mut symbols = HashMap::new();
        let mut globals = BTreeSet::new();
        let mut entry_label = None;
        let mut fallback_entry = None;

        for line in lines {
            let Some(clean) = strip_comment(line) else {
                continue;
            };
            if clean.is_empty() {
                continue;
            }

            if let Some(section) = parse_section_directive(clean)? {
                current_section = section;
                continue;
            }
            if clean.starts_with(".option ") || clean.starts_with(".type ") {
                continue;
            }
            if let Some(symbol) = clean.strip_prefix(".global ") {
                globals.insert(symbol.trim().to_string());
                continue;
            }

            let (ops, offset) = match current_section {
                SectionKind::Text => (&mut text_ops, &mut text_size),
                SectionKind::Rodata => (&mut rodata_ops, &mut rodata_size),
            };
            let op_index = ops.len();

            if let Some(label) = clean.strip_suffix(':') {
                let label = label.trim().to_string();
                let symbol = SymbolDef { section: current_section, offset: *offset };
                if symbols.insert(label.clone(), symbol).is_some() {
                    return Err(CompileError::new(format!("duplicate assembly label '{}'", label), crate::error::Span::default()));
                }
                if current_section == SectionKind::Text && globals.contains(&label) {
                    if fallback_entry.is_none() {
                        fallback_entry = Some(label.clone());
                    }
                    if !label.starts_with("__") && entry_label.is_none() {
                        entry_label = Some(label.clone());
                    }
                }
                ops.push(AsmOp::Label(label));
                continue;
            }

            let op = parse_asm_op(clean)?;
            *offset += op_size(&op, *offset, current_section, op_index, branch_size_mode);
            ops.push(op);
        }

        Ok(Self {
            text_ops,
            rodata_ops,
            text_size,
            rodata_size,
            symbols,
            globals,
            entry_label: entry_label.or(fallback_entry),
            relaxed_text_branches: branch_size_mode.relaxed_text_branches().cloned().unwrap_or_default(),
        })
    }

    fn relaxed_branch_indices(&self, layout: &SectionLayout) -> Result<BTreeSet<usize>> {
        let mut relaxed = BTreeSet::new();
        let mut offset = 0usize;
        for (index, op) in self.text_ops.iter().enumerate() {
            if let AsmOp::Instruction(inst) = op
                && conditional_branch_parts(inst).is_some()
            {
                let pc = layout.text_user_base + offset as u64;
                let target = branch_target(inst, self, layout)?;
                if !signed_bits_fit(relative_offset(pc, target)?, 13) {
                    relaxed.insert(index);
                }
            }
            offset += op_size(op, offset, SectionKind::Text, index, BranchSizeMode::Conservative);
        }
        Ok(relaxed)
    }

    fn section_size(&self, section: SectionKind) -> usize {
        match section {
            SectionKind::Text => self.text_size,
            SectionKind::Rodata => self.rodata_size,
        }
    }

    fn symbol_address(&self, label: &str, layout: &SectionLayout) -> Result<u64> {
        let symbol = self
            .symbols
            .get(label)
            .ok_or_else(|| CompileError::new(format!("unknown assembly label '{}'", label), crate::error::Span::default()))?;
        Ok(match symbol.section {
            SectionKind::Text => layout.text_user_base + symbol.offset as u64,
            SectionKind::Rodata => layout.rodata_base + symbol.offset as u64,
        })
    }

    fn encode_section(&self, section: SectionKind, out: &mut Vec<u8>, layout: &SectionLayout, base_bias: usize) -> Result<()> {
        let ops = match section {
            SectionKind::Text => &self.text_ops,
            SectionKind::Rodata => &self.rodata_ops,
        };
        let section_base = match section {
            SectionKind::Text => layout.text_user_base,
            SectionKind::Rodata => layout.rodata_base,
        };

        for (op_index, op) in ops.iter().enumerate() {
            match op {
                AsmOp::Label(_) => {}
                AsmOp::Word(word) => out.extend_from_slice(&word.to_le_bytes()),
                AsmOp::Byte(byte) => out.push(*byte),
                AsmOp::Ascii(bytes) => out.extend_from_slice(bytes),
                AsmOp::Align(bytes) => pad_to_alignment(out, *bytes),
                AsmOp::Instruction(inst) => {
                    let section_offset = out.len().checked_sub(base_bias).ok_or_else(|| {
                        CompileError::new("assembly output offset is smaller than section base bias", crate::error::Span::default())
                    })?;
                    let pc = section_base + section_offset as u64;
                    encode_instruction(
                        out,
                        inst,
                        pc,
                        self,
                        layout,
                        section == SectionKind::Text && self.relaxed_text_branches.contains(&op_index),
                    )?;
                }
            }
        }

        Ok(())
    }
}

impl MachineLayoutPlan {
    pub(super) fn build(lines: &[String]) -> Result<Self> {
        let preliminary = ParsedAssembly::from_lines_with_branch_mode(lines, BranchSizeMode::Conservative)?;
        let preliminary_layout = SectionLayout::for_text_user_size(preliminary.section_size(SectionKind::Text));
        let parsed = ParsedAssembly::from_lines_relaxed(lines, &preliminary_layout)?;
        let layout = SectionLayout::for_text_user_size(parsed.section_size(SectionKind::Text));
        let cfg = machine_cfg(&parsed)?;
        let coverage = validate_machine_block_coverage(&parsed, &cfg)?;
        let order = machine_layout_order(&cfg)?;
        let metrics = parsed.layout_metrics(&layout, &cfg, &order, coverage)?;
        Ok(Self { parsed, layout, cfg, order, metrics })
    }
}

pub(super) fn machine_layout_evidence(
    lines: &[String],
    entry_frame_sizes: &BTreeMap<String, u32>,
    ir: &IrModule,
) -> Result<MachineLayoutEvidence> {
    let plan = MachineLayoutPlan::build(lines)?;
    let runtime_error_labels = ir_runtime_error_labels(ir);
    let text_start = plan.layout.text_user_base;
    let text_end = text_start
        .checked_add(plan.metrics.text_size as u64)
        .ok_or_else(|| CompileError::new("machine evidence text range overflows u64", crate::error::Span::default()))?;
    let entry_label = plan
        .parsed
        .entry_label
        .clone()
        .ok_or_else(|| CompileError::new("machine evidence requires an entry label", crate::error::Span::default()))?;
    let blocks = plan
        .cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| MachineBlockEvidence {
            index,
            label: block.label.clone(),
            start: text_start + block.byte_start as u64,
            end: text_start + block.byte_start as u64 + block.byte_size as u64,
            terminator: match block.terminator {
                MachineTerminator::Fallthrough => MachineTerminatorEvidence::Fallthrough,
                MachineTerminator::Jump { .. } => MachineTerminatorEvidence::Jump,
                MachineTerminator::ConditionalBranch { .. } => MachineTerminatorEvidence::ConditionalBranch,
                MachineTerminator::Return => MachineTerminatorEvidence::Return,
            },
            runtime_error_codes: block.label.as_ref().and_then(|label| runtime_error_labels.get(label)).cloned().unwrap_or_default(),
        })
        .collect();
    let edges = plan
        .cfg
        .edges
        .iter()
        .map(|edge| MachineEdgeEvidence {
            from: edge.from,
            to: edge.to,
            kind: match edge.kind {
                MachineCfgEdgeKind::Fallthrough => MachineEdgeKindEvidence::Fallthrough,
                MachineCfgEdgeKind::Jump => MachineEdgeKindEvidence::Jump,
                MachineCfgEdgeKind::ConditionalTaken => MachineEdgeKindEvidence::ConditionalTaken,
                MachineCfgEdgeKind::ConditionalFallthrough => MachineEdgeKindEvidence::ConditionalFallthrough,
                MachineCfgEdgeKind::Call => MachineEdgeKindEvidence::Call,
            },
        })
        .collect();
    let symbols = plan
        .parsed
        .symbols
        .iter()
        .filter_map(|(name, symbol)| {
            (symbol.section == SectionKind::Text).then_some((name.clone(), text_start + symbol.offset as u64))
        })
        .collect();
    Ok(MachineLayoutEvidence {
        text_start,
        text_end,
        entry_label,
        blocks,
        edges,
        symbols,
        globals: plan.parsed.globals.clone(),
        entry_frame_sizes: entry_frame_sizes.clone(),
    })
}

fn ir_runtime_error_labels(ir: &IrModule) -> BTreeMap<String, Vec<u64>> {
    let mut labels = BTreeMap::new();
    for item in &ir.items {
        let (name, body) = match item {
            IrItem::Action(action) => (action.name.as_str(), &action.body),
            IrItem::Lock(lock) => (lock.name.as_str(), &lock.body),
            IrItem::PureFn(function) => (function.name.as_str(), &function.body),
            IrItem::TypeDef(_) | IrItem::Invariant(_) => continue,
        };
        for block in &body.blocks {
            if let Some(error) = block.runtime_error {
                labels.insert(format!(".L{}_block_{}", name, block.id.0), vec![error.code()]);
            }
        }
    }
    labels
}

#[derive(Debug, Clone, Copy)]
struct TextOpLayout {
    op_index: usize,
    offset: usize,
    size: usize,
}

#[derive(Debug, Clone)]
struct MachineBlock {
    label: Option<String>,
    op_start: usize,
    op_end: usize,
    byte_start: usize,
    byte_size: usize,
    terminator: MachineTerminator,
}

#[derive(Debug, Clone)]
struct MachineCfg {
    blocks: Vec<MachineBlock>,
    edges: Vec<MachineCfgEdge>,
}

#[derive(Debug, Clone, Copy, Default)]
struct MachineBlockCoverage {
    executable_text_op_count: usize,
    covered_text_op_count: usize,
}

#[derive(Debug, Clone)]
struct MachineLayoutOrder {
    block_order: Vec<usize>,
    placed_blocks: Vec<MachinePlacedBlock>,
    text_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MachinePlacedBlock {
    block_index: usize,
    byte_start: usize,
    byte_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MachineCfgEdge {
    from: usize,
    to: usize,
    kind: MachineCfgEdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineCfgEdgeKind {
    Fallthrough,
    Jump,
    ConditionalTaken,
    ConditionalFallthrough,
    Call,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MachineTerminator {
    Fallthrough,
    Jump { target: String },
    ConditionalBranch { target: String },
    Return,
}

fn text_op_layouts(parsed: &ParsedAssembly) -> Vec<TextOpLayout> {
    let mut offset = 0usize;
    let mut layouts = Vec::with_capacity(parsed.text_ops.len());
    for (op_index, op) in parsed.text_ops.iter().enumerate() {
        let size = op_size(op, offset, SectionKind::Text, op_index, BranchSizeMode::Exact(&parsed.relaxed_text_branches));
        layouts.push(TextOpLayout { op_index, offset, size });
        offset += size;
    }
    layouts
}

fn machine_blocks(parsed: &ParsedAssembly) -> Vec<MachineBlock> {
    let layouts = text_op_layouts(parsed);
    let mut blocks = Vec::new();
    let mut block_start = 0usize;
    let mut block_label = None;

    for (op_index, op) in parsed.text_ops.iter().enumerate() {
        if let AsmOp::Label(label) = op {
            if block_has_executable_ops(&parsed.text_ops[block_start..op_index]) {
                blocks.push(build_machine_block(parsed, &layouts, block_start, op_index, block_label.take()));
                block_start = op_index;
            }
            if block_label.is_none() {
                block_label = Some(label.clone());
            }
            continue;
        }

        if instruction_terminator(op).is_some() {
            blocks.push(build_machine_block(parsed, &layouts, block_start, op_index + 1, block_label.take()));
            block_start = op_index + 1;
        }
    }

    if block_start < parsed.text_ops.len() && block_has_executable_ops(&parsed.text_ops[block_start..]) {
        blocks.push(build_machine_block(parsed, &layouts, block_start, parsed.text_ops.len(), block_label));
    }

    blocks
}

fn machine_cfg(parsed: &ParsedAssembly) -> Result<MachineCfg> {
    let blocks = machine_blocks(parsed);
    let label_to_block = machine_label_to_block(parsed, &blocks);
    let mut edges = Vec::new();

    for (index, block) in blocks.iter().enumerate() {
        for target in machine_block_call_targets(parsed, block) {
            if let Some(&target_block) = label_to_block.get(&target) {
                edges.push(MachineCfgEdge { from: index, to: target_block, kind: MachineCfgEdgeKind::Call });
            }
        }
        match &block.terminator {
            MachineTerminator::Fallthrough => {
                if index + 1 < blocks.len() {
                    edges.push(MachineCfgEdge { from: index, to: index + 1, kind: MachineCfgEdgeKind::Fallthrough });
                }
            }
            MachineTerminator::Jump { target } => {
                edges.push(MachineCfgEdge {
                    from: index,
                    to: machine_cfg_target_block(target, &label_to_block)?,
                    kind: MachineCfgEdgeKind::Jump,
                });
            }
            MachineTerminator::ConditionalBranch { target } => {
                edges.push(MachineCfgEdge {
                    from: index,
                    to: machine_cfg_target_block(target, &label_to_block)?,
                    kind: MachineCfgEdgeKind::ConditionalTaken,
                });
                if index + 1 < blocks.len() {
                    edges.push(MachineCfgEdge { from: index, to: index + 1, kind: MachineCfgEdgeKind::ConditionalFallthrough });
                }
            }
            MachineTerminator::Return => {}
        }
    }

    Ok(MachineCfg { blocks, edges })
}

fn validate_machine_block_coverage(parsed: &ParsedAssembly, cfg: &MachineCfg) -> Result<MachineBlockCoverage> {
    let executable_text_op_count = parsed.text_ops.iter().filter(|op| !matches!(op, AsmOp::Label(_))).count();
    let mut covered = BTreeSet::new();

    for block in &cfg.blocks {
        if block.op_start >= block.op_end || block.op_end > parsed.text_ops.len() {
            return Err(CompileError::new(
                format!("machine block has invalid op range {}..{}", block.op_start, block.op_end),
                crate::error::Span::default(),
            ));
        }
        if !block_has_executable_ops(&parsed.text_ops[block.op_start..block.op_end]) {
            return Err(CompileError::new("machine block contains no executable instructions", crate::error::Span::default()));
        }
        for op_index in block.op_start..block.op_end {
            if matches!(parsed.text_ops[op_index], AsmOp::Label(_)) {
                continue;
            }
            if !covered.insert(op_index) {
                return Err(CompileError::new(
                    format!("machine block coverage overlaps text op {}", op_index),
                    crate::error::Span::default(),
                ));
            }
        }
    }

    if covered.len() != executable_text_op_count {
        return Err(CompileError::new(
            format!("machine blocks cover {} executable text ops but assembly contains {}", covered.len(), executable_text_op_count),
            crate::error::Span::default(),
        ));
    }

    Ok(MachineBlockCoverage { executable_text_op_count, covered_text_op_count: covered.len() })
}

fn machine_layout_order(cfg: &MachineCfg) -> Result<MachineLayoutOrder> {
    let block_order = (0..cfg.blocks.len()).collect::<Vec<_>>();
    build_machine_layout_order(cfg, block_order)
}

fn build_machine_layout_order(cfg: &MachineCfg, block_order: Vec<usize>) -> Result<MachineLayoutOrder> {
    validate_machine_layout_order(cfg, &block_order)?;
    let mut byte_start = 0usize;
    let mut placed_blocks = Vec::with_capacity(block_order.len());
    for &block_index in &block_order {
        let block = &cfg.blocks[block_index];
        placed_blocks.push(MachinePlacedBlock { block_index, byte_start, byte_size: block.byte_size });
        byte_start += block.byte_size;
    }
    Ok(MachineLayoutOrder { block_order, placed_blocks, text_size: byte_start })
}

fn validate_machine_layout_order(cfg: &MachineCfg, block_order: &[usize]) -> Result<()> {
    if block_order.len() != cfg.blocks.len() {
        return Err(CompileError::new(
            format!("machine layout order contains {} blocks but CFG contains {}", block_order.len(), cfg.blocks.len()),
            crate::error::Span::default(),
        ));
    }

    let mut seen = BTreeSet::new();
    for &block_index in block_order {
        if block_index >= cfg.blocks.len() {
            return Err(CompileError::new(
                format!("machine layout order references missing block {}", block_index),
                crate::error::Span::default(),
            ));
        }
        if !seen.insert(block_index) {
            return Err(CompileError::new(
                format!("machine layout order repeats block {}", block_index),
                crate::error::Span::default(),
            ));
        }
    }

    Ok(())
}

fn machine_label_to_block(parsed: &ParsedAssembly, blocks: &[MachineBlock]) -> HashMap<String, usize> {
    let mut label_to_block = HashMap::new();
    for (label, symbol) in &parsed.symbols {
        if symbol.section != SectionKind::Text {
            continue;
        }
        if let Some((block_index, _)) = blocks.iter().enumerate().find(|(_, block)| block.byte_start == symbol.offset) {
            label_to_block.insert(label.clone(), block_index);
        }
    }
    label_to_block
}

fn machine_cfg_target_block(target: &str, label_to_block: &HashMap<String, usize>) -> Result<usize> {
    label_to_block.get(target).copied().ok_or_else(|| {
        CompileError::new(format!("assembly branch target '{}' does not start a machine block", target), crate::error::Span::default())
    })
}

fn machine_block_call_targets(parsed: &ParsedAssembly, block: &MachineBlock) -> Vec<String> {
    parsed.text_ops[block.op_start..block.op_end]
        .iter()
        .filter_map(|op| match op {
            AsmOp::Instruction(Instruction::Call { label }) => Some(label.clone()),
            _ => None,
        })
        .collect()
}

fn unreachable_machine_block_count(parsed: &ParsedAssembly, cfg: &MachineCfg) -> usize {
    if cfg.blocks.is_empty() {
        return 0;
    }
    let label_to_block = machine_label_to_block(parsed, &cfg.blocks);
    let mut roots = parsed.entry_label.as_ref().and_then(|label| label_to_block.get(label).copied()).into_iter().collect::<Vec<_>>();
    if roots.is_empty() {
        roots.push(0);
    }
    let mut reachable = BTreeSet::new();
    let mut stack = roots;
    while let Some(block) = stack.pop() {
        if !reachable.insert(block) {
            continue;
        }
        for edge in cfg.edges.iter().filter(|edge| edge.from == block) {
            stack.push(edge.to);
        }
    }
    cfg.blocks.len().saturating_sub(reachable.len())
}

fn block_has_executable_ops(ops: &[AsmOp]) -> bool {
    ops.iter().any(|op| !matches!(op, AsmOp::Label(_)))
}

fn build_machine_block(
    parsed: &ParsedAssembly,
    layouts: &[TextOpLayout],
    op_start: usize,
    op_end: usize,
    label: Option<String>,
) -> MachineBlock {
    let byte_start = layouts.get(op_start).map(|layout| layout.offset).unwrap_or(0);
    let byte_end =
        op_end.checked_sub(1).and_then(|last| layouts.get(last).map(|layout| layout.offset + layout.size)).unwrap_or(byte_start);
    let terminator =
        parsed.text_ops[op_start..op_end].iter().rev().find_map(instruction_terminator).unwrap_or(MachineTerminator::Fallthrough);
    MachineBlock { label, op_start, op_end, byte_start, byte_size: byte_end.saturating_sub(byte_start), terminator }
}

fn instruction_terminator(op: &AsmOp) -> Option<MachineTerminator> {
    match op {
        AsmOp::Instruction(Instruction::Jump { label }) => Some(MachineTerminator::Jump { target: label.clone() }),
        AsmOp::Instruction(Instruction::Ret) => Some(MachineTerminator::Return),
        AsmOp::Instruction(inst) => {
            conditional_branch_parts(inst).map(|(_, _, label, _)| MachineTerminator::ConditionalBranch { target: label.to_string() })
        }
        _ => None,
    }
}

impl ParsedAssembly {
    fn layout_metrics(
        &self,
        layout: &SectionLayout,
        machine_cfg: &MachineCfg,
        machine_order: &MachineLayoutOrder,
        coverage: MachineBlockCoverage,
    ) -> Result<BackendLayoutMetrics> {
        let text_op_layouts = text_op_layouts(self);
        let text_size = text_op_layouts.iter().map(|op| op.size).sum();
        let mut max_cond_branch_abs_distance = 0u64;
        for op_layout in text_op_layouts {
            let AsmOp::Instruction(inst) = &self.text_ops[op_layout.op_index] else {
                continue;
            };
            if conditional_branch_parts(inst).is_none() {
                continue;
            };
            let pc = layout.text_user_base + op_layout.offset as u64;
            let target = branch_target(inst, self, layout)?;
            let distance = relative_offset(pc, target)?.unsigned_abs();
            max_cond_branch_abs_distance = max_cond_branch_abs_distance.max(distance);
        }
        let machine_block_count = machine_cfg.blocks.len();
        let max_machine_block_size = machine_cfg.blocks.iter().map(|block| block.byte_size).max().unwrap_or_default();
        let conditional_branch_block_count =
            machine_cfg.blocks.iter().filter(|block| matches!(block.terminator, MachineTerminator::ConditionalBranch { .. })).count();
        let labeled_machine_block_count = machine_cfg.blocks.iter().filter(|block| block.label.is_some()).count();
        let machine_cfg_edge_count = machine_cfg.edges.len();
        let machine_call_edge_count = machine_cfg.edges.iter().filter(|edge| edge.kind == MachineCfgEdgeKind::Call).count();
        let unreachable_machine_block_count = unreachable_machine_block_count(self, machine_cfg);
        let layout_order_block_count = machine_order.block_order.len();
        let layout_order_text_size = machine_order.text_size;
        let _covered_text_ops = machine_cfg.blocks.iter().map(|block| block.op_end.saturating_sub(block.op_start)).sum::<usize>();
        let _first_block_byte_start = machine_cfg.blocks.first().map(|block| block.byte_start).unwrap_or_default();
        Ok(BackendLayoutMetrics {
            text_size,
            rodata_size: self.section_size(SectionKind::Rodata),
            executable_text_op_count: coverage.executable_text_op_count,
            covered_text_op_count: coverage.covered_text_op_count,
            relaxed_branch_count: self.relaxed_text_branches.len(),
            max_cond_branch_abs_distance,
            machine_block_count,
            max_machine_block_size,
            conditional_branch_block_count,
            labeled_machine_block_count,
            machine_cfg_edge_count,
            machine_call_edge_count,
            unreachable_machine_block_count,
            layout_order_block_count,
            layout_order_text_size,
        })
    }
}

fn parse_section_directive(line: &str) -> Result<Option<SectionKind>> {
    if let Some(section) = line.strip_prefix(".section ") {
        return match section.trim() {
            ".text" => Ok(Some(SectionKind::Text)),
            ".rodata" => Ok(Some(SectionKind::Rodata)),
            other => Err(CompileError::new(format!("unsupported assembly section '{}'", other), crate::error::Span::default())),
        };
    }
    Ok(None)
}

fn parse_asm_op(line: &str) -> Result<AsmOp> {
    if let Some(value) = line.strip_prefix(".word ") {
        let value = parse_immediate(value.trim())?;
        return Ok(AsmOp::Word(
            u32::try_from(value).map_err(|_| {
                CompileError::new(format!("'.word' value '{}' does not fit u32", value), crate::error::Span::default())
            })?,
        ));
    }
    if let Some(value) = line.strip_prefix(".byte ") {
        let value = parse_immediate(value.trim())?;
        return Ok(AsmOp::Byte(
            u8::try_from(value)
                .map_err(|_| CompileError::new(format!("'.byte' value '{}' does not fit u8", value), crate::error::Span::default()))?,
        ));
    }
    if let Some(value) = line.strip_prefix(".ascii ") {
        return Ok(AsmOp::Ascii(parse_ascii_literal(value.trim())?));
    }
    if let Some(value) = line.strip_prefix(".align ") {
        let align_pow = parse_immediate(value.trim())?;
        if !(0..=16).contains(&align_pow) {
            return Err(CompileError::new(format!("unsupported .align value '{}'", align_pow), crate::error::Span::default()));
        }
        return Ok(AsmOp::Align(1usize << (align_pow as usize)));
    }
    Ok(AsmOp::Instruction(parse_instruction(line)?))
}

fn parse_instruction(line: &str) -> Result<Instruction> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let opcode = parts.next().unwrap().trim();
    let args = parts.next().unwrap_or("").trim();
    let args = if args.is_empty() { Vec::new() } else { args.split(',').map(|arg| arg.trim().to_string()).collect() };

    match opcode {
        "addi" => Ok(Instruction::Addi {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            imm: parse_immediate(arg(&args, 2)?)?,
        }),
        "add" => Ok(Instruction::Add {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "sub" => Ok(Instruction::Sub {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "and" => Ok(Instruction::And {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "andi" => Ok(Instruction::Andi {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            imm: parse_immediate(arg(&args, 2)?)?,
        }),
        "or" => Ok(Instruction::Or {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "xor" => Ok(Instruction::Xor {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "mul" => Ok(Instruction::Mul {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "mulhu" => Ok(Instruction::Mulhu {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "div" => Ok(Instruction::Div {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "divu" => Ok(Instruction::Divu {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "rem" => Ok(Instruction::Rem {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "remu" => Ok(Instruction::Remu {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "slt" => Ok(Instruction::Slt {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "sltu" => Ok(Instruction::Sltu {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "sgt" => Ok(Instruction::Sgt {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "xori" => Ok(Instruction::Xori {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            imm: parse_immediate(arg(&args, 2)?)?,
        }),
        "seqz" => Ok(Instruction::Seqz { rd: parse_register(arg(&args, 0)?)?, rs: parse_register(arg(&args, 1)?)? }),
        "snez" => Ok(Instruction::Snez { rd: parse_register(arg(&args, 0)?)?, rs: parse_register(arg(&args, 1)?)? }),
        "neg" => Ok(Instruction::Neg { rd: parse_register(arg(&args, 0)?)?, rs: parse_register(arg(&args, 1)?)? }),
        "ld" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Ld { rd: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "lbu" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Lbu { rd: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "sb" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Sb { rs2: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "sh" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Sh { rs2: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "sw" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Sw { rs2: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "sd" => {
            let (imm, rs1) = parse_memory_operand(arg(&args, 1)?)?;
            Ok(Instruction::Sd { rs2: parse_register(arg(&args, 0)?)?, rs1, imm })
        }
        "slli" => Ok(Instruction::Slli {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            shamt: parse_immediate(arg(&args, 2)?)?,
        }),
        "srai" => Ok(Instruction::Srai {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            shamt: parse_immediate(arg(&args, 2)?)?,
        }),
        "srli" => Ok(Instruction::Srli {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            shamt: parse_immediate(arg(&args, 2)?)?,
        }),
        "rori" => Ok(Instruction::Rori {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            shamt: parse_immediate(arg(&args, 2)?)?,
        }),
        "roriw" => Ok(Instruction::Roriw {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            shamt: parse_immediate(arg(&args, 2)?)?,
        }),
        "sll" => Ok(Instruction::Sll {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "srl" => Ok(Instruction::Srl {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "sra" => Ok(Instruction::Sra {
            rd: parse_register(arg(&args, 0)?)?,
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 2)?)?,
        }),
        "li" => Ok(Instruction::Li { rd: parse_register(arg(&args, 0)?)?, imm: parse_li_immediate(arg(&args, 1)?)? }),
        "mv" => Ok(Instruction::Addi { rd: parse_register(arg(&args, 0)?)?, rs1: parse_register(arg(&args, 1)?)?, imm: 0 }),
        "la" => Ok(Instruction::La { rd: parse_register(arg(&args, 0)?)?, label: arg(&args, 1)?.to_string() }),
        "call" => Ok(Instruction::Call { label: arg(&args, 0)?.to_string() }),
        "j" => Ok(Instruction::Jump { label: arg(&args, 0)?.to_string() }),
        "bgt" => Ok(Instruction::Blt {
            rs1: parse_register(arg(&args, 1)?)?,
            rs2: parse_register(arg(&args, 0)?)?,
            label: arg(&args, 2)?.to_string(),
        }),
        "bgez" => Ok(Instruction::Bge { rs1: parse_register(arg(&args, 0)?)?, rs2: 0, label: arg(&args, 1)?.to_string() }),
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
            let rs1 = parse_register(arg(&args, 0)?)?;
            let rs2 = parse_register(arg(&args, 1)?)?;
            let label = arg(&args, 2)?.to_string();
            match opcode {
                "beq" => Ok(Instruction::Beq { rs1, rs2, label }),
                "bne" => Ok(Instruction::Bne { rs1, rs2, label }),
                "blt" => Ok(Instruction::Blt { rs1, rs2, label }),
                "bge" => Ok(Instruction::Bge { rs1, rs2, label }),
                "bltu" => Ok(Instruction::Bltu { rs1, rs2, label }),
                "bgeu" => Ok(Instruction::Bgeu { rs1, rs2, label }),
                _ => unreachable!("branch opcode matched above"),
            }
        }
        "beqz" => Ok(Instruction::Beqz { rs: parse_register(arg(&args, 0)?)?, label: arg(&args, 1)?.to_string() }),
        "bnez" => Ok(Instruction::Bnez { rs: parse_register(arg(&args, 0)?)?, label: arg(&args, 1)?.to_string() }),
        "ret" => Ok(Instruction::Ret),
        "ecall" => Ok(Instruction::Ecall),
        other => Err(CompileError::new(format!("unsupported assembly instruction '{}'", other), crate::error::Span::default())),
    }
}

#[derive(Debug, Clone, Copy)]
enum BranchSizeMode<'a> {
    Conservative,
    Exact(&'a BTreeSet<usize>),
}

impl<'a> BranchSizeMode<'a> {
    fn relaxed_text_branches(self) -> Option<&'a BTreeSet<usize>> {
        match self {
            Self::Conservative => None,
            Self::Exact(branches) => Some(branches),
        }
    }
}

fn branch_target(inst: &Instruction, parsed: &ParsedAssembly, layout: &SectionLayout) -> Result<u64> {
    if let Some((_, _, label, _)) = conditional_branch_parts(inst) {
        parsed.symbol_address(label, layout)
    } else {
        Err(CompileError::new("instruction is not a conditional branch", crate::error::Span::default()))
    }
}

fn conditional_branch_parts(inst: &Instruction) -> Option<(u8, u8, &str, u32)> {
    match inst {
        Instruction::Beq { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b000)),
        Instruction::Bne { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b001)),
        Instruction::Blt { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b100)),
        Instruction::Bge { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b101)),
        Instruction::Bltu { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b110)),
        Instruction::Bgeu { rs1, rs2, label } => Some((*rs1, *rs2, label.as_str(), 0b111)),
        Instruction::Beqz { rs, label } => Some((*rs, 0, label.as_str(), 0b000)),
        Instruction::Bnez { rs, label } => Some((*rs, 0, label.as_str(), 0b001)),
        _ => None,
    }
}

fn inverse_branch_funct3(funct3: u32) -> u32 {
    match funct3 {
        0b000 => 0b001,
        0b001 => 0b000,
        0b100 => 0b101,
        0b101 => 0b100,
        0b110 => 0b111,
        0b111 => 0b110,
        _ => unreachable!("unsupported branch funct3"),
    }
}

fn encode_instruction(
    out: &mut Vec<u8>,
    inst: &Instruction,
    pc: u64,
    parsed: &ParsedAssembly,
    layout: &SectionLayout,
    relaxed_branch: bool,
) -> Result<()> {
    match inst {
        Instruction::Addi { rd, rs1, imm } => out.extend_from_slice(&encode_i_type(0x13, *rd, 0b000, *rs1, *imm)?.to_le_bytes()),
        Instruction::Add { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b000, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Sub { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b000, *rs1, *rs2, 0b0100000).to_le_bytes())
        }
        Instruction::And { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b111, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Andi { rd, rs1, imm } => out.extend_from_slice(&encode_i_type(0x13, *rd, 0b111, *rs1, *imm)?.to_le_bytes()),
        Instruction::Or { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b110, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Xor { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b100, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Mul { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b000, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Mulhu { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b011, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Div { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b100, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Divu { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b101, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Rem { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b110, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Remu { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b111, *rs1, *rs2, 0b0000001).to_le_bytes())
        }
        Instruction::Slt { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b010, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Sltu { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b011, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Sgt { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b010, *rs2, *rs1, 0b0000000).to_le_bytes())
        }
        Instruction::Xori { rd, rs1, imm } => out.extend_from_slice(&encode_i_type(0x13, *rd, 0b100, *rs1, *imm)?.to_le_bytes()),
        Instruction::Seqz { rd, rs } => out.extend_from_slice(&encode_i_type(0x13, *rd, 0b011, *rs, 1)?.to_le_bytes()),
        Instruction::Snez { rd, rs } => out.extend_from_slice(&encode_r_type(0x33, *rd, 0b011, 0, *rs, 0b0000000).to_le_bytes()),
        Instruction::Neg { rd, rs } => out.extend_from_slice(&encode_r_type(0x33, *rd, 0b000, 0, *rs, 0b0100000).to_le_bytes()),
        Instruction::Ld { rd, rs1, imm } => out.extend_from_slice(&encode_i_type(0x03, *rd, 0b011, *rs1, *imm)?.to_le_bytes()),
        Instruction::Lbu { rd, rs1, imm } => out.extend_from_slice(&encode_i_type(0x03, *rd, 0b100, *rs1, *imm)?.to_le_bytes()),
        Instruction::Sb { rs2, rs1, imm } => out.extend_from_slice(&encode_s_type(0x23, 0b000, *rs1, *rs2, *imm)?.to_le_bytes()),
        Instruction::Sh { rs2, rs1, imm } => out.extend_from_slice(&encode_s_type(0x23, 0b001, *rs1, *rs2, *imm)?.to_le_bytes()),
        Instruction::Sw { rs2, rs1, imm } => out.extend_from_slice(&encode_s_type(0x23, 0b010, *rs1, *rs2, *imm)?.to_le_bytes()),
        Instruction::Sd { rs2, rs1, imm } => out.extend_from_slice(&encode_s_type(0x23, 0b011, *rs1, *rs2, *imm)?.to_le_bytes()),
        Instruction::Slli { rd, rs1, shamt } => {
            if !(0..=63).contains(shamt) {
                return Err(CompileError::new("slli shift amount must be in 0..=63", crate::error::Span::default()));
            }
            out.extend_from_slice(&encode_i_type(0x13, *rd, 0b001, *rs1, *shamt)?.to_le_bytes());
        }
        Instruction::Srai { rd, rs1, shamt } => {
            if !(0..=63).contains(shamt) {
                return Err(CompileError::new("srai shift amount must be in 0..=63", crate::error::Span::default()));
            }
            let imm = (0b0100000_i64 << 5) | *shamt;
            out.extend_from_slice(&encode_i_type(0x13, *rd, 0b101, *rs1, imm)?.to_le_bytes());
        }
        Instruction::Srli { rd, rs1, shamt } => {
            if !(0..=63).contains(shamt) {
                return Err(CompileError::new("srli shift amount must be in 0..=63", crate::error::Span::default()));
            }
            out.extend_from_slice(&encode_i_type(0x13, *rd, 0b101, *rs1, *shamt)?.to_le_bytes());
        }
        Instruction::Rori { rd, rs1, shamt } => {
            if !(0..=63).contains(shamt) {
                return Err(CompileError::new("rori shift amount must be in 0..=63", crate::error::Span::default()));
            }
            let imm = (0b011000_i64 << 6) | *shamt;
            out.extend_from_slice(&encode_i_type(0x13, *rd, 0b101, *rs1, imm)?.to_le_bytes());
        }
        Instruction::Roriw { rd, rs1, shamt } => {
            if !(0..=31).contains(shamt) {
                return Err(CompileError::new("roriw shift amount must be in 0..=31", crate::error::Span::default()));
            }
            let imm = (0b0110000_i64 << 5) | *shamt;
            out.extend_from_slice(&encode_i_type(0x1b, *rd, 0b101, *rs1, imm)?.to_le_bytes());
        }
        Instruction::Sll { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b001, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Srl { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b101, *rs1, *rs2, 0b0000000).to_le_bytes())
        }
        Instruction::Sra { rd, rs1, rs2 } => {
            out.extend_from_slice(&encode_r_type(0x33, *rd, 0b101, *rs1, *rs2, 0b0100000).to_le_bytes())
        }
        Instruction::Li { rd, imm } => encode_li_sequence(out, *rd, *imm)?,
        Instruction::La { rd, label } => encode_address_sequence(out, *rd, pc, parsed.symbol_address(label, layout)?)?,
        Instruction::Call { label } => {
            let target = parsed.symbol_address(label, layout)?;
            encode_call_sequence(out, pc, target)?;
        }
        Instruction::Jump { label } => {
            let target = parsed.symbol_address(label, layout)?;
            out.extend_from_slice(&encode_j_type(0x6f, 0, relative_offset(pc, target)?)?.to_le_bytes());
        }
        Instruction::Beq { .. }
        | Instruction::Bne { .. }
        | Instruction::Blt { .. }
        | Instruction::Bge { .. }
        | Instruction::Bltu { .. }
        | Instruction::Bgeu { .. }
        | Instruction::Beqz { .. }
        | Instruction::Bnez { .. } => {
            let (rs1, rs2, label, funct3) = conditional_branch_parts(inst).expect("conditional branch parts");
            let target = parsed.symbol_address(label, layout)?;
            if relaxed_branch {
                out.extend_from_slice(&encode_b_type(0x63, inverse_branch_funct3(funct3), rs1, rs2, 8)?.to_le_bytes());
                out.extend_from_slice(&encode_j_type(0x6f, 0, relative_offset(pc + 4, target)?)?.to_le_bytes());
            } else {
                out.extend_from_slice(&encode_b_type(0x63, funct3, rs1, rs2, relative_offset(pc, target)?)?.to_le_bytes());
            }
        }
        Instruction::Ret => out.extend_from_slice(&encode_i_type(0x67, 0, 0b000, 1, 0)?.to_le_bytes()),
        Instruction::Ecall => out.extend_from_slice(&encode_ecall().to_le_bytes()),
    }
    Ok(())
}

/// Fixed two-instruction form for the start trampoline, whose size is part
/// of the entry ABI contract.
fn encode_fixed_li_sequence(out: &mut Vec<u8>, rd: u8, imm: i128) -> Result<()> {
    if let Some(signed) = li_signed_i64(imm)
        && li_fits_lui_addi_rv64(signed)
    {
        let (hi, lo) = split_hi_lo(signed)?;
        out.extend_from_slice(&encode_u_type(0x37, rd, hi).to_le_bytes());
        out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, rd, lo)?.to_le_bytes());
        return Ok(());
    }
    encode_large_li_sequence(out, rd, li_bits(imm)?)
}

fn encode_li_sequence(out: &mut Vec<u8>, rd: u8, imm: i128) -> Result<()> {
    match li_form(imm) {
        LiForm::Addi => {
            let signed = li_signed_i64(imm).expect("addi form implies an i64 immediate");
            out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, 0, signed)?.to_le_bytes());
        }
        LiForm::Lui => {
            let signed = li_signed_i64(imm).expect("lui form implies an i64 immediate");
            out.extend_from_slice(&encode_u_type(0x37, rd, signed >> 12).to_le_bytes());
        }
        LiForm::LuiAddi => {
            let signed = li_signed_i64(imm).expect("lui+addi form implies an i64 immediate");
            let (hi, lo) = split_hi_lo(signed)?;
            out.extend_from_slice(&encode_u_type(0x37, rd, hi).to_le_bytes());
            out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, rd, lo)?.to_le_bytes());
        }
        LiForm::Large => encode_large_li_sequence(out, rd, li_bits(imm)?)?,
    }
    Ok(())
}

fn encode_large_li_sequence(out: &mut Vec<u8>, rd: u8, bits: u64) -> Result<()> {
    let bytes = bits.to_be_bytes();
    out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, 0, i64::from(bytes[0]))?.to_le_bytes());
    for byte in bytes.iter().skip(1) {
        out.extend_from_slice(&encode_i_type(0x13, rd, 0b001, rd, 8)?.to_le_bytes());
        out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, rd, i64::from(*byte))?.to_le_bytes());
    }
    Ok(())
}

fn li_signed_i64(imm: i128) -> Option<i64> {
    i64::try_from(imm).ok()
}

fn li_bits(imm: i128) -> Result<u64> {
    if imm < i128::from(i64::MIN) || imm > i128::from(u64::MAX) {
        return Err(CompileError::new(format!("li immediate '{}' does not fit 64 bits", imm), crate::error::Span::default()));
    }
    if imm < 0 {
        Ok((imm as i64) as u64)
    } else {
        Ok(imm as u64)
    }
}

fn encode_address_sequence(out: &mut Vec<u8>, rd: u8, pc: u64, target: u64) -> Result<()> {
    let (hi, lo) = split_hi_lo(relative_offset(pc, target)?)?;
    out.extend_from_slice(&encode_u_type(0x17, rd, hi).to_le_bytes());
    out.extend_from_slice(&encode_i_type(0x13, rd, 0b000, rd, lo)?.to_le_bytes());
    Ok(())
}

fn encode_call_sequence(out: &mut Vec<u8>, pc: u64, target: u64) -> Result<()> {
    let (hi, lo) = split_hi_lo(relative_offset(pc, target)?)?;
    out.extend_from_slice(&encode_u_type(0x17, 1, hi).to_le_bytes());
    out.extend_from_slice(&encode_i_type(0x67, 1, 0b000, 1, lo)?.to_le_bytes());
    Ok(())
}

fn op_size(op: &AsmOp, current_offset: usize, section: SectionKind, op_index: usize, branch_size_mode: BranchSizeMode<'_>) -> usize {
    match op {
        AsmOp::Label(_) => 0,
        AsmOp::Instruction(Instruction::Li { imm, .. }) => li_sequence_size(*imm),
        AsmOp::Instruction(Instruction::La { .. }) => 8,
        AsmOp::Instruction(Instruction::Call { .. }) => 8,
        AsmOp::Instruction(
            Instruction::Beq { .. }
            | Instruction::Bne { .. }
            | Instruction::Blt { .. }
            | Instruction::Bge { .. }
            | Instruction::Bltu { .. }
            | Instruction::Bgeu { .. }
            | Instruction::Beqz { .. }
            | Instruction::Bnez { .. },
        ) => match branch_size_mode {
            BranchSizeMode::Conservative => 8,
            BranchSizeMode::Exact(relaxed) if section == SectionKind::Text && relaxed.contains(&op_index) => 8,
            BranchSizeMode::Exact(_) => 4,
        },
        AsmOp::Instruction(_) => 4,
        AsmOp::Word(_) => 4,
        AsmOp::Byte(_) => 1,
        AsmOp::Ascii(bytes) => bytes.len(),
        AsmOp::Align(bytes) => padding_for(current_offset, *bytes),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiForm {
    /// `addi rd, zero, imm` for a signed 12-bit immediate.
    Addi,
    /// `lui rd, imm >> 12` when the low 12 bits are zero.
    Lui,
    /// `lui` + `addi`.
    LuiAddi,
    /// Byte-by-byte construction for wide immediates.
    Large,
}

fn li_form(imm: i128) -> LiForm {
    let Some(signed) = li_signed_i64(imm) else {
        return LiForm::Large;
    };
    if (-2048..=2047).contains(&signed) {
        return LiForm::Addi;
    }
    if signed & 0xfff == 0 {
        let hi = signed >> 12;
        if (-0x80000..=0x7ffff).contains(&hi) {
            return LiForm::Lui;
        }
    }
    if li_fits_lui_addi_rv64(signed) {
        LiForm::LuiAddi
    } else {
        LiForm::Large
    }
}

fn li_sequence_size(imm: i128) -> usize {
    match li_form(imm) {
        LiForm::Addi | LiForm::Lui => 4,
        LiForm::LuiAddi => 8,
        LiForm::Large => 60,
    }
}

fn write_elf_header(
    out: &mut [u8],
    entry: u64,
    program_header_count: u16,
    section_header_offset: u64,
    section_header_count: u16,
    section_name_index: u16,
) -> Result<()> {
    if out.len() != ELF_HEADER_SIZE {
        return Err(CompileError::new("invalid ELF header buffer size", crate::error::Span::default()));
    }
    out.fill(0);
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes());
    out[18..20].copy_from_slice(&243u16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&entry.to_le_bytes());
    out[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
    out[40..48].copy_from_slice(&section_header_offset.to_le_bytes());
    out[48..52].copy_from_slice(&0u32.to_le_bytes());
    out[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
    out[54..56].copy_from_slice(&(ELF_PROGRAM_HEADER_SIZE as u16).to_le_bytes());
    out[56..58].copy_from_slice(&program_header_count.to_le_bytes());
    out[58..60].copy_from_slice(&(ELF_SECTION_HEADER_SIZE as u16).to_le_bytes());
    out[60..62].copy_from_slice(&section_header_count.to_le_bytes());
    out[62..64].copy_from_slice(&section_name_index.to_le_bytes());
    Ok(())
}

fn write_section_header(
    out: &mut [u8],
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    alignment: u64,
) -> Result<()> {
    if out.len() != ELF_SECTION_HEADER_SIZE {
        return Err(CompileError::new("invalid ELF section header buffer size", crate::error::Span::default()));
    }
    out.fill(0);
    out[0..4].copy_from_slice(&name_offset.to_le_bytes());
    out[4..8].copy_from_slice(&section_type.to_le_bytes());
    out[8..16].copy_from_slice(&flags.to_le_bytes());
    out[16..24].copy_from_slice(&address.to_le_bytes());
    out[24..32].copy_from_slice(&offset.to_le_bytes());
    out[32..40].copy_from_slice(&size.to_le_bytes());
    out[48..56].copy_from_slice(&alignment.to_le_bytes());
    Ok(())
}

fn write_program_header(out: &mut [u8], flags: u32, offset: u64, vaddr: u64, file_size: u64, memory_size: u64) -> Result<()> {
    if out.len() != ELF_PROGRAM_HEADER_SIZE {
        return Err(CompileError::new("invalid ELF program header buffer size", crate::error::Span::default()));
    }
    out.fill(0);
    out[0..4].copy_from_slice(&1u32.to_le_bytes());
    out[4..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out[16..24].copy_from_slice(&vaddr.to_le_bytes());
    out[24..32].copy_from_slice(&vaddr.to_le_bytes());
    out[32..40].copy_from_slice(&file_size.to_le_bytes());
    out[40..48].copy_from_slice(&memory_size.to_le_bytes());
    out[48..56].copy_from_slice(&(ELF_SEGMENT_ALIGN as u64).to_le_bytes());
    Ok(())
}

pub(super) fn strip_comment(line: &str) -> Option<&str> {
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' if !escape => in_string = !in_string,
            '#' if !in_string => return Some(line[..idx].trim()),
            '\\' if in_string => {
                escape = !escape;
                continue;
            }
            _ => {}
        }
        escape = false;
    }
    let trimmed = line.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn parse_ascii_literal(value: &str) -> Result<Vec<u8>> {
    let Some(inner) = value.strip_prefix('"').and_then(|value| value.strip_suffix('"')) else {
        return Err(CompileError::new(format!("invalid .ascii literal '{}'", value), crate::error::Span::default()));
    };

    let mut out = Vec::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.extend_from_slice(ch.to_string().as_bytes());
            continue;
        }

        let escaped = chars
            .next()
            .ok_or_else(|| CompileError::new("unterminated escape sequence in .ascii literal", crate::error::Span::default()))?;
        match escaped {
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            '\\' => out.push(b'\\'),
            '"' => out.push(b'"'),
            'x' => {
                let hi = chars
                    .next()
                    .ok_or_else(|| CompileError::new("incomplete hex escape in .ascii literal", crate::error::Span::default()))?;
                let lo = chars
                    .next()
                    .ok_or_else(|| CompileError::new("incomplete hex escape in .ascii literal", crate::error::Span::default()))?;
                let hex = format!("{}{}", hi, lo);
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|_| CompileError::new(format!("invalid hex escape '\\x{}'", hex), crate::error::Span::default()))?;
                out.push(byte);
            }
            other => {
                return Err(CompileError::new(
                    format!("unsupported escape sequence '\\{}' in .ascii literal", other),
                    crate::error::Span::default(),
                ));
            }
        }
    }

    Ok(out)
}

fn parse_memory_operand(value: &str) -> Result<(i64, u8)> {
    let open = value
        .find('(')
        .ok_or_else(|| CompileError::new(format!("invalid memory operand '{}'", value), crate::error::Span::default()))?;
    let close = value
        .rfind(')')
        .ok_or_else(|| CompileError::new(format!("invalid memory operand '{}'", value), crate::error::Span::default()))?;
    let imm = parse_immediate(value[..open].trim())?;
    let rs1 = parse_register(value[open + 1..close].trim())?;
    Ok((imm, rs1))
}

pub(super) fn memory_operand_offset_and_base(value: &str) -> Option<(i64, &str)> {
    let open = value.find('(')?;
    let close = value.rfind(')')?;
    let offset = parse_immediate(value[..open].trim()).ok()?;
    let base = value[open + 1..close].trim();
    (!base.is_empty()).then_some((offset, base))
}

pub(super) fn small_signed_immediate(value: i64) -> bool {
    (-2048..=2047).contains(&value)
}

pub(super) fn scratch_register_avoiding(registers: &[&str]) -> &'static str {
    for candidate in ["t6", "t5", "t3", "t2", "t1", "t0"] {
        let candidate_id = parse_register(candidate).expect("scratch register name should be valid");
        if registers.iter().all(|register| parse_register(register).ok() != Some(candidate_id)) {
            return candidate;
        }
    }
    "t6"
}

pub(super) fn parse_register(name: &str) -> Result<u8> {
    let reg = match name {
        "zero" | "x0" => 0,
        "ra" | "x1" => 1,
        "sp" | "x2" => 2,
        "gp" | "x3" => 3,
        "tp" | "x4" => 4,
        "t0" | "x5" => 5,
        "t1" | "x6" => 6,
        "t2" | "x7" => 7,
        "s0" | "fp" | "x8" => 8,
        "s1" | "x9" => 9,
        "a0" | "x10" => 10,
        "a1" | "x11" => 11,
        "a2" | "x12" => 12,
        "a3" | "x13" => 13,
        "a4" | "x14" => 14,
        "a5" | "x15" => 15,
        "a6" | "x16" => 16,
        "a7" | "x17" => 17,
        "s2" | "x18" => 18,
        "s3" | "x19" => 19,
        "s4" | "x20" => 20,
        "s5" | "x21" => 21,
        "s6" | "x22" => 22,
        "s7" | "x23" => 23,
        "s8" | "x24" => 24,
        "s9" | "x25" => 25,
        "s10" | "x26" => 26,
        "s11" | "x27" => 27,
        "t3" | "x28" => 28,
        "t4" | "x29" => 29,
        "t5" | "x30" => 30,
        "t6" | "x31" => 31,
        other => return Err(CompileError::new(format!("unknown register '{}'", other), crate::error::Span::default())),
    };
    Ok(reg)
}

pub(super) fn parse_immediate(value: &str) -> Result<i64> {
    if let Some(hex) = value.strip_prefix("-0x") {
        return i64::from_str_radix(hex, 16)
            .map(|value| -value)
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()));
    }
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("+0x")) {
        return i64::from_str_radix(hex, 16)
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()));
    }
    value.parse::<i64>().map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()))
}

fn parse_li_immediate(value: &str) -> Result<i128> {
    if let Some(hex) = value.strip_prefix("-0x") {
        let parsed = i128::from_str_radix(hex, 16)
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()))?;
        return validate_li_immediate(-parsed, value);
    }
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("+0x")) {
        let parsed = u128::from_str_radix(hex, 16)
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()))?;
        if parsed <= u128::from(u64::MAX) {
            return Ok(parsed as i128);
        }
        return Err(CompileError::new(format!("li immediate '{}' does not fit 64 bits", value), crate::error::Span::default()));
    }
    if value.starts_with('-') {
        let parsed = value
            .parse::<i128>()
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()))?;
        validate_li_immediate(parsed, value)
    } else {
        value
            .parse::<u128>()
            .map_err(|_| CompileError::new(format!("invalid immediate '{}'", value), crate::error::Span::default()))
            .and_then(|parsed| {
                if parsed <= u128::from(u64::MAX) {
                    Ok(parsed as i128)
                } else {
                    Err(CompileError::new(format!("li immediate '{}' does not fit 64 bits", value), crate::error::Span::default()))
                }
            })
    }
}

fn validate_li_immediate(parsed: i128, source: &str) -> Result<i128> {
    if (i64::MIN as i128..=u64::MAX as i128).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(CompileError::new(format!("li immediate '{}' does not fit 64 bits", source), crate::error::Span::default()))
    }
}

fn arg(args: &[String], index: usize) -> Result<&str> {
    args.get(index)
        .map(|value| value.as_str())
        .ok_or_else(|| CompileError::new("malformed assembly instruction", crate::error::Span::default()))
}

fn encode_r_type(opcode: u32, rd: u8, funct3: u32, rs1: u8, rs2: u8, funct7: u32) -> u32 {
    (funct7 << 25) | ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | (funct3 << 12) | ((rd as u32) << 7) | opcode
}

fn encode_i_type(opcode: u32, rd: u8, funct3: u32, rs1: u8, imm: i64) -> Result<u32> {
    let imm = encode_signed_bits(imm, 12)?;
    Ok((imm << 20) | ((rs1 as u32) << 15) | (funct3 << 12) | ((rd as u32) << 7) | opcode)
}

fn encode_s_type(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm: i64) -> Result<u32> {
    let imm = encode_signed_bits(imm, 12)?;
    let imm_lo = imm & 0x1f;
    let imm_hi = (imm >> 5) & 0x7f;
    Ok((imm_hi << 25) | ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | (funct3 << 12) | (imm_lo << 7) | opcode)
}

fn encode_b_type(opcode: u32, funct3: u32, rs1: u8, rs2: u8, imm: i64) -> Result<u32> {
    if imm % 2 != 0 {
        return Err(CompileError::new("branch target is not 2-byte aligned", crate::error::Span::default()));
    }
    let imm = encode_signed_bits(imm, 13)?;
    let bit12 = (imm >> 12) & 0x1;
    let bits10_5 = (imm >> 5) & 0x3f;
    let bits4_1 = (imm >> 1) & 0xf;
    let bit11 = (imm >> 11) & 0x1;
    Ok((bit12 << 31)
        | (bits10_5 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | (bits4_1 << 8)
        | (bit11 << 7)
        | opcode)
}

fn encode_u_type(opcode: u32, rd: u8, imm: i64) -> u32 {
    (((imm as i32 as u32) & 0x000f_ffff) << 12) | ((rd as u32) << 7) | opcode
}

fn encode_j_type(opcode: u32, rd: u8, imm: i64) -> Result<u32> {
    if imm % 2 != 0 {
        return Err(CompileError::new("jump target is not 2-byte aligned", crate::error::Span::default()));
    }
    let imm = encode_signed_bits(imm, 21)?;
    let bit20 = (imm >> 20) & 0x1;
    let bits10_1 = (imm >> 1) & 0x3ff;
    let bit11 = (imm >> 11) & 0x1;
    let bits19_12 = (imm >> 12) & 0xff;
    Ok((bit20 << 31) | (bits10_1 << 21) | (bit11 << 20) | (bits19_12 << 12) | ((rd as u32) << 7) | opcode)
}

fn encode_ecall() -> u32 {
    0x0000_0073
}

fn encode_signed_bits(value: i64, bits: u32) -> Result<u32> {
    if !signed_bits_fit(value, bits) {
        return Err(CompileError::new(
            format!("immediate '{}' does not fit {}-bit signed field", value, bits),
            crate::error::Span::default(),
        ));
    }
    Ok((value as i32 as u32) & ((1u32 << bits) - 1))
}

fn signed_bits_fit(value: i64, bits: u32) -> bool {
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << (bits - 1)) - 1;
    value >= min && value <= max
}

fn split_hi_lo(value: i64) -> Result<(i64, i64)> {
    if !li_fits_lui_addi_rv64(value) {
        return Err(CompileError::new(
            format!("value '{}' is outside the supported RV64 LUI/ADDI immediate range", value),
            crate::error::Span::default(),
        ));
    }
    let adjusted = value.checked_add(0x800).ok_or_else(|| {
        CompileError::new(format!("value '{}' overflowed while splitting its immediate", value), crate::error::Span::default())
    })?;
    let hi = adjusted >> 12;
    let lo = value - (hi << 12);
    if !(-2048..=2047).contains(&lo) {
        return Err(CompileError::new(format!("low immediate '{}' is out of range after split", lo), crate::error::Span::default()));
    }
    Ok((hi, lo))
}

fn li_fits_lui_addi_rv64(value: i64) -> bool {
    if !(i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        return false;
    }
    let hi = (value + 0x800) >> 12;
    (-0x80000..=0x7ffff).contains(&hi)
}

fn relative_offset(pc: u64, target: u64) -> Result<i64> {
    i64::try_from(target as i128 - pc as i128)
        .map_err(|_| CompileError::new("relative offset overflowed i64", crate::error::Span::default()))
}

pub(super) fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

pub(super) fn align_frame(value: usize) -> usize {
    align_up(value.max(16), 16)
}

pub(super) fn is_min_call(func: &str) -> bool {
    matches!(func, "min" | "math_min" | "__math_min")
}

pub(super) fn is_void_runtime_requirement_call(func: &str) -> bool {
    matches!(
        func,
        "__ckb_require_maturity"
            | "__ckb_exec_cell_dep_u8_args"
            | "__ckb_exec_cell_dep_hex4"
            | "__ckb_spawn_wait_cell_dep_hex4"
            | "__ckb_require_time"
            | "__ckb_require_epoch_after"
            | "__ckb_require_epoch_relative"
            | "__ckb_require_cell_lock_hash"
            | "__ckb_require_cell_type_hash"
            | "__ckb_require_current_script_args_empty"
            | "__ckb_require_cell_lock_args_empty"
            | "__ckb_require_cell_type_args_empty"
            | "__ckb_require_cell_lock_args_hash"
            | "__ckb_require_cell_type_args_hash"
            | "__ckb_require_cell_lock_args_prefix_hash"
            | "__ckb_require_cell_type_args_prefix_hash"
            | "__ckb_require_cell_lock_args_suffix_hash"
            | "__ckb_require_cell_type_args_suffix_hash"
            | "__ckb_require_cell_lock_script_hash_type"
            | "__ckb_require_cell_type_script_hash_type"
            | "__ckb_require_input_out_point_tx_hash"
            | "__ckb_require_input_out_point"
            | "__ckb_require_metapoint_relative"
            | "__ckb_require_lock_type_metapoint_pairs"
            | "__ckb_require_type_lock_metapoint_pairs"
            | "__ckb_require_lock_type_metapoint_pairs_from_i32_data"
            | "__ckb_require_type_lock_metapoint_pairs_from_i32_data"
            | "__ckb_require_lock_type_metapoint_pairs_from_i32_data_filtered"
            | "__ckb_require_type_lock_metapoint_pairs_from_i32_data_filtered"
            | "__ckb_require_lock_match_master_out_point_pairs_from_data"
            | "__dao_require_header_dep_for_input"
            | "__dao_require_input_since_at_least"
            | "__dao_require_input_relative_epoch_since_at_least"
            | "__xudt_require_owner_mode_input_type"
            | "__xudt_require_owner_mode_type_args"
            | "__xudt_require_owner_mode_type_args_current_script"
            | "__cellscript_require_fungible_type_group_v1"
            | "__xudt_require_group_amount_conserved"
            | "__xudt_require_group_amount_minted"
            | "__xudt_require_group_amount_burned"
            | "__c256_require_u128_product_lte"
            | "__c256_require_u128_product_eq"
            | "__c256_require_u128_sum2_products_lte"
            | "__c256_require_u128_sum2_products_eq"
            | "__ckb_require_witness_size_at_least"
    )
}

pub(super) fn is_runtime_scalar_failclosed_call(func: &str) -> bool {
    matches!(
        func,
        "__ckb_source_input"
            | "__ckb_source_output"
            | "__ckb_source_cell_dep"
            | "__ckb_source_header_dep"
            | "__ckb_source_group_input"
            | "__ckb_source_group_output"
            | "__ckb_since_epoch_absolute"
            | "__ckb_since_epoch_relative"
            | "__ckb_since_block_absolute"
            | "__ckb_since_block_relative"
            | "__ckb_since_timestamp_absolute"
            | "__ckb_since_timestamp_relative"
            | "__ckb_since_decode"
            | "__ckb_since_from_raw_checked"
            | "__ckb_since_as_absolute_block"
            | "__ckb_since_as_relative_block"
            | "__ckb_since_as_absolute_epoch"
            | "__ckb_since_as_relative_epoch"
            | "__ckb_since_as_absolute_timestamp"
            | "__ckb_since_as_relative_timestamp"
            | "__ckb_since_is_relative"
            | "__ckb_since_is_disabled"
            | "__ckb_since_metric"
            | "__ckb_since_value"
            | "__ckb_epoch_duration"
            | "__ckb_epoch_add"
            | "__ckb_epoch_sub"
            | "__ckb_current_role"
            | "__ckb_cell_capacity"
            | "__ckb_cell_occupied_capacity"
            | "__ckb_cell_unoccupied_capacity"
            | "__ckb_cell_output_index"
            | "__ckb_cell_data_size"
            | "__ckb_cell_data_equal"
            | "__ckb_source_bytes_equal"
            | "__ckb_source_bytes_equal_memory"
            | "__ckb_source_bytes_zero"
            | "__ckb_cell_count"
            | "__ckb_cell_has_type"
            | "__ckb_cell_data_u8"
            | "__ckb_cell_lock_size"
            | "__ckb_cell_type_size"
            | "__ckb_cell_lock_u8"
            | "__ckb_cell_type_u8"
            | "__ckb_input_since_at"
            | "__ckb_cell_data_u32_le"
            | "__ckb_cell_data_u64_le"
            | "__ckb_cell_lock_hash_type"
            | "__ckb_cell_type_hash_type"
            | "__ckb_cell_lock_args_empty"
            | "__ckb_cell_type_args_empty"
            | "__dao_accumulated_rate"
            | "__dao_input_accumulated_rate"
            | "__dao_has_dao_type"
            | "__dao_is_deposit_data"
            | "__dao_is_withdrawal_request_data"
            | "__xudt_amount_low"
            | "__xudt_amount_high"
            | "__xudt_owner_mode_input_type_hash"
            | "__ckb_witness_size"
            | "__ckb_witness_count"
            | "__ckb_witness_u8"
            | "__ckb_witness_u32_le"
            | "__ckb_transaction_u32_le"
            | "__ckb_witness_u64_le"
            | "__ckb_witness_bounded_size"
            | "__ckb_witness_bounded_u8"
            | "__ckb_witness_bounded_u32_le"
            | "__ckb_witness_bounded_u64_le"
    )
}

pub(super) fn is_runtime_header_u64_call(func: &str) -> bool {
    matches!(
        func,
        "__env_current_timepoint"
            | "__ckb_header_epoch_number"
            | "__ckb_header_epoch_start_block_number"
            | "__ckb_header_epoch_length"
            | "__ckb_header_dep_epoch_number"
            | "__ckb_header_dep_epoch_start_block_number"
            | "__ckb_header_dep_epoch_length"
            | "__ckb_header_dep_block_number"
            | "__ckb_header_dep_timestamp_millis"
            | "__ckb_input_since"
    )
}

pub(super) fn ckb_source_name(source: u64) -> &'static str {
    match source {
        CKB_SOURCE_INPUT => "Input",
        CKB_SOURCE_OUTPUT => "Output",
        CKB_SOURCE_CELL_DEP => "CellDep",
        CKB_SOURCE_HEADER_DEP => "HeaderDep",
        CKB_SOURCE_GROUP_INPUT => "GroupInput",
        CKB_SOURCE_GROUP_OUTPUT => "GroupOutput",
        source if source == (CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_INPUT) => "GroupInput",
        source if source == (CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_OUTPUT) => "GroupOutput",
        source if source == (CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_CELL_DEP) => "GroupCellDep",
        source if source == (CKB_SOURCE_GROUP_FLAG | CKB_SOURCE_HEADER_DEP) => "GroupHeaderDep",
        _ => "Unknown",
    }
}

fn padding_for(offset: usize, align: usize) -> usize {
    align_up(offset, align) - offset
}

fn pad_to_alignment(out: &mut Vec<u8>, align: usize) {
    let pad = padding_for(out.len(), align);
    out.resize(out.len() + pad, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS: &[(&str, &str)] = &[
        ("add", "add t0, a0, a1"),
        ("addi", "addi t0, t0, -1"),
        ("and", "and t2, a0, a1"),
        ("andi", "andi t2, a0, 7"),
        ("beq", "beq a0, a1, branch_target"),
        ("bge", "bge a0, a1, branch_target"),
        ("bgeu", "bgeu a0, a1, branch_target"),
        ("bgez", "bgez a0, branch_target"),
        ("bgt", "bgt a0, a1, branch_target"),
        ("blt", "blt a1, a0, branch_target"),
        ("bltu", "bltu a1, a0, branch_target"),
        ("bne", "bne a0, a1, branch_target"),
        ("bnez", "bnez a0, branch_target"),
        ("beqz", "beqz a0, branch_target"),
        ("call", "call helper"),
        ("div", "div t5, a0, a1"),
        ("divu", "divu t5, a0, a1"),
        ("ecall", "ecall"),
        ("j", "j done"),
        ("la", "la t3, data_label"),
        ("lbu", "lbu t2, 8(sp)"),
        ("ld", "ld t1, 0(sp)"),
        ("li", "li a0, 8"),
        ("mul", "mul t4, a0, a1"),
        ("mv", "mv s9, a0"),
        ("neg", "neg s6, a0"),
        ("or", "or t3, a0, a1"),
        ("rem", "rem t6, a0, a1"),
        ("remu", "remu t6, a0, a1"),
        ("ret", "ret"),
        ("rori", "rori s3, s3, 32"),
        ("roriw", "roriw s3, s3, 17"),
        ("sb", "sb t1, 8(sp)"),
        ("sd", "sd t0, 0(sp)"),
        ("seqz", "seqz s4, a0"),
        ("sgt", "sgt s2, a0, a1"),
        ("sh", "sh t1, 10(sp)"),
        ("sll", "sll a0, a0, a1"),
        ("slli", "slli s7, a0, 3"),
        ("slt", "slt s0, a1, a0"),
        ("sltu", "sltu s1, a1, a0"),
        ("snez", "snez s5, a0"),
        ("sra", "sra a0, a0, a1"),
        ("srai", "srai a0, a0, 1"),
        ("srl", "srl a0, a0, a1"),
        ("srli", "srli s8, a0, 1"),
        ("sub", "sub t1, a0, a1"),
        ("sw", "sw t1, 12(sp)"),
        ("xor", "xor a0, a0, a1"),
        ("xori", "xori s3, a0, 1"),
    ];

    const INTENTIONALLY_UNSUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS: &[(&str, &str)] = &[
        ("addiw", "addiw a0, a0, 1"),
        ("addw", "addw a0, a0, a1"),
        ("amoadd.w", "amoadd.w a0, a1, (a2)"),
        ("auipc", "auipc a0, 0"),
        ("ble", "ble a0, a1, target"),
        ("bleu", "bleu a0, a1, target"),
        ("blez", "blez a0, target"),
        ("bgtu", "bgtu a0, a1, target"),
        ("bgtz", "bgtz a0, target"),
        ("bltz", "bltz a0, target"),
        ("c.nop", "c.nop"),
        ("csrr", "csrr a0, cycle"),
        ("fence", "fence"),
        ("flw", "flw fa0, 0(sp)"),
        ("jal", "jal ra, target"),
        ("jalr", "jalr zero, 0(ra)"),
        ("jr", "jr ra"),
        ("lb", "lb a0, 0(sp)"),
        ("lh", "lh a0, 0(sp)"),
        ("lhu", "lhu a0, 0(sp)"),
        ("lui", "lui a0, 1"),
        ("lw", "lw a0, 0(sp)"),
        ("lwu", "lwu a0, 0(sp)"),
        ("nop", "nop"),
        ("not", "not a0, a1"),
        ("ori", "ori a0, a0, 1"),
        ("slti", "slti a0, a0, 1"),
        ("sltiu", "sltiu a0, a0, 1"),
        ("subw", "subw a0, a0, a1"),
        ("tail", "tail target"),
    ];

    #[derive(Debug)]
    struct TestProgramHeader {
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        file_size: u64,
        memory_size: u64,
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(&bytes[offset..offset + 2]);
        u16::from_le_bytes(raw)
    }

    fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        u32::from_le_bytes(raw)
    }

    fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(raw)
    }

    fn elf_program_headers(elf: &[u8]) -> Vec<TestProgramHeader> {
        assert!(elf.starts_with(b"\x7fELF"), "expected ELF magic");
        let phoff = usize::try_from(read_u64_le(elf, 32)).expect("program header offset should fit usize");
        let phentsize = usize::from(read_u16_le(elf, 54));
        let phnum = usize::from(read_u16_le(elf, 56));
        assert_eq!(phentsize, ELF_PROGRAM_HEADER_SIZE);

        (0..phnum)
            .map(|index| {
                let offset = phoff + index * phentsize;
                TestProgramHeader {
                    p_type: read_u32_le(elf, offset),
                    flags: read_u32_le(elf, offset + 4),
                    offset: read_u64_le(elf, offset + 8),
                    vaddr: read_u64_le(elf, offset + 16),
                    file_size: read_u64_le(elf, offset + 32),
                    memory_size: read_u64_le(elf, offset + 40),
                }
            })
            .collect()
    }

    fn elf_text_file_offset(elf: &[u8]) -> usize {
        let header = elf_program_headers(elf)
            .into_iter()
            .find(|header| header.p_type == 1 && header.flags & ELF_PF_X != 0)
            .expect("ELF should contain an executable load segment");
        let offset_into_segment = ELF_BASE_ADDR.checked_sub(header.vaddr).expect("text base should be inside load segment");
        usize::try_from(header.offset + offset_into_segment).expect("text file offset should fit usize")
    }

    #[test]
    fn strict_audit_internal_elf_entry_preserves_ckb_stack_pointer() {
        let lines = vec![".section .text".to_string(), ".global entry".to_string(), "entry:".to_string(), "ret".to_string()];

        let elf = assemble_elf_internal(&lines).expect("internal assembler should emit a CKB-loadable ELF");
        let headers = elf_program_headers(&elf);
        assert_eq!(headers.len(), 1, "internal CKB ELF should expose one load segment");
        assert_eq!(headers[0].flags, ELF_PF_R | ELF_PF_X, "code segment should be readable and executable only");
        assert_eq!(headers[0].flags & ELF_PF_W, 0, "code segment must not be writable");
        assert_eq!(headers[0].file_size, headers[0].memory_size, "code segment should not fake stack memory in PT_LOAD");

        let text_offset = elf_text_file_offset(&elf);
        let trampoline = (0..START_TRAMPOLINE_SIZE / 4).map(|index| read_u32_le(&elf, text_offset + index * 4)).collect::<Vec<_>>();
        assert_eq!(trampoline, vec![0x0000_0097, 0x0140_80e7, 0x0000_08b7, 0x05d8_8893, 0x0000_0073]);
        assert!(trampoline[..4].iter().all(|instruction| (instruction >> 7) & 0x1f != 2), "trampoline must not write sp");

        let entry_instruction = read_u32_le(&elf, text_offset + START_TRAMPOLINE_SIZE);
        assert_eq!(entry_instruction, 0x0000_8067, "entry body should start after the 20-byte trampoline");
    }

    #[test]
    fn internal_assembler_relaxes_out_of_range_conditional_branch() {
        let mut lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "beqz a0, far_target".to_string(),
        ];
        for _ in 0..1500 {
            lines.push("addi t0, t0, 0".to_string());
        }
        lines.push("far_target:".to_string());
        lines.push("ret".to_string());

        let elf = assemble_elf_internal(&lines).expect("internal assembler should relax long conditional branches");
        assert!(elf.starts_with(b"\x7fELF"));
    }

    #[test]
    fn internal_assembler_encodes_register_conditional_branches() {
        for mnemonic in ["beq", "bne", "blt", "bge", "bltu", "bgeu"] {
            let lines = vec![
                ".section .text".to_string(),
                ".global entry".to_string(),
                "entry:".to_string(),
                "li a0, 1".to_string(),
                "li a1, 1".to_string(),
                format!("{} a0, a1, target", mnemonic),
                "li a0, 2".to_string(),
                "target:".to_string(),
                "ret".to_string(),
            ];

            let elf = assemble_elf_internal(&lines).unwrap_or_else(|err| panic!("internal assembler should encode {mnemonic}: {err}"));
            assert!(elf.starts_with(b"\x7fELF"), "expected ELF output for {mnemonic}");
        }
    }

    #[test]
    fn internal_assembler_encodes_emitted_instruction_surface() {
        let lines = supported_instruction_surface_lines();

        let elf = assemble_elf_internal(&lines).expect("internal assembler should encode the emitted instruction surface");
        assert!(elf.starts_with(b"\x7fELF"));
    }

    #[test]
    fn internal_assembler_rejects_intentionally_unsupported_mnemonics() {
        for (mnemonic, instruction) in INTENTIONALLY_UNSUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS {
            let lines = vec![
                ".section .text".to_string(),
                ".global entry".to_string(),
                "entry:".to_string(),
                (*instruction).to_string(),
                "target:".to_string(),
                "ret".to_string(),
            ];
            let err = match assemble_elf_internal(&lines) {
                Ok(_) => panic!("internal assembler unexpectedly accepted unsupported mnemonic {mnemonic}"),
                Err(err) => err,
            };
            assert!(
                err.message.contains("unsupported assembly instruction"),
                "unexpected error for unsupported mnemonic {mnemonic}: {err}"
            );
        }
    }

    #[test]
    fn generated_public_assembly_mnemonics_are_declared() {
        let surfaces = [
            ("stdlib", crate::stdlib::StdLib::generate_assembly()),
            ("collections", crate::stdlib::collections::Collections::generate_assembly()),
        ];
        let supported = SUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS.iter().map(|(mnemonic, _)| *mnemonic).collect::<BTreeSet<_>>();
        let mut undeclared = Vec::new();

        for (surface, assembly) in surfaces {
            for (line_number, mnemonic) in emitted_mnemonics(&assembly).into_iter() {
                if !supported.contains(mnemonic.as_str()) {
                    undeclared.push(format!("{surface}:{line_number}: {mnemonic}"));
                }
            }
        }

        assert!(
            undeclared.is_empty(),
            "generated public assembly used mnemonics outside the declared internal assembler surface:\n{}",
            undeclared.join("\n")
        );
    }

    #[test]
    fn bundled_example_codegen_mnemonics_are_declared() {
        let examples = ["amm_pool.cell", "launch.cell", "multisig.cell", "nft.cell", "timelock.cell", "token.cell", "vesting.cell"];
        let supported = SUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS.iter().map(|(mnemonic, _)| *mnemonic).collect::<BTreeSet<_>>();
        let mut undeclared = Vec::new();

        for example in examples {
            let path = camino::Utf8PathBuf::from(format!("{}/examples/{}", env!("CARGO_MANIFEST_DIR"), example));
            let result = crate::compile_file(
                path,
                crate::CompileOptions { target: Some("riscv64-asm".to_string()), ..crate::CompileOptions::default() },
            )
            .unwrap_or_else(|err| panic!("{example} should compile to assembly: {}", err.message));
            let assembly = std::str::from_utf8(&result.artifact_bytes)
                .unwrap_or_else(|err| panic!("{example} emitted invalid utf-8 assembly: {err}"));

            for (line_number, mnemonic) in emitted_mnemonics(assembly).into_iter() {
                if !supported.contains(mnemonic.as_str()) {
                    undeclared.push(format!("{example}:{line_number}: {mnemonic}"));
                }
            }
        }

        assert!(
            undeclared.is_empty(),
            "bundled examples used mnemonics outside the declared internal assembler surface:\n{}",
            undeclared.join("\n")
        );
    }

    fn supported_instruction_surface_lines() -> Vec<String> {
        let mut lines = vec![".section .text".to_string(), ".global entry".to_string(), "entry:".to_string(), "li a1, 4".to_string()];
        for (mnemonic, instruction) in SUPPORTED_INTERNAL_ASSEMBLER_MNEMONICS {
            if !matches!(*mnemonic, "ecall" | "ret") {
                lines.push((*instruction).to_string());
            }
        }
        lines.extend([
            "branch_target:".to_string(),
            "ecall".to_string(),
            "helper:".to_string(),
            "ret".to_string(),
            "done:".to_string(),
            "ret".to_string(),
            ".section .rodata".to_string(),
            "data_label:".to_string(),
            ".word 7".to_string(),
            ".byte 1".to_string(),
            ".ascii \"x\"".to_string(),
            ".align 3".to_string(),
        ]);
        lines
    }

    fn emitted_mnemonics(assembly: &str) -> Vec<(usize, String)> {
        assembly
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let clean = strip_comment(line)?;
                if clean.is_empty() || clean.starts_with('.') || clean.ends_with(':') {
                    return None;
                }
                let mnemonic = clean.split_whitespace().next()?.trim_end_matches(',');
                Some((index + 1, mnemonic.to_string()))
            })
            .collect()
    }

    #[test]
    fn internal_assembler_encodes_small_li_forms_and_boundaries() {
        // ADDI form: signed 12-bit range, one instruction.
        for (imm, size) in [(0i128, 4), (1, 4), (2047, 4), (-2048, 4)] {
            assert_eq!(li_sequence_size(imm), size, "imm {imm}");
            assert_eq!(li_form(imm), LiForm::Addi, "imm {imm}");
        }
        // LUI form: low 12 bits zero, 20-bit signed high part. +2^31 is
        // deliberately absent: a single LUI sign-extends its 20-bit operand,
        // so it cannot produce the positive value (the classifier correctly
        // routes it to the wide construction).
        for imm in [4096i128, -4096, -(1i128 << 31), 0x7ffff000] {
            assert_eq!(li_form(imm), LiForm::Lui, "imm {imm}");
            assert_eq!(li_sequence_size(imm), 4, "imm {imm}");
        }
        // Just outside both single forms: two instructions.
        for imm in [2048i128, -2049, 4097] {
            assert_eq!(li_form(imm), LiForm::LuiAddi, "imm {imm}");
            assert_eq!(li_sequence_size(imm), 8, "imm {imm}");
        }
        // The encoding and the size model agree on every form.
        for imm in [-2049i128, -2048, -1, 0, 1, 2047, 2048, 4095, 4096, 6144, 1 << 31, -(1 << 31), 0x7fffffff, -(1i128 << 31)] {
            let mut encoded = Vec::new();
            encode_li_sequence(&mut encoded, 10, imm).expect("encode li");
            assert_eq!(encoded.len(), li_sequence_size(imm), "size model diverges for imm {imm}");
        }
        // Exact ADDI word for the canonical small constant.
        let mut encoded = Vec::new();
        encode_li_sequence(&mut encoded, 10, 5).unwrap();
        assert_eq!(encoded, 0x00500513u32.to_le_bytes().to_vec());
        // Exact LUI word for 4096: lui a0, 1.
        let mut encoded = Vec::new();
        encode_li_sequence(&mut encoded, 10, 4096).unwrap();
        assert_eq!(encoded, 0x00001537u32.to_le_bytes().to_vec());
    }

    #[test]
    fn internal_assembler_encodes_full_width_li_literals() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 9223372036854775808".to_string(),
            "li a1, 18446744073709551615".to_string(),
            "ret".to_string(),
        ];

        let elf = assemble_elf_internal(&lines).expect("internal assembler should encode u64-width li literals");
        assert!(elf.starts_with(b"\x7fELF"));
    }

    #[test]
    fn li_parser_enforces_the_complete_64_bit_domain() {
        assert_eq!(parse_li_immediate("-0x8000000000000000").unwrap(), i64::MIN as i128);
        assert_eq!(parse_li_immediate("+0xffffffffffffffff").unwrap(), u64::MAX as i128);
        for value in ["-0x8000000000000001", "-9223372036854775809", "0x10000000000000000", "18446744073709551616"] {
            let error = parse_li_immediate(value).expect_err("out-of-domain li literal must fail during parsing");
            assert!(error.message.contains("does not fit 64 bits"), "unexpected error for {value}: {}", error.message);
        }
    }

    #[test]
    fn signed_immediate_parser_accepts_explicit_plus() {
        assert_eq!(parse_immediate("+12").unwrap(), 12);
        assert_eq!(parse_immediate("+0x7ff").unwrap(), 0x7ff);
    }

    #[test]
    fn split_hi_lo_rejects_extreme_values_before_arithmetic() {
        assert!(split_hi_lo(i64::MIN).is_err());
        assert!(split_hi_lo(i64::MAX).is_err());
        assert_eq!(split_hi_lo(i32::MIN as i64).unwrap(), (-0x80000, 0));
        assert_eq!(split_hi_lo(0x7fff_f7ff).unwrap(), (0x7ffff, 0x7ff));
        assert!(split_hi_lo(0x7fff_f800).is_err());
    }

    #[test]
    fn runtime_expression_temp_offsets_are_explicitly_bounded() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.frame_size = RUNTIME_EXPR_TEMP_SIZE + RUNTIME_SCRATCH_SIZE + 16;
        assert!(generator.checked_runtime_expr_temp_offset(0).is_some());
        assert!(generator.checked_runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS - 1).is_some());
        assert_eq!(generator.checked_runtime_expr_temp_offset(RUNTIME_EXPR_TEMP_SLOTS), None);
        assert_eq!(generator.checked_runtime_expr_temp_offset(usize::MAX), None);
    }

    #[test]
    fn rv64_li_boundary_values_materialize_correct_bits() {
        let cases = [(0x7fff_f7ffi128, 8usize), (0x7fff_f800i128, 60usize), (0x7fff_ffffi128, 60usize), (0x8000_0000i128, 60usize)];

        for (value, expected_size) in cases {
            let mut bytes = Vec::new();
            encode_li_sequence(&mut bytes, 10, value).expect("li should encode");
            assert_eq!(bytes.len(), expected_size, "unexpected li size for {value:#x}");
            assert_eq!(simulate_li_sequence(&bytes, 10), value as u64, "li materialized wrong bits for {value:#x}");
        }
    }

    fn simulate_li_sequence(bytes: &[u8], register: usize) -> u64 {
        let mut regs = [0u64; 32];
        for chunk in bytes.chunks_exact(4) {
            let inst = u32::from_le_bytes(chunk.try_into().expect("instruction chunk should be four bytes"));
            let opcode = inst & 0x7f;
            let rd = ((inst >> 7) & 0x1f) as usize;
            let funct3 = (inst >> 12) & 0x7;
            let rs1 = ((inst >> 15) & 0x1f) as usize;
            match (opcode, funct3) {
                (0x37, _) => {
                    regs[rd] = ((inst & 0xffff_f000) as i32 as i64) as u64;
                }
                (0x13, 0b000) => {
                    let imm = sign_extend(inst >> 20, 12);
                    regs[rd] = regs[rs1].wrapping_add(imm as u64);
                }
                (0x13, 0b001) => {
                    let shamt = (inst >> 20) & 0x3f;
                    regs[rd] = regs[rs1] << shamt;
                }
                _ => panic!("unexpected instruction in li sequence: 0x{inst:08x}"),
            }
            regs[0] = 0;
        }
        regs[register]
    }

    fn sign_extend(value: u32, bits: u32) -> i64 {
        let shift = 64 - bits;
        ((u64::from(value) << shift) as i64) >> shift
    }

    #[test]
    fn stack_pointer_offsets_are_emitted_through_helpers() {
        let implementation = include_str!("mod.rs")
            .split("\n    fn emit_runtime_ckb_v014_surface_helpers")
            .next()
            .expect("source should contain runtime helper boundary");
        let offenders = implementation
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let emits_stack_memory =
                    (line.contains("self.emit(format!(") || line.contains("self.emit(\"")) && line.contains("(sp)");
                let emits_stack_addi =
                    (line.contains("self.emit(\"addi ") || line.contains("self.emit(format!(\"addi ")) && line.contains(", sp,");
                let allowed_stack_memory = line.contains("self.emit(format!(\"{} {}, {}(sp)\", opcode, register, offset))");
                let allowed_outgoing_stack_memory = line.contains("self.emit(format!(\"sd {}, {}(sp)\", register, offset))");
                let allowed_stack_addi = line.contains("self.emit(format!(\"addi {}, sp, {}\", rd, offset))");
                ((emits_stack_memory && !allowed_stack_memory && !allowed_outgoing_stack_memory)
                    || (emits_stack_addi && !allowed_stack_addi))
                    .then(|| format!("{}: {}", index + 1, line.trim()))
            })
            .collect::<Vec<_>>();

        assert!(offenders.is_empty(), "stack pointer accesses must go through stack helpers:\n{}", offenders.join("\n"));
    }

    #[test]
    fn large_addi_avoids_clobbering_source_register() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.emit_large_addi("t0", "t6", 2048);
        generator.emit_large_addi("t6", "t6", 4096);

        assert_eq!(generator.assembly, vec!["    li t5, 2048", "    add t0, t6, t5", "    li t5, 4096", "    add t6, t6, t5",]);
    }

    #[test]
    fn sp_addi_large_offsets_clobber_only_destination_register() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.emit_sp_addi("t4", 4096);
        generator.emit_sp_addi("t6", 8192);

        assert_eq!(generator.assembly, vec!["    li t4, 4096", "    add t4, sp, t4", "    li t6, 8192", "    add t6, sp, t6",]);
    }

    #[test]
    fn state_transition_edges_use_explicit_consumed_binding() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.consume_order = vec![1, 2];
        generator.consume_type_names.insert(1, "Offer".to_string());
        generator.consume_type_names.insert(2, "Offer".to_string());
        generator.consume_binding_ids.insert("left".to_string(), 1);
        generator.consume_binding_ids.insert("right".to_string(), 2);

        let state_edge = IrStateTransitionEdge {
            input_binding: Some("right".to_string()),
            output_binding: None,
            type_name: "Offer".to_string(),
            field_name: "state".to_string(),
            from: "Live".to_string(),
            to: "Filled".to_string(),
            from_index: 1,
            to_index: 2,
        };

        assert_eq!(generator.consumed_var_for_state_transition("Offer", &[state_edge]), Some(2));
    }

    #[test]
    fn consumed_schema_params_use_loaded_cell_size_for_field_checks() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        let binding = IrVar { id: 0, name: "auth".to_string(), ty: IrType::Named("MintAuthority".to_string()) };
        let params = vec![IrParam {
            name: "auth".to_string(),
            ty: binding.ty.clone(),
            is_mut: false,
            is_ref: false,
            is_read_ref: false,
            source: ParamSource::Default,
            binding: binding.clone(),
        }];
        let body = IrBody {
            cell_bindings: Vec::new(),
            consume_set: vec![CellPattern {
                operation: "input".to_string(),
                type_hash: None,
                binding: "auth".to_string(),
                fields: Vec::new(),
            }],
            read_refs: Vec::new(),
            create_set: Vec::new(),
            mutate_set: Vec::new(),
            write_intents: Vec::new(),
            bounded_collection_ops: Vec::new(),
            borrow_regions: Vec::new(),
            trusted_external_calls: Vec::new(),
            enforced_claims: Vec::new(),
            blocks: Vec::new(),
        };

        generator.prepare_function_layout(&body, &params);

        let loaded_size_offset =
            generator.cell_buffer_size_offsets.get(&binding.id).copied().expect("consumed input should have size slot");
        assert_eq!(generator.schema_pointer_size_offsets.get(&binding.id), Some(&loaded_size_offset));
    }

    #[test]
    fn unaligned_scalar_load_large_offsets_preserve_live_accumulator() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.emit_unaligned_scalar_load("t4", "t6", "t2", 2048, 2);

        assert_eq!(
            generator.assembly,
            vec![
                "    li t6, 0",
                "    li t5, 2048",
                "    add t5, t4, t5",
                "    lbu t2, 0(t5)",
                "    or t6, t6, t2",
                "    li t5, 2049",
                "    add t5, t4, t5",
                "    lbu t2, 0(t5)",
                "    slli t2, t2, 8",
                "    or t6, t6, t2",
            ]
        );
    }

    #[test]
    fn aligned_cell_buffer_u64_load_uses_one_native_instruction() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.cell_buffer_offsets.insert(7, 64);

        generator.emit_schema_scalar_load(7, "t4", "t0", "t2", 8, 8);

        assert_eq!(generator.assembly, vec!["    # cellscript abi: aligned u64 schema load var7 offset=8", "    ld t0, 8(t4)"]);
    }

    #[test]
    fn unaligned_or_unproven_schema_u64_load_stays_bytewise() {
        let mut unaligned = CodeGenerator::new(CodegenOptions::default());
        unaligned.cell_buffer_offsets.insert(7, 64);
        unaligned.emit_schema_scalar_load(7, "t4", "t0", "t2", 1, 8);
        assert_eq!(unaligned.assembly.iter().filter(|line| line.contains("lbu t2")).count(), 8);
        assert!(!unaligned.assembly.iter().any(|line| line.contains("ld t0")));

        let mut unproven = CodeGenerator::new(CodegenOptions::default());
        unproven.emit_schema_scalar_load(7, "t4", "t0", "t2", 0, 8);
        assert_eq!(unproven.assembly.iter().filter(|line| line.contains("lbu t2")).count(), 8);
        assert!(!unproven.assembly.iter().any(|line| line.contains("ld t0")));
    }

    #[test]
    fn schema_size_facts_elide_only_until_the_size_slot_is_reused() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());

        generator.emit_dominating_schema_exact_size_check(80, 8, "Token");
        let after_first_check = generator.assembly.len();
        generator.emit_loaded_schema_exact_size_check(80, 8, "Token");
        generator.emit_loaded_schema_bounds_check(80, 8, "Token.amount");
        assert_eq!(
            generator.assembly.len(),
            after_first_check + 3,
            "only evidence comments and a zero-byte block boundary should remain"
        );
        assert!(generator.assembly.last().is_some_and(|line| line.contains("schema_proof_boundary")));

        generator.invalidate_schema_size_facts(80);
        generator.emit_loaded_schema_bounds_check(80, 8, "Token.amount reloaded");
        assert!(generator.assembly.len() > after_first_check + 2, "a reused size slot must be checked again");
    }

    #[test]
    fn generated_large_offsets_are_normalized_before_assembly() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.emit("sd t0, 2048(sp)");
        generator.emit("ld t6, 2056(sp)");
        generator.emit("lbu t2, 2048(t4)");
        generator.emit("addi t0, t4, 2048");
        generator.emit("sb t0, 4096(t6)");

        assert_eq!(
            generator.assembly,
            vec![
                "    li t6, 2048",
                "    add t6, sp, t6",
                "    sd t0, 0(t6)",
                "    li t5, 2056",
                "    add t5, sp, t5",
                "    ld t6, 0(t5)",
                "    li t6, 2048",
                "    add t6, t4, t6",
                "    lbu t2, 0(t6)",
                "    li t6, 2048",
                "    add t0, t4, t6",
                "    li t5, 4096",
                "    add t5, t6, t5",
                "    sb t0, 0(t5)",
            ]
        );
    }

    #[test]
    fn read_ref_runtime_fallback_records_cell_buffer_state() {
        let mut generator = CodeGenerator::new(CodegenOptions::default());
        generator.frame_size = align_frame(RUNTIME_EXPR_TEMP_SIZE + RUNTIME_SCRATCH_SIZE + 16);
        let dest = IrVar { id: 42, name: "cfg".to_string(), ty: IrType::Named("Config".to_string()) };
        generator.read_ref_indices.insert(dest.id, 0);

        generator.emit_read_ref(&dest, "Config").expect("read_ref fallback should lower");

        let size_offset = generator.runtime_scratch_size_offset();
        let buffer_offset = generator.runtime_scratch_buffer_offset();
        assert_eq!(generator.schema_pointer_size_offsets.get(&dest.id), Some(&size_offset));
        assert_eq!(generator.cell_buffer_size_offsets.get(&dest.id), Some(&size_offset));
        assert_eq!(generator.cell_buffer_offsets.get(&dest.id), Some(&buffer_offset));
    }

    #[test]
    fn generated_stdlib_assembly_is_internal_assembler_clean() {
        let lines = crate::stdlib::StdLib::generate_assembly().lines().map(|line| line.to_string()).collect::<Vec<_>>();

        let elf = assemble_elf_internal(&lines).expect("generated stdlib assembly should assemble internally");
        assert!(elf.starts_with(b"\x7fELF"));
    }

    #[test]
    fn generated_collection_assembly_is_internal_assembler_clean() {
        let lines =
            crate::stdlib::collections::Collections::generate_assembly().lines().map(|line| line.to_string()).collect::<Vec<_>>();

        let elf = assemble_elf_internal(&lines).expect("generated collection assembly should assemble internally");
        assert!(elf.starts_with(b"\x7fELF"));
    }

    #[test]
    fn internal_assembler_rejects_unresolved_call_targets() {
        let lines = vec![".section .text".to_string(), ".global main".to_string(), "main:".to_string(), "call missing".to_string()];
        let err = assemble_elf_internal(&lines).unwrap_err();

        assert!(err.message.contains("unknown assembly label 'missing'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn elf_assembly_classifies_unresolved_symbols() {
        let lines = vec![".section .text".to_string(), ".global main".to_string(), "main:".to_string(), "call missing".to_string()];
        let err = assemble_generated_elf(&lines).unwrap_err();

        assert_eq!(err.code.as_deref(), Some("E2200"));
        assert!(err.message.contains("unresolved call target"), "unexpected error: {}", err.message);
    }

    #[test]
    fn internal_assembler_relaxes_out_of_range_register_conditional_branch() {
        for mnemonic in ["beq", "bne", "blt", "bge", "bltu", "bgeu"] {
            let mut lines = vec![
                ".section .text".to_string(),
                ".global entry".to_string(),
                "entry:".to_string(),
                "li a0, 0".to_string(),
                "li a1, 0".to_string(),
                format!("{} a0, a1, far_target", mnemonic),
            ];
            for _ in 0..1500 {
                lines.push("addi t0, t0, 0".to_string());
            }
            lines.push("far_target:".to_string());
            lines.push("ret".to_string());

            let plan = MachineLayoutPlan::build(&lines).unwrap_or_else(|err| panic!("machine layout should relax {mnemonic}: {err}"));
            assert_eq!(plan.metrics.relaxed_branch_count, 1, "expected one relaxed branch for {mnemonic}");
            let elf = assemble_elf_internal(&lines).unwrap_or_else(|err| panic!("internal assembler should relax {mnemonic}: {err}"));
            assert!(elf.starts_with(b"\x7fELF"), "expected ELF output for relaxed {mnemonic}");
        }
    }

    #[test]
    fn machine_layout_plan_reports_branch_relaxation_metrics() {
        let mut lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "beqz a0, far_target".to_string(),
        ];
        for _ in 0..1500 {
            lines.push("addi t0, t0, 0".to_string());
        }
        lines.push("far_target:".to_string());
        lines.push("ret".to_string());

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        assert_eq!(plan.metrics.relaxed_branch_count, 1);
        assert!(
            plan.metrics.max_cond_branch_abs_distance > 4096,
            "synthetic branch should exceed RV64 B-type range: {:?}",
            plan.metrics
        );
        assert_eq!(plan.metrics.text_size, plan.parsed.section_size(SectionKind::Text));
        assert_eq!(plan.metrics.covered_text_op_count, plan.metrics.executable_text_op_count);
        assert!(plan.metrics.executable_text_op_count > 1500, "synthetic text ops should be visible: {:?}", plan.metrics);
        assert_eq!(plan.metrics.layout_order_block_count, plan.metrics.machine_block_count);
        assert_eq!(plan.metrics.layout_order_text_size, plan.metrics.text_size);
        assert_eq!(plan.metrics.conditional_branch_block_count, 1);
        assert!(plan.metrics.machine_cfg_edge_count >= 2, "far branch CFG edges should be visible: {:?}", plan.metrics);
        assert_eq!(plan.metrics.machine_call_edge_count, 0);
        assert_eq!(plan.metrics.unreachable_machine_block_count, 0);
        assert!(plan.metrics.machine_block_count >= 2, "far branch should produce multiple machine blocks: {:?}", plan.metrics);
        assert!(
            plan.metrics.max_machine_block_size > 4096,
            "large fallthrough block should be visible in layout metrics: {:?}",
            plan.metrics
        );
    }

    #[test]
    fn machine_layout_plan_builds_explicit_machine_blocks() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "beqz a0, done".to_string(),
            "li a0, 1".to_string(),
            "j done".to_string(),
            "done:".to_string(),
            "ret".to_string(),
        ];

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        let cfg = &plan.cfg;
        let blocks = &cfg.blocks;
        assert_eq!(blocks.len(), 3, "expected entry, fallthrough, and done blocks: {:?}", blocks);
        assert_eq!(blocks[0].label.as_deref(), Some("entry"));
        assert_eq!(blocks[0].terminator, MachineTerminator::ConditionalBranch { target: "done".to_string() });
        assert_eq!(blocks[1].terminator, MachineTerminator::Jump { target: "done".to_string() });
        assert_eq!(blocks[2].label.as_deref(), Some("done"));
        assert_eq!(blocks[2].terminator, MachineTerminator::Return);

        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(plan.order.block_order, vec![0, 1, 2]);
        assert_eq!(plan.order.placed_blocks.len(), 3);
        assert_eq!(
            plan.order.placed_blocks,
            vec![
                MachinePlacedBlock { block_index: 0, byte_start: 0, byte_size: cfg.blocks[0].byte_size },
                MachinePlacedBlock { block_index: 1, byte_start: cfg.blocks[0].byte_size, byte_size: cfg.blocks[1].byte_size },
                MachinePlacedBlock {
                    block_index: 2,
                    byte_start: cfg.blocks[0].byte_size + cfg.blocks[1].byte_size,
                    byte_size: cfg.blocks[2].byte_size
                },
            ]
        );
        assert_eq!(plan.order.text_size, plan.metrics.text_size);
        assert_eq!(plan.metrics.executable_text_op_count, 5);
        assert_eq!(plan.metrics.covered_text_op_count, 5);
        assert_eq!(plan.metrics.layout_order_block_count, 3);
        assert_eq!(
            cfg.edges,
            vec![
                MachineCfgEdge { from: 0, to: 2, kind: MachineCfgEdgeKind::ConditionalTaken },
                MachineCfgEdge { from: 0, to: 1, kind: MachineCfgEdgeKind::ConditionalFallthrough },
                MachineCfgEdge { from: 1, to: 2, kind: MachineCfgEdgeKind::Jump },
            ]
        );
        assert_eq!(unreachable_machine_block_count(&plan.parsed, cfg), 0);
    }

    #[test]
    fn machine_layout_plan_builds_register_conditional_branch_blocks() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "li a1, 0".to_string(),
            "bgeu a0, a1, done".to_string(),
            "li a0, 1".to_string(),
            "j done".to_string(),
            "done:".to_string(),
            "ret".to_string(),
        ];

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        let cfg = &plan.cfg;
        assert_eq!(cfg.blocks.len(), 3, "expected entry, fallthrough, and done blocks: {:?}", cfg.blocks);
        assert_eq!(cfg.blocks[0].label.as_deref(), Some("entry"));
        assert_eq!(cfg.blocks[0].terminator, MachineTerminator::ConditionalBranch { target: "done".to_string() });
        assert_eq!(
            cfg.edges,
            vec![
                MachineCfgEdge { from: 0, to: 2, kind: MachineCfgEdgeKind::ConditionalTaken },
                MachineCfgEdge { from: 0, to: 1, kind: MachineCfgEdgeKind::ConditionalFallthrough },
                MachineCfgEdge { from: 1, to: 2, kind: MachineCfgEdgeKind::Jump },
            ]
        );
    }

    #[test]
    fn machine_cfg_tracks_call_edges_to_local_helpers() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "call local_helper".to_string(),
            "ret".to_string(),
            "local_helper:".to_string(),
            "li a0, 0".to_string(),
            "ret".to_string(),
        ];

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        let cfg = &plan.cfg;
        assert_eq!(cfg.blocks.len(), 2, "expected entry and local helper blocks: {:?}", cfg.blocks);
        assert_eq!(cfg.blocks[0].label.as_deref(), Some("entry"));
        assert_eq!(cfg.blocks[1].label.as_deref(), Some("local_helper"));
        assert!(
            cfg.edges.contains(&MachineCfgEdge { from: 0, to: 1, kind: MachineCfgEdgeKind::Call }),
            "call edge to local helper should be explicit: {:?}",
            cfg.edges
        );
        assert_eq!(plan.metrics.machine_call_edge_count, 1);
        assert_eq!(unreachable_machine_block_count(&plan.parsed, cfg), 0);
    }

    #[test]
    fn machine_reachability_uses_entry_label_not_every_global() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "ret".to_string(),
            ".global unused_export".to_string(),
            "unused_export:".to_string(),
            "li a0, 1".to_string(),
            "ret".to_string(),
        ];

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        assert_eq!(plan.parsed.entry_label.as_deref(), Some("entry"));
        assert_eq!(plan.cfg.blocks.len(), 2, "expected entry and unused export blocks: {:?}", plan.cfg.blocks);
        assert_eq!(plan.metrics.unreachable_machine_block_count, 1);
        assert_eq!(unreachable_machine_block_count(&plan.parsed, &plan.cfg), 1);
    }

    #[test]
    fn machine_layout_order_rejects_missing_duplicate_or_unknown_blocks() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "beqz a0, done".to_string(),
            "li a0, 1".to_string(),
            "j done".to_string(),
            "done:".to_string(),
            "ret".to_string(),
        ];

        let plan = MachineLayoutPlan::build(&lines).expect("machine layout plan");
        assert!(validate_machine_layout_order(&plan.cfg, &[0, 1]).is_err());
        assert!(validate_machine_layout_order(&plan.cfg, &[0, 1, 1]).is_err());
        assert!(validate_machine_layout_order(&plan.cfg, &[0, 1, 3]).is_err());
        let permuted = build_machine_layout_order(&plan.cfg, vec![2, 0, 1]).expect("permuted layout order should be valid");
        assert_eq!(permuted.block_order, vec![2, 0, 1]);
        assert_eq!(permuted.placed_blocks[0].block_index, 2);
        assert_eq!(permuted.placed_blocks[0].byte_start, 0);
        assert_eq!(permuted.placed_blocks[1].byte_start, plan.cfg.blocks[2].byte_size);
        assert_eq!(permuted.text_size, plan.order.text_size);
    }

    #[test]
    fn machine_layout_plan_rejects_branch_target_outside_text() {
        let lines = vec![
            ".section .text".to_string(),
            ".global entry".to_string(),
            "entry:".to_string(),
            "li a0, 0".to_string(),
            "beqz a0, data_label".to_string(),
            "ret".to_string(),
            ".section .rodata".to_string(),
            "data_label:".to_string(),
            ".word 1".to_string(),
        ];

        let err = MachineLayoutPlan::build(&lines).expect_err("branch targets outside text blocks should be rejected");
        assert!(err.message.contains("does not start a machine block"), "unexpected error for invalid CFG target: {}", err.message);
    }

    #[test]
    fn generated_functions_use_shared_epilogue_tail() {
        let ir = IrModule {
            name: "shape_test".to_string(),
            entry_selection: crate::ir::IrEntrySelection::Legacy,
            items: vec![IrItem::Action(IrAction {
                name: "shape".to_string(),
                entry_trigger: None,
                source_dispositions: vec![],
                audit_claims: vec![],
                params: vec![],
                return_type: Some(IrType::U64),
                state_transition_edges: vec![],
                protocol_role_candidates: vec![],
                effect_class: EffectClass::Pure,
                scheduler_hints: SchedulerHints::default(),
                body: IrBody {
                    cell_bindings: Vec::new(),
                    consume_set: vec![],
                    read_refs: vec![],
                    create_set: vec![],
                    mutate_set: vec![],
                    write_intents: vec![],
                    bounded_collection_ops: vec![],
                    borrow_regions: vec![],
                    trusted_external_calls: vec![],
                    enforced_claims: vec![],
                    blocks: vec![IrBlock {
                        id: BlockId(0),
                        instructions: vec![],
                        terminator: IrTerminator::Return(Some(IrOperand::Const(IrConst::U64(7)))),
                        runtime_error: None,
                    }],
                },
            })],
            external_type_defs: vec![],
            external_callable_abis: vec![],
            enum_fixed_sizes: HashMap::new(),
            enum_layouts: HashMap::new(),
        };
        let assembly = CodeGenerator::new(CodegenOptions::default()).generate(&ir, ArtifactFormat::RiscvAssembly).unwrap();
        let assembly = String::from_utf8(assembly).unwrap();
        let shape_start = assembly.find("shape:\n").expect("shape function label");
        let runtime_start =
            assembly[shape_start..].find(".section .text").map(|offset| shape_start + offset).unwrap_or(assembly.len());
        let shape_assembly = &assembly[shape_start..runtime_start];

        assert!(shape_assembly.contains("j .Lshape_epilogue"), "return sites should jump to the shared epilogue:\n{}", shape_assembly);
        assert_eq!(
            shape_assembly.matches(".Lshape_epilogue:").count(),
            1,
            "a function should emit one shared epilogue label:\n{}",
            shape_assembly
        );
        assert_eq!(
            shape_assembly.matches("ret").count(),
            1,
            "a function should emit one physical return in its shared epilogue:\n{}",
            shape_assembly
        );
    }
}
