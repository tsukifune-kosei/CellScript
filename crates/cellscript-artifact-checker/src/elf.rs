use crate::schema::MachineRange;

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const EM_RISCV: u16 = 243;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_R: u32 = 4;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfErrorKind {
    Truncated,
    InvalidHeader,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedType,
    UnsupportedMachine,
    InvalidTable,
    InvalidSection,
    ProhibitedLinkState,
    MissingText,
    InvalidInstruction,
    InvalidBranchTarget,
    BudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfParseError {
    pub kind: ElfErrorKind,
    pub message: String,
}

impl ElfParseError {
    fn new(kind: ElfErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl std::fmt::Display for ElfParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ElfParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    pub name: String,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
}

impl ElfSection {
    pub fn range(&self) -> MachineRange {
        MachineRange { start: self.address, end: self.address.saturating_add(self.size) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfSegment {
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedControlFlow {
    pub address: u64,
    pub target: u64,
    pub kind: DecodedControlFlowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub word: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackAdjustment {
    pub address: u64,
    pub delta: i64,
}

struct DecodedText {
    instructions: Vec<DecodedInstruction>,
    stack_adjustments: Vec<StackAdjustment>,
    syscall_addresses: Vec<u64>,
    control_flow: Vec<DecodedControlFlow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedControlFlowKind {
    ConditionalBranch,
    DirectJump,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedElf {
    pub entry: u64,
    pub sections: Vec<ElfSection>,
    pub segments: Vec<ElfSegment>,
    pub text: ElfSection,
    pub rodata: ElfSection,
    pub instruction_count: u64,
    pub instructions: Vec<DecodedInstruction>,
    pub stack_adjustments: Vec<StackAdjustment>,
    pub syscall_addresses: Vec<u64>,
    pub control_flow: Vec<DecodedControlFlow>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfSummary {
    pub class: String,
    pub endian: String,
    pub machine: String,
    pub entry: u64,
    pub text_range: MachineRange,
    pub text_size_bytes: u64,
    pub rodata_range: MachineRange,
    pub rodata_size_bytes: u64,
    pub instruction_count: u64,
    pub syscall_count: usize,
    pub section_count: usize,
    pub load_segment_count: usize,
}

impl ParsedElf {
    pub fn summary(&self) -> ElfSummary {
        ElfSummary {
            class: "ELF64".to_string(),
            endian: "little".to_string(),
            machine: "RISC-V".to_string(),
            entry: self.entry,
            text_range: self.text.range(),
            text_size_bytes: self.text.size,
            rodata_range: self.rodata.range(),
            rodata_size_bytes: self.rodata.size,
            instruction_count: self.instruction_count,
            syscall_count: self.syscall_addresses.len(),
            section_count: self.sections.len(),
            load_segment_count: self.segments.len(),
        }
    }

    pub fn bytes_for_range<'a>(&self, artifact: &'a [u8], range: MachineRange) -> Result<&'a [u8], ElfParseError> {
        let section = self.sections.iter().find(|section| section.range().contains_range(range)).ok_or_else(|| {
            ElfParseError::new(
                ElfErrorKind::InvalidSection,
                format!("machine range {:#x}..{:#x} is outside all ELF sections", range.start, range.end),
            )
        })?;
        let relative = range
            .start
            .checked_sub(section.address)
            .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "machine range begins before its ELF section"))?;
        let start = section
            .offset
            .checked_add(relative)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "machine range file offset overflows usize"))?;
        let len = usize::try_from(range.len())
            .map_err(|_| ElfParseError::new(ElfErrorKind::InvalidSection, "machine range length overflows usize"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "machine range end overflows usize"))?;
        artifact.get(start..end).ok_or_else(|| ElfParseError::new(ElfErrorKind::Truncated, "machine range exceeds artifact bytes"))
    }
}

pub fn parse_elf(bytes: &[u8], max_instructions: u64) -> Result<ParsedElf, ElfParseError> {
    if bytes.len() < ELF64_HEADER_SIZE {
        return Err(ElfParseError::new(ElfErrorKind::Truncated, "ELF header is truncated"));
    }
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(ElfParseError::new(ElfErrorKind::InvalidHeader, "artifact is not ELF"));
    }
    if bytes[4] != 2 {
        return Err(ElfParseError::new(ElfErrorKind::UnsupportedClass, "checker requires ELF64"));
    }
    if bytes[5] != 1 {
        return Err(ElfParseError::new(ElfErrorKind::UnsupportedEndian, "checker requires little-endian ELF"));
    }
    if bytes[6] != 1 || bytes[7..16].iter().any(|byte| *byte != 0) || read_u32(bytes, 20)? != 1 || read_u32(bytes, 48)? != 0 {
        return Err(ElfParseError::new(ElfErrorKind::InvalidHeader, "ELF version is not 1"));
    }
    if read_u16(bytes, 16)? != ET_EXEC {
        return Err(ElfParseError::new(ElfErrorKind::UnsupportedType, "checker requires ET_EXEC"));
    }
    if read_u16(bytes, 18)? != EM_RISCV {
        return Err(ElfParseError::new(ElfErrorKind::UnsupportedMachine, "checker requires EM_RISCV"));
    }
    if usize::from(read_u16(bytes, 52)?) != ELF64_HEADER_SIZE {
        return Err(ElfParseError::new(ElfErrorKind::InvalidHeader, "unexpected ELF64 header size"));
    }

    let entry = read_u64(bytes, 24)?;
    let program_offset = read_u64(bytes, 32)?;
    let section_offset = read_u64(bytes, 40)?;
    let program_entry_size = usize::from(read_u16(bytes, 54)?);
    let program_count = usize::from(read_u16(bytes, 56)?);
    let section_entry_size = usize::from(read_u16(bytes, 58)?);
    let section_count = usize::from(read_u16(bytes, 60)?);
    let shstr_index = usize::from(read_u16(bytes, 62)?);

    if program_count == 0 || program_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(ElfParseError::new(ElfErrorKind::InvalidTable, "ELF must have standard ELF64 program headers"));
    }
    if section_count < 4 || section_entry_size != ELF64_SECTION_HEADER_SIZE || shstr_index >= section_count {
        return Err(ElfParseError::new(
            ElfErrorKind::InvalidTable,
            "ELF must contain null, .text, .rodata, and .shstrtab section headers",
        ));
    }

    let program_table = checked_table(bytes, program_offset, program_entry_size, program_count, "program header")?;
    let mut segments = Vec::new();
    for header in program_table.chunks_exact(program_entry_size) {
        if read_u32(header, 0)? != PT_LOAD {
            return Err(ElfParseError::new(ElfErrorKind::ProhibitedLinkState, "checker permits only PT_LOAD program headers"));
        }
        let segment = ElfSegment {
            flags: read_u32(header, 4)?,
            offset: read_u64(header, 8)?,
            virtual_address: read_u64(header, 16)?,
            file_size: read_u64(header, 32)?,
            memory_size: read_u64(header, 40)?,
        };
        checked_file_range(bytes, segment.offset, segment.file_size, "PT_LOAD")?;
        if segment.memory_size < segment.file_size {
            return Err(ElfParseError::new(ElfErrorKind::InvalidTable, "PT_LOAD memory size is smaller than file size"));
        }
        if segment.flags != PF_R | PF_X {
            return Err(ElfParseError::new(
                ElfErrorKind::ProhibitedLinkState,
                "CellScript ELF PT_LOAD segments must be read/execute and never writable",
            ));
        }
        segments.push(segment);
    }
    if segments.is_empty() || !segments.iter().any(|segment| segment.flags & PF_X != 0 && segment_contains(segment, entry)) {
        return Err(ElfParseError::new(ElfErrorKind::InvalidTable, "ELF entry is not contained in an executable PT_LOAD segment"));
    }

    let section_table = checked_table(bytes, section_offset, section_entry_size, section_count, "section header")?;
    let string_header = section_table
        .get(shstr_index * section_entry_size..(shstr_index + 1) * section_entry_size)
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidTable, "section string table header is missing"))?;
    if read_u32(string_header, 4)? != SHT_STRTAB || read_u64(string_header, 8)? != 0 || read_u64(string_header, 16)? != 0 {
        return Err(ElfParseError::new(ElfErrorKind::InvalidSection, "section-name table has an invalid type, flags, or address"));
    }
    let string_offset = read_u64(string_header, 24)?;
    let string_size = read_u64(string_header, 32)?;
    let strings = checked_file_range(bytes, string_offset, string_size, ".shstrtab")?;

    let mut sections = Vec::with_capacity(section_count.saturating_sub(1));
    for (index, header) in section_table.chunks_exact(section_entry_size).enumerate() {
        if index == 0 {
            if header.iter().any(|byte| *byte != 0) {
                return Err(ElfParseError::new(ElfErrorKind::InvalidSection, "ELF null section header is not zero"));
            }
            continue;
        }
        let name_offset = usize::try_from(read_u32(header, 0)?)
            .map_err(|_| ElfParseError::new(ElfErrorKind::InvalidSection, "section name offset overflows usize"))?;
        let name = read_c_string(strings, name_offset)?;
        let section = ElfSection {
            name,
            section_type: read_u32(header, 4)?,
            flags: read_u64(header, 8)?,
            address: read_u64(header, 16)?,
            offset: read_u64(header, 24)?,
            size: read_u64(header, 32)?,
        };
        checked_file_range(bytes, section.offset, section.size, &section.name)?;
        if matches!(section.section_type, SHT_RELA | SHT_DYNAMIC | SHT_REL | SHT_DYNSYM)
            || matches!(section.name.as_str(), ".dynamic" | ".dynsym" | ".dynstr" | ".interp" | ".plt" | ".got" | ".got.plt")
        {
            return Err(ElfParseError::new(
                ElfErrorKind::ProhibitedLinkState,
                format!("prohibited dynamic or relocation section '{}'", section.name),
            ));
        }
        sections.push(section);
    }
    sections.sort_by(|a, b| a.name.cmp(&b.name));
    if sections.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(ElfParseError::new(ElfErrorKind::InvalidSection, "ELF contains duplicate section names"));
    }
    if sections.len() != 3
        || sections.iter().map(|section| section.name.as_str()).collect::<Vec<_>>() != [".rodata", ".shstrtab", ".text"]
    {
        return Err(ElfParseError::new(
            ElfErrorKind::InvalidSection,
            "checker permits exactly .text, .rodata, and .shstrtab sections",
        ));
    }

    let text = sections
        .iter()
        .find(|section| section.name == ".text")
        .cloned()
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::MissingText, "ELF has no .text section"))?;
    let rodata = sections
        .iter()
        .find(|section| section.name == ".rodata")
        .cloned()
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "ELF has no .rodata section"))?;
    if text.section_type != SHT_PROGBITS || text.flags != SHF_ALLOC | SHF_EXECINSTR || text.size == 0 || text.size % 4 != 0 {
        return Err(ElfParseError::new(ElfErrorKind::InvalidSection, ".text must be non-empty, executable, and four-byte aligned"));
    }
    if rodata.section_type != SHT_PROGBITS || rodata.flags != SHF_ALLOC {
        return Err(ElfParseError::new(ElfErrorKind::InvalidSection, ".rodata must not be executable"));
    }
    if !text.range().contains(entry) {
        return Err(ElfParseError::new(ElfErrorKind::InvalidSection, "ELF entry is outside .text"));
    }
    for section in [&text, &rodata] {
        if !segments.iter().any(|segment| segment_contains_range(segment, section.address, section.size)) {
            return Err(ElfParseError::new(
                ElfErrorKind::InvalidSection,
                format!("ELF section '{}' is outside PT_LOAD mappings", section.name),
            ));
        }
    }

    let instruction_count = text.size / 4;
    if instruction_count > max_instructions {
        return Err(ElfParseError::new(
            ElfErrorKind::BudgetExceeded,
            format!("ELF instruction count {} exceeds budget {}", instruction_count, max_instructions),
        ));
    }
    let text_bytes = checked_file_range(bytes, text.offset, text.size, ".text")?;
    let decoded = validate_instructions(text_bytes, text.address, text.range())?;

    Ok(ParsedElf {
        entry,
        sections,
        segments,
        text,
        rodata,
        instruction_count,
        instructions: decoded.instructions,
        stack_adjustments: decoded.stack_adjustments,
        syscall_addresses: decoded.syscall_addresses,
        control_flow: decoded.control_flow,
    })
}

fn validate_instructions(bytes: &[u8], base: u64, text_range: MachineRange) -> Result<DecodedText, ElfParseError> {
    let mut instructions = Vec::new();
    let mut stack_adjustments = Vec::new();
    let mut syscalls = Vec::new();
    let mut control_flow = Vec::new();
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let address = base + (index as u64) * 4;
        let opcode = word & 0x7f;
        if !instruction_is_allowed(word) {
            return Err(ElfParseError::new(
                ElfErrorKind::InvalidInstruction,
                format!("instruction {:#010x} at {:#x} is outside the CellScript RV64 allowlist", word, address),
            ));
        }
        validate_stack_pointer_write(bytes, index, word, address, &mut stack_adjustments)?;
        instructions.push(DecodedInstruction { address, word });
        if word == 0x0000_0073 {
            syscalls.push(address);
        }
        let target = match opcode {
            0x63 => Some((branch_target(address, word), DecodedControlFlowKind::ConditionalBranch)),
            0x6f => Some((jal_target(address, word), DecodedControlFlowKind::DirectJump)),
            0x67 if word != 0x0000_8067 => {
                Some((decode_call_target(bytes, index, word, address)?, DecodedControlFlowKind::DirectJump))
            }
            _ => None,
        };
        if let Some((target, kind)) = target {
            if target % 4 != 0 || !text_range.contains(target) {
                return Err(ElfParseError::new(
                    ElfErrorKind::InvalidBranchTarget,
                    format!("control-flow target {:#x} from {:#x} is outside aligned .text", target, address),
                ));
            }
            control_flow.push(DecodedControlFlow { address, target, kind });
        }
    }
    Ok(DecodedText { instructions, stack_adjustments, syscall_addresses: syscalls, control_flow })
}

fn decode_call_target(bytes: &[u8], index: usize, word: u32, address: u64) -> Result<u64, ElfParseError> {
    let rd = (word >> 7) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = (word >> 15) & 0x1f;
    if rd != 1 || rs1 != 1 || funct3 != 0 || index == 0 {
        return Err(ElfParseError::new(
            ElfErrorKind::InvalidInstruction,
            format!("jalr at {address:#x} is neither ret nor a canonical auipc/jalr call"),
        ));
    }
    let previous = instruction_word(bytes, index - 1)?;
    if previous & 0x7f != 0x17 || (previous >> 7) & 0x1f != 1 {
        return Err(ElfParseError::new(
            ElfErrorKind::InvalidInstruction,
            format!("jalr call at {address:#x} is not immediately preceded by 'auipc ra'"),
        ));
    }
    let high = sign_extend(previous & 0xffff_f000, 32);
    let low = sign_extend(word >> 20, 12);
    Ok(add_signed(address - 4, high.saturating_add(low)) & !1)
}

fn validate_stack_pointer_write(
    bytes: &[u8],
    index: usize,
    word: u32,
    address: u64,
    adjustments: &mut Vec<StackAdjustment>,
) -> Result<(), ElfParseError> {
    let opcode = word & 0x7f;
    let rd = (word >> 7) & 0x1f;
    if rd != 2 || !opcode_writes_rd(opcode) {
        return Ok(());
    }
    let rs1 = (word >> 15) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    if opcode == 0x13 && funct3 == 0 && rs1 == 2 {
        adjustments.push(StackAdjustment { address, delta: sign_extend(word >> 20, 12) });
        return Ok(());
    }
    let rs2 = (word >> 20) & 0x1f;
    if opcode == 0x33 && funct3 == 0 && (word >> 25) & 0x7f == 0 && rs1 == 2 {
        let delta = preceding_lui_addi_constant(bytes, index, rs2).ok_or_else(|| {
            ElfParseError::new(
                ElfErrorKind::InvalidInstruction,
                format!("stack adjustment at {address:#x} does not use an immediately materialised bounded constant"),
            )
        })?;
        adjustments.push(StackAdjustment { address, delta });
        return Ok(());
    }
    Err(ElfParseError::new(
        ElfErrorKind::InvalidInstruction,
        format!("instruction at {address:#x} writes sp outside the canonical frame-adjustment forms"),
    ))
}

fn preceding_lui_addi_constant(bytes: &[u8], index: usize, register: u32) -> Option<i64> {
    if index < 2 {
        return None;
    }
    let addi = instruction_word(bytes, index - 1).ok()?;
    let lui = instruction_word(bytes, index - 2).ok()?;
    if addi & 0x7f != 0x13
        || (addi >> 12) & 0x7 != 0
        || (addi >> 7) & 0x1f != register
        || (addi >> 15) & 0x1f != register
        || lui & 0x7f != 0x37
        || (lui >> 7) & 0x1f != register
    {
        return None;
    }
    Some(sign_extend(lui & 0xffff_f000, 32).saturating_add(sign_extend(addi >> 20, 12)))
}

fn instruction_word(bytes: &[u8], index: usize) -> Result<u32, ElfParseError> {
    let offset =
        index.checked_mul(4).ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidInstruction, "instruction offset overflows"))?;
    read_u32(bytes, offset)
}

fn opcode_writes_rd(opcode: u32) -> bool {
    matches!(opcode, 0x03 | 0x13 | 0x17 | 0x1b | 0x33 | 0x37 | 0x3b | 0x67 | 0x6f)
}

fn instruction_is_allowed(word: u32) -> bool {
    let opcode = word & 0x7f;
    let rd = (word >> 7) & 0x1f;
    let funct3 = (word >> 12) & 0x7;
    let funct7 = (word >> 25) & 0x7f;
    let funct6 = (word >> 26) & 0x3f;
    match opcode {
        0x03 => matches!(funct3, 3 | 4),
        0x13 => match funct3 {
            0 | 4 | 6 | 7 => true,
            1 => funct6 == 0,
            // The emitted `seqz rd, rs` pseudo-instruction is exactly
            // `sltiu rd, rs, 1`; arbitrary SLTIU immediates are not part of
            // the current CellScript machine surface.
            3 => word >> 20 == 1,
            // RV64I logical/arithmetic shifts plus the exact Zbb RORI funct6
            // used by the VM2 Blake2b backend. Other bitmanip immediates stay
            // outside the independently checked machine surface.
            5 => matches!(funct6, 0 | 0x10 | 0x18),
            _ => false,
        },
        0x17 | 0x37 => true,
        0x6f => matches!(rd, 0 | 1),
        0x1b => match funct3 {
            0 => true,
            1 => funct7 == 0,
            5 => matches!(funct7, 0 | 0x20 | 0x30),
            _ => false,
        },
        0x23 => matches!(funct3, 0..=3),
        0x33 => match funct7 {
            0 | 1 => true,
            0x20 => matches!(funct3, 0 | 5),
            _ => false,
        },
        0x3b => match funct7 {
            0 => matches!(funct3, 0 | 1 | 5),
            1 => matches!(funct3, 0 | 4 | 5 | 6 | 7),
            0x20 => matches!(funct3, 0 | 5),
            _ => false,
        },
        0x63 => !matches!(funct3, 2 | 3),
        0x67 => funct3 == 0,
        0x73 => word == 0x0000_0073,
        _ => false,
    }
}

fn branch_target(address: u64, word: u32) -> u64 {
    let immediate =
        (((word >> 31) & 0x1) << 12) | (((word >> 7) & 0x1) << 11) | (((word >> 25) & 0x3f) << 5) | (((word >> 8) & 0xf) << 1);
    add_signed(address, sign_extend(immediate, 13))
}

fn jal_target(address: u64, word: u32) -> u64 {
    let immediate =
        (((word >> 31) & 0x1) << 20) | (((word >> 12) & 0xff) << 12) | (((word >> 20) & 0x1) << 11) | (((word >> 21) & 0x3ff) << 1);
    add_signed(address, sign_extend(immediate, 21))
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((i64::from(value)) << shift) >> shift
}

fn add_signed(base: u64, offset: i64) -> u64 {
    if offset >= 0 {
        base.saturating_add(offset as u64)
    } else {
        base.saturating_sub(offset.unsigned_abs())
    }
}

fn segment_contains(segment: &ElfSegment, address: u64) -> bool {
    segment.virtual_address <= address && address < segment.virtual_address.saturating_add(segment.memory_size)
}

fn segment_contains_range(segment: &ElfSegment, address: u64, size: u64) -> bool {
    segment.virtual_address <= address && address.saturating_add(size) <= segment.virtual_address.saturating_add(segment.memory_size)
}

fn checked_table<'a>(bytes: &'a [u8], offset: u64, entry_size: usize, count: usize, label: &str) -> Result<&'a [u8], ElfParseError> {
    let size = entry_size
        .checked_mul(count)
        .and_then(|size| u64::try_from(size).ok())
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidTable, format!("{} table size overflows", label)))?;
    checked_file_range(bytes, offset, size, label)
}

fn checked_file_range<'a>(bytes: &'a [u8], offset: u64, size: u64, label: &str) -> Result<&'a [u8], ElfParseError> {
    let start = usize::try_from(offset)
        .map_err(|_| ElfParseError::new(ElfErrorKind::InvalidTable, format!("{} offset overflows usize", label)))?;
    let len = usize::try_from(size)
        .map_err(|_| ElfParseError::new(ElfErrorKind::InvalidTable, format!("{} size overflows usize", label)))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidTable, format!("{} range overflows usize", label)))?;
    bytes.get(start..end).ok_or_else(|| ElfParseError::new(ElfErrorKind::Truncated, format!("{} exceeds artifact bytes", label)))
}

fn read_c_string(bytes: &[u8], offset: usize) -> Result<String, ElfParseError> {
    let rest = bytes
        .get(offset..)
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "section name offset exceeds .shstrtab"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| ElfParseError::new(ElfErrorKind::InvalidSection, "section name is not NUL terminated"))?;
    let value = std::str::from_utf8(&rest[..end])
        .map_err(|_| ElfParseError::new(ElfErrorKind::InvalidSection, "section name is not UTF-8"))?;
    Ok(value.to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfParseError> {
    let slice =
        bytes.get(offset..offset + 2).ok_or_else(|| ElfParseError::new(ElfErrorKind::Truncated, "ELF u16 field is truncated"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfParseError> {
    let slice =
        bytes.get(offset..offset + 4).ok_or_else(|| ElfParseError::new(ElfErrorKind::Truncated, "ELF u32 field is truncated"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfParseError> {
    let slice =
        bytes.get(offset..offset + 8).ok_or_else(|| ElfParseError::new(ElfErrorKind::Truncated, "ELF u64 field is truncated"))?;
    Ok(u64::from_le_bytes([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]))
}

#[cfg(test)]
mod tests {
    use super::instruction_is_allowed;

    #[test]
    fn allowlist_accepts_only_the_emitted_sltiu_seqz_form() {
        assert!(instruction_is_allowed(0x0015_3e13));
        assert!(!instruction_is_allowed(0x0025_3e13));
    }

    #[test]
    fn allowlist_accepts_rori_but_rejects_neighboring_reserved_shift_immediate() {
        // rori s3, s3, 32 (funct6=0b011000, shamt=32).
        assert!(instruction_is_allowed(0x6209_d993));
        // Same registers/shamt under the next, unallocated funct6.
        assert!(!instruction_is_allowed(0x6609_d993));
    }

    #[test]
    fn allowlist_accepts_roriw_but_rejects_neighboring_reserved_shift_immediate() {
        // roriw s3, s3, 17 (funct7=0b0110000, shamt=17).
        assert!(instruction_is_allowed(0x6119_d99b));
        // Same registers/shamt under the next, unallocated funct7.
        assert!(!instruction_is_allowed(0x6319_d99b));
    }
}
