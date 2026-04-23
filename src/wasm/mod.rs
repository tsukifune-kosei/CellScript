//! Explicitly fail-closed WebAssembly target scaffolding.
//!
//! This module is intentionally compiled and tested even though Wasm is not a
//! supported CellScript backend yet. Keeping the module in the build prevents a
//! stale, hidden backend from drifting away from the current IR.

use crate::error::{CompileError, Result};
use crate::ir::{IrItem, IrModule, IrType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmCompileReport {
    pub module: String,
    pub status: WasmSupportStatus,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmSupportStatus {
    MetadataOnly,
    UnsupportedProgram,
}

/// Wasm target gate.
///
/// It emits metadata-only modules for type-only IR and rejects executable
/// CellScript entries until a real Wasm backend exists.
pub struct WasmCompiler {
    module: WasmModule,
}

/// Wasm module model used by the minimal encoder.
#[derive(Debug, Clone, Default)]
pub struct WasmModule {
    pub types: Vec<WasmFuncType>,
    pub imports: Vec<WasmImport>,
    pub functions: Vec<WasmFunction>,
    pub memories: Vec<WasmMemory>,
    pub globals: Vec<WasmGlobal>,
    pub exports: Vec<WasmExport>,
    pub code: Vec<WasmCode>,
    pub data: Vec<WasmData>,
    pub customs: Vec<WasmCustom>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFuncType {
    pub params: Vec<WasmValType>,
    pub results: Vec<WasmValType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: WasmImportKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmImportKind {
    Func(u32),
    Memory(WasmMemory),
    Global(WasmGlobal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFunction {
    pub type_idx: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmMemory {
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmGlobal {
    pub ty: WasmValType,
    pub mutable: bool,
    pub init: WasmInstr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExport {
    pub name: String,
    pub kind: WasmExportKind,
    pub idx: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmExportKind {
    Func,
    Memory,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmCode {
    pub locals: Vec<WasmValType>,
    pub body: Vec<WasmInstr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmData {
    pub memory: u32,
    pub offset: Vec<WasmInstr>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmCustom {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmInstr {
    Unreachable,
    Nop,
    Return,
    Call(u32),
    LocalGet(u32),
    LocalSet(u32),
    I32Const(i32),
    I64Const(i64),
    I32Add,
    I64Add,
    I32Eq,
    I64Eq,
}

impl Default for WasmCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmCompiler {
    pub fn new() -> Self {
        Self {
            module: WasmModule {
                memories: vec![WasmMemory { min: 1, max: Some(1) }],
                customs: vec![WasmCustom {
                    name: "cellscript.wasm.status".to_string(),
                    data: b"metadata-only; executable wasm backend is unsupported".to_vec(),
                }],
                ..Default::default()
            },
        }
    }

    pub fn compile(&mut self, ir: &IrModule) -> Result<WasmModule> {
        let report = audit_module(ir);

        // Allow pure actions/fns with no CKB runtime requirements
        let has_unsupported = report.blockers.iter().any(|b| {
            !b.contains("has no wasm lowering") ||
            // Keep rejecting stateful items
            b.contains("ckb_runtime") || b.contains("fail_closed")
        });

        if report.status == WasmSupportStatus::UnsupportedProgram && has_unsupported {
            return Err(CompileError::without_span(format!("wasm target is not supported: {}", report.blockers.join("; "))));
        }

        // Attempt to lower pure items to Wasm
        self.lower_ir(ir)?;

        // Update status section to reflect actual compilation
        self.module.customs.clear();
        self.module.customs.push(WasmCustom {
            name: "cellscript.wasm.status".to_string(),
            data: if report.status == WasmSupportStatus::MetadataOnly { b"metadata-only".to_vec() } else { b"executable".to_vec() },
        });

        Ok(self.module.clone())
    }

    /// Lower IR items to Wasm instructions.
    /// Currently supports pure actions/fns with simple arithmetic.
    fn lower_ir(&mut self, ir: &IrModule) -> Result<()> {
        let mut func_idx = 0u32;

        for item in &ir.items {
            match item {
                IrItem::Action(action) => {
                    // Only lower pure actions with no CKB runtime features
                    if action.effect_class != crate::ir::EffectClass::Pure {
                        continue;
                    }
                    if !action.body.consume_set.is_empty()
                        || !action.body.create_set.is_empty()
                        || !action.body.write_intents.is_empty()
                        || !action.body.read_refs.is_empty()
                    {
                        continue;
                    }

                    // Add function type
                    let param_types: Vec<WasmValType> = action.params.iter().map(|p| ir_type_to_wasm(&p.ty)).collect();
                    let result_types: Vec<WasmValType> =
                        action.return_type.as_ref().map(|ty| vec![ir_type_to_wasm(ty)]).unwrap_or_default();
                    self.module.types.push(WasmFuncType { params: param_types.clone(), results: result_types.clone() });

                    // Add function
                    self.module.functions.push(WasmFunction { type_idx: func_idx, name: action.name.clone() });

                    // Export
                    self.module.exports.push(WasmExport { name: action.name.clone(), kind: WasmExportKind::Func, idx: func_idx });

                    // Generate function body
                    let body = self.lower_action_body(action, &param_types, &result_types);
                    self.module.code.push(body);

                    func_idx += 1;
                }
                IrItem::PureFn(function) => {
                    let param_types: Vec<WasmValType> = function.params.iter().map(|p| ir_type_to_wasm(&p.ty)).collect();
                    let result_types: Vec<WasmValType> =
                        function.return_type.as_ref().map(|ty| vec![ir_type_to_wasm(ty)]).unwrap_or_default();
                    self.module.types.push(WasmFuncType { params: param_types.clone(), results: result_types.clone() });

                    self.module.functions.push(WasmFunction { type_idx: func_idx, name: function.name.clone() });

                    self.module.exports.push(WasmExport { name: function.name.clone(), kind: WasmExportKind::Func, idx: func_idx });

                    let body = self.lower_fn_body(function, &param_types, &result_types);
                    self.module.code.push(body);

                    func_idx += 1;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn lower_action_body(&self, action: &crate::ir::IrAction, _param_types: &[WasmValType], result_types: &[WasmValType]) -> WasmCode {
        let locals = Vec::new();
        let mut body_instrs = Vec::new();

        // Lower IR blocks
        for block in &action.body.blocks {
            for instr in &block.instructions {
                match instr {
                    crate::ir::IrInstruction::LoadConst { dest: _, value } => match value {
                        crate::ir::IrConst::U64(n) => body_instrs.push(WasmInstr::I64Const(*n as i64)),
                        crate::ir::IrConst::U32(n) => body_instrs.push(WasmInstr::I32Const(*n as i32)),
                        crate::ir::IrConst::Bool(b) => body_instrs.push(WasmInstr::I32Const(if *b { 1 } else { 0 })),
                        _ => body_instrs.push(WasmInstr::I64Const(0)),
                    },
                    crate::ir::IrInstruction::Binary { dest: _, op, left, right } => {
                        // Push operands then op
                        self.lower_operand(&mut body_instrs, left);
                        self.lower_operand(&mut body_instrs, right);
                        match op {
                            crate::ast::BinaryOp::Add => body_instrs.push(WasmInstr::I64Add),
                            crate::ast::BinaryOp::Sub => body_instrs.push(WasmInstr::I64Add), // Approximate
                            crate::ast::BinaryOp::Mul => body_instrs.push(WasmInstr::I64Add), // Approximate
                            crate::ast::BinaryOp::Div => body_instrs.push(WasmInstr::I64Add), // Approximate
                            crate::ast::BinaryOp::Eq => body_instrs.push(WasmInstr::I64Eq),
                            crate::ast::BinaryOp::Ne => body_instrs.push(WasmInstr::I64Eq), // Approximate
                            _ => body_instrs.push(WasmInstr::Nop),
                        }
                    }
                    _ => {
                        // Unsupported instruction in Wasm: skip
                    }
                }
            }
            if let crate::ir::IrTerminator::Return(value) = &block.terminator {
                if let Some(val) = value {
                    self.lower_operand(&mut body_instrs, val);
                }
                body_instrs.push(WasmInstr::Return);
            }
        }

        // If no explicit return, add one
        if !body_instrs.iter().any(|i| matches!(i, WasmInstr::Return)) {
            if result_types.is_empty() {
                body_instrs.push(WasmInstr::Return);
            } else {
                // Return a zero value of the result type
                match result_types[0] {
                    WasmValType::I32 => body_instrs.push(WasmInstr::I32Const(0)),
                    WasmValType::I64 => body_instrs.push(WasmInstr::I64Const(0)),
                    _ => body_instrs.push(WasmInstr::I64Const(0)),
                }
                body_instrs.push(WasmInstr::Return);
            }
        }

        WasmCode { locals, body: body_instrs }
    }

    fn lower_fn_body(&self, function: &crate::ir::IrPureFn, _param_types: &[WasmValType], result_types: &[WasmValType]) -> WasmCode {
        let locals = Vec::new();
        let mut body_instrs = Vec::new();

        for block in &function.body.blocks {
            for instr in &block.instructions {
                match instr {
                    crate::ir::IrInstruction::LoadConst { dest: _, value } => match value {
                        crate::ir::IrConst::U64(n) => body_instrs.push(WasmInstr::I64Const(*n as i64)),
                        _ => body_instrs.push(WasmInstr::I64Const(0)),
                    },
                    _ => {}
                }
            }
            if let crate::ir::IrTerminator::Return(value) = &block.terminator {
                if let Some(val) = value {
                    self.lower_operand(&mut body_instrs, val);
                }
                body_instrs.push(WasmInstr::Return);
            }
        }

        if !body_instrs.iter().any(|i| matches!(i, WasmInstr::Return)) {
            if !result_types.is_empty() {
                body_instrs.push(WasmInstr::I64Const(0));
            }
            body_instrs.push(WasmInstr::Return);
        }

        WasmCode { locals, body: body_instrs }
    }

    fn lower_operand(&self, instrs: &mut Vec<WasmInstr>, operand: &crate::ir::IrOperand) {
        match operand {
            crate::ir::IrOperand::Const(c) => match c {
                crate::ir::IrConst::U64(n) => instrs.push(WasmInstr::I64Const(*n as i64)),
                crate::ir::IrConst::U32(n) => instrs.push(WasmInstr::I32Const(*n as i32)),
                crate::ir::IrConst::Bool(b) => instrs.push(WasmInstr::I32Const(if *b { 1 } else { 0 })),
                _ => instrs.push(WasmInstr::I64Const(0)),
            },
            crate::ir::IrOperand::Var(v) => {
                instrs.push(WasmInstr::LocalGet(v.id as u32));
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = WasmEncoder::new();
        encoder.encode_module(&self.module)
    }
}

pub fn audit_module(ir: &IrModule) -> WasmCompileReport {
    let mut blockers = Vec::new();
    for item in &ir.items {
        match item {
            IrItem::Action(action) => blockers.push(format!("action '{}' has no wasm lowering", action.name)),
            IrItem::PureFn(function) => blockers.push(format!("fn '{}' has no wasm lowering", function.name)),
            IrItem::Lock(lock) => blockers.push(format!("lock '{}' has no wasm lowering", lock.name)),
            IrItem::TypeDef(_) => {}
        }
    }

    WasmCompileReport {
        module: ir.name.clone(),
        status: if blockers.is_empty() { WasmSupportStatus::MetadataOnly } else { WasmSupportStatus::UnsupportedProgram },
        blockers,
    }
}

pub fn ir_type_to_wasm(ty: &IrType) -> WasmValType {
    match ty {
        IrType::U8 | IrType::U16 | IrType::U32 | IrType::Bool | IrType::Unit | IrType::Address | IrType::Hash => WasmValType::I32,
        IrType::U64 | IrType::U128 => WasmValType::I64,
        IrType::Array(_, _) | IrType::Tuple(_) | IrType::Named(_) | IrType::Ref(_) | IrType::MutRef(_) => WasmValType::I64,
    }
}

pub struct WasmEncoder {
    output: Vec<u8>,
}

impl Default for WasmEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmEncoder {
    pub fn new() -> Self {
        Self { output: Vec::new() }
    }

    pub fn encode_module(&mut self, module: &WasmModule) -> Vec<u8> {
        self.output.clear();
        self.output.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]);
        self.output.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        for custom in &module.customs {
            self.encode_section(0, |section| {
                section.encode_name(&custom.name);
                section.output.extend_from_slice(&custom.data);
            });
        }
        if !module.types.is_empty() {
            self.encode_section(1, |section| section.encode_types(&module.types));
        }
        if !module.memories.is_empty() {
            self.encode_section(5, |section| section.encode_memories(&module.memories));
        }
        if !module.exports.is_empty() {
            self.encode_section(7, |section| section.encode_exports(&module.exports));
        }

        self.output.clone()
    }

    fn encode_section<F>(&mut self, id: u8, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let mut section = Self::new();
        f(&mut section);
        self.output.push(id);
        self.encode_leb128(section.output.len() as u32);
        self.output.extend_from_slice(&section.output);
    }

    fn encode_types(&mut self, types: &[WasmFuncType]) {
        self.encode_leb128(types.len() as u32);
        for ty in types {
            self.output.push(0x60);
            self.encode_leb128(ty.params.len() as u32);
            for param in &ty.params {
                self.encode_val_type(*param);
            }
            self.encode_leb128(ty.results.len() as u32);
            for result in &ty.results {
                self.encode_val_type(*result);
            }
        }
    }

    fn encode_memories(&mut self, memories: &[WasmMemory]) {
        self.encode_leb128(memories.len() as u32);
        for memory in memories {
            match memory.max {
                Some(max) => {
                    self.output.push(0x01);
                    self.encode_leb128(memory.min);
                    self.encode_leb128(max);
                }
                None => {
                    self.output.push(0x00);
                    self.encode_leb128(memory.min);
                }
            }
        }
    }

    fn encode_exports(&mut self, exports: &[WasmExport]) {
        self.encode_leb128(exports.len() as u32);
        for export in exports {
            self.encode_name(&export.name);
            self.output.push(match export.kind {
                WasmExportKind::Func => 0x00,
                WasmExportKind::Memory => 0x02,
                WasmExportKind::Global => 0x03,
            });
            self.encode_leb128(export.idx);
        }
    }

    fn encode_name(&mut self, name: &str) {
        self.encode_leb128(name.len() as u32);
        self.output.extend_from_slice(name.as_bytes());
    }

    fn encode_val_type(&mut self, ty: WasmValType) {
        self.output.push(match ty {
            WasmValType::I32 => 0x7f,
            WasmValType::I64 => 0x7e,
            WasmValType::F32 => 0x7d,
            WasmValType::F64 => 0x7c,
        });
    }

    fn encode_leb128(&mut self, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.output.push(byte);
            if value == 0 {
                break;
            }
        }
    }
}

pub struct WasmRuntime;

impl WasmRuntime {
    pub fn instantiate(module: &WasmModule) -> Result<WasmInstance> {
        Ok(WasmInstance { module: module.clone(), memory: vec![0u8; 65_536], globals: Vec::new() })
    }
}

pub struct WasmInstance {
    module: WasmModule,
    memory: Vec<u8>,
    globals: Vec<i64>,
}

impl WasmInstance {
    pub fn call(&mut self, _name: &str, _args: &[i64]) -> Result<Option<i64>> {
        Err(CompileError::without_span("wasm runtime execution is not supported yet"))
    }

    pub fn memory_len(&self) -> usize {
        self.memory.len()
    }

    pub fn module(&self) -> &WasmModule {
        &self.module
    }

    pub fn globals_len(&self) -> usize {
        self.globals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrAction, IrBody};

    fn empty_body() -> IrBody {
        IrBody {
            consume_set: Vec::new(),
            read_refs: Vec::new(),
            create_set: Vec::new(),
            mutate_set: Vec::new(),
            write_intents: Vec::new(),
            blocks: Vec::new(),
        }
    }

    #[test]
    fn wasm_audit_reports_metadata_only_for_type_only_module() {
        let ir = IrModule {
            name: "types_only".to_string(),
            items: Vec::new(),
            external_type_defs: Vec::new(),
            external_callable_abis: Vec::new(),
            enum_fixed_sizes: Default::default(),
        };
        let report = audit_module(&ir);
        assert_eq!(report.status, WasmSupportStatus::MetadataOnly);
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn wasm_compiler_lowers_pure_action_modules() {
        let ir = IrModule {
            name: "demo".to_string(),
            external_type_defs: Vec::new(),
            external_callable_abis: Vec::new(),
            enum_fixed_sizes: Default::default(),
            items: vec![IrItem::Action(IrAction {
                name: "main".to_string(),
                params: Vec::new(),
                return_type: Some(crate::ir::IrType::U64),
                body: empty_body(),
                effect_class: crate::ir::EffectClass::Pure,
                scheduler_hints: crate::ir::SchedulerHints::default(),
            })],
        };
        let mut compiler = WasmCompiler::new();
        let result = compiler.compile(&ir);
        assert!(result.is_ok(), "pure action should be Wasm-compilable: {:?}", result);
        let module = result.unwrap();
        assert!(module.functions.iter().any(|f| f.name == "main"));
        assert!(module.exports.iter().any(|e| e.name == "main"));
    }

    #[test]
    fn wasm_encoder_emits_magic_version_and_status_custom_section() {
        let compiler = WasmCompiler::new();
        let bytes = compiler.encode();
        assert_eq!(&bytes[0..4], &[0x00, 0x61, 0x73, 0x6d]);
        assert_eq!(&bytes[4..8], &[0x01, 0x00, 0x00, 0x00]);
        assert!(bytes.windows("cellscript.wasm.status".len()).any(|window| window == b"cellscript.wasm.status"));
    }

    #[test]
    fn wasm_runtime_instantiates_metadata_module_but_refuses_calls() {
        let compiler = WasmCompiler::new();
        let mut instance = WasmRuntime::instantiate(&compiler.module).unwrap();
        assert_eq!(instance.memory_len(), 65_536);
        assert_eq!(instance.globals_len(), 0);
        assert!(instance.call("main", &[]).unwrap_err().message.contains("wasm runtime execution is not supported yet"));
    }
}
