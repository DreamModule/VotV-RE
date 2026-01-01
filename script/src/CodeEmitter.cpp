#include “CodeEmitter.h”
#include “Utils.h”
#include <filesystem>

CppCodeEmitter::CppCodeEmitter(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg)
: funcInfo(funcInfo), cfg(cfg), indentLevel(0) {}

std::string CppCodeEmitter::EmitFunction() {
std::stringstream result;

```
result << EmitHeader() << "\n\n";
result << EmitImplementation();

return result.str();
```

}

std::string CppCodeEmitter::EmitHeader() {
std::stringstream ss;

```
ss << "// Function: " << funcInfo.name << "\n";
ss << "// Address: " << StringUtils::ToHex(funcInfo.address) << "\n";
ss << "// Size: 0x" << std::hex << funcInfo.size << " bytes\n";

return ss.str();
```

}

std::string CppCodeEmitter::EmitImplementation() {
impl.str(””);
impl.clear();

```
EmitFunctionSignature();
impl << " {\n";
IncIndent();

EmitLocalVariables();

if (cfg.entryBlock) {
    EmitBlockRecursive(cfg.entryBlock);
}

DecIndent();
impl << "}\n";

return impl.str();
```

}

void CppCodeEmitter::EmitFunctionSignature() {
Decompiler dec;
impl << dec.TypeToString(funcInfo.returnValue.type) << “ “ << funcInfo.name << “(”;

```
for (size_t i = 0; i < funcInfo.parameters.size(); i++) {
    const auto& param = funcInfo.parameters[i];
    impl << dec.TypeToString(param.type) << " " << param.name;
    if (i < funcInfo.parameters.size() - 1) impl << ", ";
}

impl << ")";
```

}

void CppCodeEmitter::EmitLocalVariables() {
Decompiler dec;
for (const auto& [name, var] : funcInfo.localVars) {
impl << Indent() << dec.TypeToString(var.type) << “ “ << var.name;

```
    if (var.type == VarType::INT32 || var.type == VarType::INT64 ||
        var.type == VarType::UINT32 || var.type == VarType::UINT64) {
        impl << " = 0";
    } else if (var.type == VarType::POINTER) {
        impl << " = nullptr";
    }
    
    impl << ";\n";
}
if (!funcInfo.localVars.empty()) impl << "\n";
```

}

void CppCodeEmitter::EmitBlockRecursive(const BasicBlock* block) {
if (!block || emittedBlocks.count(block->blockId)) return;
emittedBlocks.insert(block->blockId);

```
if (block->predecessors.size() > 1 && block != cfg.entryBlock) {
    impl << Indent() << "label_" << block->blockId << ":\n";
}

if (block->isLoopHeader) {
    impl << Indent() << "while (true) {\n";
    IncIndent();
}

size_t opIndex = 0;
for (const auto& instr : block->instructions) {
    const auto* operands = &block->operands[opIndex];
    EmitInstruction(instr, operands);
    opIndex += instr.operand_count;
}

if (block->successors.size() == 1) {
    EmitBlockRecursive(block->successors[0]);
} else if (block->successors.size() == 2) {
    const auto& lastInstr = block->instructions.back();
    size_t lastOpIndex = 0;
    for (size_t i = 0; i < block->instructions.size() - 1; i++) {
        lastOpIndex += block->instructions[i].operand_count;
    }
    
    impl << Indent() << "if (";
    ExpressionBuilder exprBuilder(funcInfo);
    impl << exprBuilder.BuildCondition(lastInstr);
    impl << ") {\n";
    IncIndent();
    EmitBlockRecursive(block->successors[0]);
    DecIndent();
    impl << Indent() << "} else {\n";
    IncIndent();
    EmitBlockRecursive(block->successors[1]);
    DecIndent();
    impl << Indent() << "}\n";
}

if (block->isLoopEnd) {
    DecIndent();
    impl << Indent() << "}\n";
}
```

}

void CppCodeEmitter::EmitInstruction(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {

```
if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
    EmitArithmeticOp(instr, operands);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD ||
           instr.mnemonic == ZYDIS_MNEMONIC_SUB ||
           instr.mnemonic == ZYDIS_MNEMONIC_XOR ||
           instr.mnemonic == ZYDIS_MNEMONIC_OR ||
           instr.mnemonic == ZYDIS_MNEMONIC_AND) {
    EmitArithmeticOp(instr, operands);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_CMP ||
           instr.mnemonic == ZYDIS_MNEMONIC_TEST) {
    EmitComparisonOp(instr, operands);
} else if (instr.mnemonic >= ZYDIS_MNEMONIC_JB && 
           instr.mnemonic <= ZYDIS_MNEMONIC_JZ) {
} else if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
    EmitCallOp(instr, operands);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_RET) {
    impl << Indent() << "return result;\n";
} else if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH ||
           instr.mnemonic == ZYDIS_MNEMONIC_POP) {
} else {
    char buffer[256];
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatInstruction(&formatter, &instr, operands,
                                   instr.operand_count, buffer, sizeof(buffer), 0);
    impl << Indent() << "// " << buffer << "\n";
}
```

}

void CppCodeEmitter::EmitArithmeticOp(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {
impl << Indent();

```
if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
    impl << EmitOperand(operands[0]) << " = " << EmitOperand(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD) {
    impl << EmitOperand(operands[0]) << " += " << EmitOperand(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB) {
    impl << EmitOperand(operands[0]) << " -= " << EmitOperand(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == operands[1].reg.value) {
        impl << EmitOperand(operands[0]) << " = 0";
    } else {
        impl << EmitOperand(operands[0]) << " ^= " << EmitOperand(operands[1]);
    }
} else if (instr.mnemonic == ZYDIS_MNEMONIC_OR) {
    impl << EmitOperand(operands[0]) << " |= " << EmitOperand(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_AND) {
    impl << EmitOperand(operands[0]) << " &= " << EmitOperand(operands[1]);
}

impl << ";\n";
```

}

void CppCodeEmitter::EmitComparisonOp(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {
impl << Indent() << “// “;

```
if (instr.mnemonic == ZYDIS_MNEMONIC_CMP) {
    impl << "compare " << EmitOperand(operands[0]) << " with " << EmitOperand(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_TEST) {
    impl << "test " << EmitOperand(operands[0]) << " against " << EmitOperand(operands[1]);
}

impl << "\n";
```

}

void CppCodeEmitter::EmitCallOp(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {
impl << Indent();

```
if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    impl << "CallFunction_" << std::hex << operands[0].imm.value.u << "()";
} else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
    impl << "(*" << EmitMemoryOperand(operands[0]) << ")()";
} else {
    impl << "CallIndirect(" << EmitOperand(operands[0]) << ")";
}

impl << ";\n";
```

}

std::string CppCodeEmitter::EmitOperand(const ZydisDecodedOperand& op) {
if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
return EmitRegisterOperand(op.reg.value);
} else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
return EmitImmediateOperand(op);
} else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
return EmitMemoryOperand(op);
}
return “unknown”;
}

std::string CppCodeEmitter::EmitRegisterOperand(ZydisRegister reg) {
ExpressionBuilder builder(funcInfo);
return builder.GetRegisterName(reg);
}

std::string CppCodeEmitter::EmitImmediateOperand(const ZydisDecodedOperand& op) {
std::stringstream ss;
if (op.imm.is_signed) {
ss << (int64_t)op.imm.value.s;
} else {
if (op.imm.value.u > 0xFFFF) {
ss << “0x” << std::hex << op.imm.value.u;
} else {
ss << std::dec << op.imm.value.u;
}
}
return ss.str();
}

std::string CppCodeEmitter::EmitMemoryOperand(const ZydisDecodedOperand& op) {
std::stringstream ss;
ss << “*(”;

```
if (op.mem.base != ZYDIS_REGISTER_NONE) {
    ss << EmitRegisterOperand(op.mem.base);
}

if (op.mem.disp.has_displacement) {
    if (op.mem.disp.value >= 0) {
        ss << " + " << op.mem.disp.value;
    } else {
        ss << " - " << (-op.mem.disp.value);
    }
}

ss << ")";
return ss.str();
```

}

std::string CppCodeEmitter::Indent() {
return std::string(indentLevel * 4, ’ ’);
}

AsmCodeEmitter::AsmCodeEmitter(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg)
: funcInfo(funcInfo), cfg(cfg) {
ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

std::string AsmCodeEmitter::EmitAssembly() {
std::stringstream ss;

```
ss << "; Function: " << funcInfo.name << "\n";
ss << "; Address: " << StringUtils::ToHex(funcInfo.address) << "\n";
ss << "; Size: 0x" << std::hex << funcInfo.size << " bytes\n\n";

for (const auto& block : cfg.blocks) {
    ss << EmitBlockLabel(block->blockId) << ":\n";
    
    size_t opIndex = 0;
    uintptr_t addr = block->startAddr;
    
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        ss << "    " << FormatInstruction(instr, operands, addr) << "\n";
        
        opIndex += instr.operand_count;
        addr += instr.length;
    }
    
    ss << "\n";
}

return ss.str();
```

}

std::string AsmCodeEmitter::FormatInstruction(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands,
uintptr_t address) {
char buffer[256];
ZydisFormatterFormatInstruction(&formatter, &instr, operands,
instr.operand_count, buffer, sizeof(buffer), address);
return std::string(buffer);
}

std::string AsmCodeEmitter::EmitBlockLabel(int blockId) {
return “loc_” + std::to_string(blockId);
}

PseudocodeEmitter::PseudocodeEmitter(const FunctionInfo& funcInfo,
const ControlFlowGraph& cfg,
const PatternRecognizer& patterns)
: funcInfo(funcInfo), cfg(cfg), patterns(patterns), indentLevel(0) {}

std::string PseudocodeEmitter::EmitPseudocode() {
code.str(””);
code.clear();

```
code << "function " << funcInfo.name << "(";
for (size_t i = 0; i < funcInfo.parameters.size(); i++) {
    code << funcInfo.parameters[i].name;
    if (i < funcInfo.parameters.size() - 1) code << ", ";
}
code << "):\n";

IncIndent();

for (const auto& loop : patterns.detectedLoops) {
    EmitLoop(loop);
}

for (const auto& cond : patterns.detectedConditions) {
    EmitCondition(cond);
}

DecIndent();
code << "end\n";

return code.str();
```

}

void PseudocodeEmitter::EmitLoop(const PatternRecognizer::LoopPattern& loop) {
code << std::string(indentLevel * 2, ’ ’);

```
if (loop.loopType == PatternType::LOOP_FOR) {
    code << "for " << loop.initExpr << " to " << loop.condExpr << ":\n";
} else if (loop.loopType == PatternType::LOOP_WHILE) {
    code << "while " << loop.condExpr << ":\n";
}

IncIndent();
code << std::string(indentLevel * 2, ' ') << "// loop body\n";
DecIndent();
```

}

void PseudocodeEmitter::EmitCondition(const PatternRecognizer::ConditionPattern& cond) {
code << std::string(indentLevel * 2, ’ ’);
code << “if “ << cond.conditionExpr << “:\n”;
IncIndent();
code << std::string(indentLevel * 2, ’ ’) << “// then branch\n”;
DecIndent();

```
if (cond.elseBranch) {
    code << std::string(indentLevel * 2, ' ') << "else:\n";
    IncIndent();
    code << std::string(indentLevel * 2, ' ') << "// else branch\n";
    DecIndent();
}
```

}

DocumentationGenerator::DocumentationGenerator(const FunctionInfo& funcInfo,
const ControlFlowGraph& cfg)
: funcInfo(funcInfo), cfg(cfg) {}

std::string DocumentationGenerator::GenerateDocumentation() {
std::stringstream ss;

```
ss << "/**\n";
ss << " * " << GenerateFunctionSummary() << "\n";
ss << " *\n";
ss << GenerateParameterDocs();
ss << GenerateReturnValueDocs();
ss << " *\n";
ss << " * @complexity " << GenerateComplexityAnalysis() << "\n";
ss << " */\n";

return ss.str();
```

}

std::string DocumentationGenerator::GenerateFunctionSummary() {
return “Function “ + funcInfo.name + “ at address “ +
StringUtils::ToHex(funcInfo.address);
}

std::string DocumentationGenerator::GenerateParameterDocs() {
std::stringstream ss;
Decompiler dec;

```
for (const auto& param : funcInfo.parameters) {
    ss << " * @param " << param.name << " " << dec.TypeToString(param.type) << "\n";
}

return ss.str();
```

}

std::string DocumentationGenerator::GenerateReturnValueDocs() {
Decompiler dec;
return “ * @return “ + dec.TypeToString(funcInfo.returnValue.type) + “\n”;
}

std::string DocumentationGenerator::GenerateComplexityAnalysis() {
size_t totalInstructions = 0;
for (const auto& block : cfg.blocks) {
totalInstructions += block->instructions.size();
}

```
return "O(n) - " + std::to_string(totalInstructions) + " instructions";
```

}

ProjectGenerator::ProjectGenerator(const std::string& projectName)
: projectName(projectName) {}

void ProjectGenerator::AddSourceFile(const std::string& filename, const std::string& content) {
sourceFiles[filename] = content;
}

void ProjectGenerator::AddHeaderFile(const std::string& filename, const std::string& content) {
headerFiles[filename] = content;
}

void ProjectGenerator::GenerateCMakeLists() {
std::string content = GenerateCMakeContent();
sourceFiles[“CMakeLists.txt”] = content;
}

void ProjectGenerator::GenerateREADME() {
std::string content = GenerateReadmeContent();
sourceFiles[“README.md”] = content;
}

std::string ProjectGenerator::GenerateCMakeContent() {
std::stringstream ss;

```
ss << "cmake_minimum_required(VERSION 3.15)\n";
ss << "project(" << projectName << " CXX)\n\n";
ss << "set(CMAKE_CXX_STANDARD 17)\n\n";
ss << "add_executable(" << projectName << "\n";

for (const auto& [name, _] : sourceFiles) {
    if (StringUtils::EndsWith(name, ".cpp")) {
        ss << "    " << name << "\n";
    }
}

ss << ")\n";

return ss.str();
```

}

std::string ProjectGenerator::GenerateReadmeContent() {
std::stringstream ss;

```
ss << "# " << projectName << "\n\n";
ss << "Decompiled code from binary analysis.\n\n";
ss << "## Build Instructions\n\n";
ss << "```bash\n";
ss << "mkdir build\n";
ss << "cd build\n";
ss << "cmake ..\n";
ss << "make\n";
ss << "```\n";

return ss.str();
```

}

void ProjectGenerator::SaveProject(const std::string& outputDir) {
std::filesystem::create_directories(outputDir);
std::filesystem::create_directories(outputDir + “/include”);
std::filesystem::create_directories(outputDir + “/src”);

```
for (const auto& [name, content] : headerFiles) {
    FileUtils::WriteFile(outputDir + "/include/" + name, content);
}

for (const auto& [name, content] : sourceFiles) {
    FileUtils::WriteFile(outputDir + "/src/" + name, content);
}
```

}
