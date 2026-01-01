#include “Decompiler.h”
#include <fstream>
#include <algorithm>
#include <queue>
#include <iomanip>
#include <filesystem>

Decompiler::Decompiler() {}
Decompiler::~Decompiler() {}

bool Decompiler::Initialize() {
ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
return true;
}

std::unique_ptr<ControlFlowGraph> Decompiler::BuildCFG(uintptr_t address, size_t size) {
auto cfg = std::make_unique<ControlFlowGraph>();
std::map<uintptr_t, BasicBlock*> blockStarts;
std::set<uintptr_t> branchTargets;
std::vector<std::pair<uintptr_t, uintptr_t>> pendingBranches;

```
branchTargets.insert(address);

uintptr_t offset = 0;
while (offset < size) {
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, 
        (void*)(address + offset), size - offset, 
        &instruction, operands))) {
        
        uintptr_t currentAddr = address + offset;
        
        if (IsJumpInstruction(instruction) || IsCallInstruction(instruction)) {
            uintptr_t target = GetJumpTarget(instruction, operands, currentAddr);
            if (target != 0 && target >= address && target < address + size) {
                branchTargets.insert(target);
                if (IsJumpInstruction(instruction)) {
                    branchTargets.insert(currentAddr + instruction.length);
                }
            }
        }
        
        if (IsRetInstruction(instruction)) {
            branchTargets.insert(currentAddr + instruction.length);
        }
        
        offset += instruction.length;
    } else {
        offset++;
    }
}

std::vector<uintptr_t> sortedTargets(branchTargets.begin(), branchTargets.end());
std::sort(sortedTargets.begin(), sortedTargets.end());

for (size_t i = 0; i < sortedTargets.size(); i++) {
    uintptr_t blockStart = sortedTargets[i];
    uintptr_t blockEnd = (i + 1 < sortedTargets.size()) ? sortedTargets[i + 1] : address + size;
    
    auto block = std::make_unique<BasicBlock>();
    block->startAddr = blockStart;
    block->endAddr = blockEnd;
    block->blockId = (int)cfg->blocks.size();
    block->visited = false;
    block->isLoopHeader = false;
    block->isLoopEnd = false;
    block->loopHeader = nullptr;
    
    uintptr_t instrOffset = 0;
    while (blockStart + instrOffset < blockEnd) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
            (void*)(blockStart + instrOffset), blockEnd - (blockStart + instrOffset),
            &instruction, operands))) {
            
            block->instructions.push_back(instruction);
            for (int j = 0; j < instruction.operand_count; j++) {
                block->operands.push_back(operands[j]);
            }
            
            instrOffset += instruction.length;
            
            if (IsJumpInstruction(instruction) || IsRetInstruction(instruction)) {
                break;
            }
        } else {
            break;
        }
    }
    
    blockStarts[blockStart] = block.get();
    cfg->blocks.push_back(std::move(block));
}

for (auto& block : cfg->blocks) {
    if (!block->instructions.empty()) {
        const auto& lastInstr = block->instructions.back();
        const auto* lastOperands = &block->operands[block->operands.size() - lastInstr.operand_count];
        
        if (IsJumpInstruction(lastInstr)) {
            uintptr_t target = GetJumpTarget(lastInstr, lastOperands, 
                block->startAddr + (block->endAddr - block->startAddr - lastInstr.length));
            
            if (target != 0 && blockStarts.count(target)) {
                block->successors.push_back(blockStarts[target]);
                blockStarts[target]->predecessors.push_back(block.get());
            }
            
            if (lastInstr.mnemonic != ZYDIS_MNEMONIC_JMP) {
                uintptr_t fallthrough = block->endAddr;
                if (blockStarts.count(fallthrough)) {
                    block->successors.push_back(blockStarts[fallthrough]);
                    blockStarts[fallthrough]->predecessors.push_back(block.get());
                }
            }
        } else if (!IsRetInstruction(lastInstr)) {
            uintptr_t fallthrough = block->endAddr;
            if (blockStarts.count(fallthrough)) {
                block->successors.push_back(blockStarts[fallthrough]);
                blockStarts[fallthrough]->predecessors.push_back(block.get());
            }
        }
    }
}

cfg->entryBlock = cfg->blocks.empty() ? nullptr : cfg->blocks[0].get();
cfg->addressToBlock = blockStarts;

return cfg;
```

}

void Decompiler::DetectLoops(ControlFlowGraph& cfg) {
std::set<BasicBlock*> visited;
std::set<BasicBlock*> recStack;

```
std::function<void(BasicBlock*)> dfs = [&](BasicBlock* block) {
    if (!block) return;
    visited.insert(block);
    recStack.insert(block);
    
    for (auto* succ : block->successors) {
        if (recStack.count(succ)) {
            succ->isLoopHeader = true;
            block->isLoopEnd = true;
            block->loopHeader = succ;
        } else if (!visited.count(succ)) {
            dfs(succ);
        }
    }
    
    recStack.erase(block);
};

if (cfg.entryBlock) {
    dfs(cfg.entryBlock);
}
```

}

void Decompiler::AnalyzeFunction(FunctionInfo& funcInfo, const ControlFlowGraph& cfg) {
funcInfo.stackSize = 0;
funcInfo.usesFramePointer = false;

```
if (cfg.blocks.empty()) return;

const auto& firstBlock = cfg.blocks[0];
if (!firstBlock->instructions.empty()) {
    for (size_t i = 0; i < firstBlock->instructions.size() && i < 5; i++) {
        const auto& instr = firstBlock->instructions[i];
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH && 
            firstBlock->operands[i * instr.operand_count].reg.value == ZYDIS_REGISTER_RBP) {
            funcInfo.usesFramePointer = true;
        }
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_SUB) {
            const auto& op1 = firstBlock->operands[i * instr.operand_count];
            const auto& op2 = firstBlock->operands[i * instr.operand_count + 1];
            
            if (op1.type == ZYDIS_OPERAND_TYPE_REGISTER && 
                op1.reg.value == ZYDIS_REGISTER_RSP &&
                op2.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                funcInfo.stackSize = (int)op2.imm.value.u;
            }
        }
    }
}

std::map<ZydisRegister, int> paramRegs = {
    {ZYDIS_REGISTER_RCX, 0}, {ZYDIS_REGISTER_RDX, 1},
    {ZYDIS_REGISTER_R8, 2}, {ZYDIS_REGISTER_R9, 3}
};

std::set<ZydisRegister> usedParams;

for (const auto& block : cfg.blocks) {
    for (const auto& instr : block->instructions) {
        for (int i = 0; i < instr.operand_count; i++) {
            auto& op = block->operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (paramRegs.count(op.reg.value)) {
                    usedParams.insert(op.reg.value);
                }
            }
        }
    }
}

int paramIdx = 0;
for (auto reg : {ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9}) {
    if (usedParams.count(reg)) {
        Variable param;
        param.name = "param" + std::to_string(paramIdx++);
        param.type = VarType::UINT64;
        param.isParameter = true;
        param.isReturn = false;
        param.size = 8;
        funcInfo.parameters.push_back(param);
    }
}

funcInfo.returnValue.name = "result";
funcInfo.returnValue.type = VarType::UINT64;
funcInfo.returnValue.isReturn = true;
funcInfo.returnValue.size = 8;
```

}

void Decompiler::InferTypes(FunctionInfo& funcInfo, const ControlFlowGraph& cfg) {
for (const auto& block : cfg.blocks) {
size_t opIndex = 0;
for (const auto& instr : block->instructions) {
const auto* operands = &block->operands[opIndex];

```
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVSS || instr.mnemonic == ZYDIS_MNEMONIC_ADDSS) {
            for (auto& param : funcInfo.parameters) {
                if (param.type == VarType::UINT64) {
                    param.type = VarType::FLOAT32;
                    param.size = 4;
                }
            }
        }
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVSD || instr.mnemonic == ZYDIS_MNEMONIC_ADDSD) {
            for (auto& param : funcInfo.parameters) {
                if (param.type == VarType::UINT64) {
                    param.type = VarType::FLOAT64;
                    param.size = 8;
                }
            }
        }
        
        opIndex += instr.operand_count;
    }
}
```

}

std::string Decompiler::GenerateCppCode(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg) {
CodeGenerator generator(funcInfo, cfg);
return generator.Generate();
}

std::string Decompiler::GenerateAsmFile(const ControlFlowGraph& cfg, const FunctionInfo& funcInfo) {
std::stringstream ss;

```
ss << "; Function: " << funcInfo.name << "\n";
ss << "; Address: 0x" << std::hex << funcInfo.address << "\n";
ss << "; Size: 0x" << funcInfo.size << " bytes\n";
ss << "; Stack Size: 0x" << funcInfo.stackSize << "\n\n";

for (const auto& block : cfg.blocks) {
    ss << "block_" << block->blockId << ":  ; 0x" << std::hex << block->startAddr << "\n";
    
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instr, 
            &block->operands[opIndex], instr.operand_count,
            buffer, sizeof(buffer), block->startAddr);
        
        ss << "    " << buffer << "\n";
        opIndex += instr.operand_count;
    }
    
    ss << "\n";
}

return ss.str();
```

}

std::string Decompiler::TypeToString(VarType type) {
switch (type) {
case VarType::INT8: return “int8_t”;
case VarType::INT16: return “int16_t”;
case VarType::INT32: return “int32_t”;
case VarType::INT64: return “int64_t”;
case VarType::UINT8: return “uint8_t”;
case VarType::UINT16: return “uint16_t”;
case VarType::UINT32: return “uint32_t”;
case VarType::UINT64: return “uint64_t”;
case VarType::FLOAT32: return “float”;
case VarType::FLOAT64: return “double”;
case VarType::POINTER: return “void*”;
case VarType::BOOL: return “bool”;
default: return “auto”;
}
}

bool Decompiler::IsJumpInstruction(const ZydisDecodedInstruction& instr) {
return (instr.mnemonic >= ZYDIS_MNEMONIC_JB && instr.mnemonic <= ZYDIS_MNEMONIC_JZ) ||
instr.mnemonic == ZYDIS_MNEMONIC_JMP;
}

bool Decompiler::IsCallInstruction(const ZydisDecodedInstruction& instr) {
return instr.mnemonic == ZYDIS_MNEMONIC_CALL;
}

bool Decompiler::IsRetInstruction(const ZydisDecodedInstruction& instr) {
return instr.mnemonic == ZYDIS_MNEMONIC_RET;
}

uintptr_t Decompiler::GetJumpTarget(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands, uintptr_t instrAddr) {

```
if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    ZyanU64 target;
    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[0], instrAddr, &target))) {
        return (uintptr_t)target;
    }
}

return 0;
```

}

bool Decompiler::DecompileFunction(uintptr_t address, size_t maxSize,
const std::string& functionName, const std::string& outputDir) {

```
std::filesystem::create_directories(outputDir);
std::filesystem::create_directories(outputDir + "/asm");
std::filesystem::create_directories(outputDir + "/cpp");

auto cfg = BuildCFG(address, maxSize);
if (!cfg || cfg->blocks.empty()) {
    return false;
}

DetectLoops(*cfg);

FunctionInfo funcInfo;
funcInfo.name = functionName;
funcInfo.address = address;
funcInfo.size = maxSize;

AnalyzeFunction(funcInfo, *cfg);
InferTypes(funcInfo, *cfg);

std::string asmCode = GenerateAsmFile(*cfg, funcInfo);
std::string cppCode = GenerateCppCode(funcInfo, *cfg);

std::string safeName = CreateSafeFileName(functionName);
SaveToFile(outputDir + "/asm/" + safeName + ".asm", asmCode);
SaveToFile(outputDir + "/cpp/" + safeName + ".cpp", cppCode);

return true;
```

}

void Decompiler::SaveToFile(const std::string& path, const std::string& content) {
std::ofstream file(path);
if (file.is_open()) {
file << content;
file.close();
}
}

std::string Decompiler::CreateSafeFileName(const std::string& name) {
std::string safe = name;
for (char& c : safe) {
if (!isalnum(c) && c != ‘*’) {
c = ’*’;
}
}
return safe;
}

CodeGenerator::CodeGenerator(const FunctionInfo& info, const ControlFlowGraph& cfg)
: funcInfo(info), cfg(cfg), indentLevel(0) {}

std::string CodeGenerator::Generate() {
GenerateFunctionSignature();
code << “ {\n”;
IncIndent();

```
GenerateVariableDeclarations();

if (cfg.entryBlock) {
    GenerateBlockRecursive(cfg.entryBlock);
}

DecIndent();
code << "}\n";

return code.str();
```

}

void CodeGenerator::GenerateFunctionSignature() {
code << TypeToString(funcInfo.returnValue.type) << “ “ << funcInfo.name << “(”;

```
for (size_t i = 0; i < funcInfo.parameters.size(); i++) {
    const auto& param = funcInfo.parameters[i];
    code << TypeToString(param.type) << " " << param.name;
    if (i < funcInfo.parameters.size() - 1) {
        code << ", ";
    }
}

code << ")";
```

}

void CodeGenerator::GenerateVariableDeclarations() {
for (const auto& [name, var] : funcInfo.localVars) {
code << Indent() << TypeToString(var.type) << “ “ << var.name << “;\n”;
}
if (!funcInfo.localVars.empty()) {
code << “\n”;
}
}

void CodeGenerator::GenerateBlockRecursive(const BasicBlock* block) {
if (!block || processedBlocks.count(block->blockId)) {
return;
}

```
processedBlocks.insert(block->blockId);

if (block->isLoopHeader) {
    code << Indent() << "while (true) {\n";
    IncIndent();
}

size_t opIndex = 0;
for (const auto& instr : block->instructions) {
    const auto* operands = &block->operands[opIndex];
    GenerateInstruction(instr, operands);
    opIndex += instr.operand_count;
}

if (block->successors.size() == 1) {
    GenerateBlockRecursive(block->successors[0]);
} else if (block->successors.size() == 2) {
    const auto& lastInstr = block->instructions.back();
    
    code << Indent() << "if (";
    ExpressionBuilder exprBuilder(funcInfo);
    code << exprBuilder.BuildCondition(lastInstr);
    code << ") {\n";
    IncIndent();
    GenerateBlockRecursive(block->successors[0]);
    DecIndent();
    code << Indent() << "} else {\n";
    IncIndent();
    GenerateBlockRecursive(block->successors[1]);
    DecIndent();
    code << Indent() << "}\n";
}

if (block->isLoopEnd) {
    DecIndent();
    code << Indent() << "}\n";
}
```

}

void CodeGenerator::GenerateInstruction(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {

```
ExpressionBuilder exprBuilder(funcInfo);

if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
    code << Indent() << exprBuilder.BuildExpression(instr, operands) << ";\n";
} else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD || 
           instr.mnemonic == ZYDIS_MNEMONIC_SUB ||
           instr.mnemonic == ZYDIS_MNEMONIC_XOR ||
           instr.mnemonic == ZYDIS_MNEMONIC_OR ||
           instr.mnemonic == ZYDIS_MNEMONIC_AND) {
    code << Indent() << exprBuilder.BuildExpression(instr, operands) << ";\n";
} else if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
    code << Indent() << "CallFunction_" << std::hex << operands[0].imm.value.u << "();\n";
} else if (instr.mnemonic == ZYDIS_MNEMONIC_RET) {
    code << Indent() << "return result;\n";
} else if (!IsJumpInstruction(instr)) {
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instr, operands, 
        instr.operand_count, buffer, sizeof(buffer), 0);
    code << Indent() << "// " << buffer << "\n";
}
```

}

std::string CodeGenerator::Indent() {
return std::string(indentLevel * 4, ’ ’);
}

std::string CodeGenerator::TypeToString(VarType type) {
Decompiler d;
return d.TypeToString(type);
}

std::string ExpressionBuilder::BuildExpression(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands) {

```
std::stringstream ss;

if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
    ss << GetOperandString(operands[0]) << " = " << GetOperandString(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD) {
    ss << GetOperandString(operands[0]) << " += " << GetOperandString(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB) {
    ss << GetOperandString(operands[0]) << " -= " << GetOperandString(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
    ss << GetOperandString(operands[0]) << " ^= " << GetOperandString(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_OR) {
    ss << GetOperandString(operands[0]) << " |= " << GetOperandString(operands[1]);
} else if (instr.mnemonic == ZYDIS_MNEMONIC_AND) {
    ss << GetOperandString(operands[0]) << " &= " << GetOperandString(operands[1]);
}

return ss.str();
```

}

std::string ExpressionBuilder::BuildCondition(const ZydisDecodedInstruction& instr) {
switch (instr.mnemonic) {
case ZYDIS_MNEMONIC_JE: return “condition_equal”;
case ZYDIS_MNEMONIC_JNE: return “condition_not_equal”;
case ZYDIS_MNEMONIC_JL: return “condition_less”;
case ZYDIS_MNEMONIC_JLE: return “condition_less_equal”;
case ZYDIS_MNEMONIC_JG: return “condition_greater”;
case ZYDIS_MNEMONIC_JGE: return “condition_greater_equal”;
case ZYDIS_MNEMONIC_JB: return “condition_below”;
case ZYDIS_MNEMONIC_JBE: return “condition_below_equal”;
case ZYDIS_MNEMONIC_JA: return “condition_above”;
case ZYDIS_MNEMONIC_JAE: return “condition_above_equal”;
default: return “condition_unknown”;
}
}

std::string ExpressionBuilder::GetOperandString(const ZydisDecodedOperand& op) {
std::stringstream ss;

```
if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
    ss << GetRegisterName(op.reg.value);
} else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    ss << "0x" << std::hex << op.imm.value.u;
} else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
    ss << "*(" << GetRegisterName(op.mem.base);
    if (op.mem.disp.has_displacement) {
        if (op.mem.disp.value >= 0) {
            ss << " + 0x" << std::hex << op.mem.disp.value;
        } else {
            ss << " - 0x" << std::hex << (-op.mem.disp.value);
        }
    }
    ss << ")";
}

return ss.str();
```

}

std::string ExpressionBuilder::GetRegisterName(ZydisRegister reg) {
switch (reg) {
case ZYDIS_REGISTER_RAX: return “rax”;
case ZYDIS_REGISTER_RBX: return “rbx”;
case ZYDIS_REGISTER_RCX: return “rcx”;
case ZYDIS_REGISTER_RDX: return “rdx”;
case ZYDIS_REGISTER_RSI: return “rsi”;
case ZYDIS_REGISTER_RDI: return “rdi”;
case ZYDIS_REGISTER_RBP: return “rbp”;
case ZYDIS_REGISTER_RSP: return “rsp”;
case ZYDIS_REGISTER_R8: return “r8”;
case ZYDIS_REGISTER_R9: return “r9”;
case ZYDIS_REGISTER_R10: return “r10”;
case ZYDIS_REGISTER_R11: return “r11”;
case ZYDIS_REGISTER_R12: return “r12”;
case ZYDIS_REGISTER_R13: return “r13”;
case ZYDIS_REGISTER_R14: return “r14”;
case ZYDIS_REGISTER_R15: return “r15”;
case ZYDIS_REGISTER_EAX: return “eax”;
case ZYDIS_REGISTER_EBX: return “ebx”;
case ZYDIS_REGISTER_ECX: return “ecx”;
case ZYDIS_REGISTER_EDX: return “edx”;
default: return “reg_unknown”;
}
}
