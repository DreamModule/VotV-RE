#include “PatternRecognition.h”
#include <sstream>
#include <algorithm>

PatternRecognizer::PatternRecognizer() {
InitializePatterns();
}

void PatternRecognizer::InitializePatterns() {
Pattern memcpyPattern;
memcpyPattern.type = PatternType::MEMCPY;
memcpyPattern.description = “memcpy loop pattern”;
memcpyPattern.matcher = [this](const BasicBlock* block, size_t idx) {
return MatchMemcpy(block, idx);
};
memcpyPattern.generator = [](const BasicBlock* block, size_t idx, const FunctionInfo& info) {
return “memcpy(dest, src, size)”;
};
patterns.push_back(memcpyPattern);

```
Pattern memsetPattern;
memsetPattern.type = PatternType::MEMSET;
memsetPattern.description = "memset loop pattern";
memsetPattern.matcher = [this](const BasicBlock* block, size_t idx) {
    return MatchMemset(block, idx);
};
memsetPattern.generator = [](const BasicBlock* block, size_t idx, const FunctionInfo& info) {
    return "memset(dest, value, size)";
};
patterns.push_back(memsetPattern);

Pattern vcallPattern;
vcallPattern.type = PatternType::VIRTUAL_CALL;
vcallPattern.description = "virtual function call";
vcallPattern.matcher = [this](const BasicBlock* block, size_t idx) {
    return MatchVirtualCall(block, idx);
};
vcallPattern.generator = [](const BasicBlock* block, size_t idx, const FunctionInfo& info) {
    return "obj->VirtualMethod()";
};
patterns.push_back(vcallPattern);
```

}

void PatternRecognizer::RegisterPattern(const Pattern& pattern) {
patterns.push_back(pattern);
}

bool PatternRecognizer::RecognizePattern(const BasicBlock* block, size_t instrIndex,
PatternType& outType) {
for (const auto& pattern : patterns) {
if (pattern.matcher(block, instrIndex)) {
outType = pattern.type;
return true;
}
}
return false;
}

std::string PatternRecognizer::GenerateCode(const BasicBlock* block, size_t instrIndex,
PatternType type, const FunctionInfo& funcInfo) {
for (const auto& pattern : patterns) {
if (pattern.type == type) {
return pattern.generator(block, instrIndex, funcInfo);
}
}
return “”;
}

bool PatternRecognizer::MatchMemcpy(const BasicBlock* block, size_t instrIndex) {
if (instrIndex + 3 > block->instructions.size()) return false;

```
const auto& instr1 = block->instructions[instrIndex];
const auto& instr2 = block->instructions[instrIndex + 1];
const auto& instr3 = block->instructions[instrIndex + 2];

if (instr1.mnemonic == ZYDIS_MNEMONIC_MOV &&
    instr2.mnemonic == ZYDIS_MNEMONIC_MOV &&
    instr3.mnemonic == ZYDIS_MNEMONIC_ADD) {
    
    size_t op1Idx = 0;
    for (size_t i = 0; i < instrIndex; i++) {
        op1Idx += block->instructions[i].operand_count;
    }
    
    const auto& op1 = block->operands[op1Idx];
    const auto& op2 = block->operands[op1Idx + instr1.operand_count];
    
    if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY &&
        op2.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        return true;
    }
}

return false;
```

}

bool PatternRecognizer::MatchMemset(const BasicBlock* block, size_t instrIndex) {
if (instrIndex + 2 > block->instructions.size()) return false;

```
const auto& instr1 = block->instructions[instrIndex];
const auto& instr2 = block->instructions[instrIndex + 1];

if (instr1.mnemonic == ZYDIS_MNEMONIC_MOV && instr2.mnemonic == ZYDIS_MNEMONIC_ADD) {
    size_t opIdx = 0;
    for (size_t i = 0; i < instrIndex; i++) {
        opIdx += block->instructions[i].operand_count;
    }
    
    const auto& dest = block->operands[opIdx];
    const auto& value = block->operands[opIdx + 1];
    
    if (dest.type == ZYDIS_OPERAND_TYPE_MEMORY &&
        value.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return true;
    }
}

return false;
```

}

bool PatternRecognizer::MatchVirtualCall(const BasicBlock* block, size_t instrIndex) {
if (instrIndex + 1 > block->instructions.size()) return false;

```
const auto& instr = block->instructions[instrIndex];

if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
    size_t opIdx = 0;
    for (size_t i = 0; i < instrIndex; i++) {
        opIdx += block->instructions[i].operand_count;
    }
    
    const auto& target = block->operands[opIdx];
    
    if (target.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        return true;
    }
}

return false;
```

}

void PatternRecognizer::DetectLoopPatterns(ControlFlowGraph& cfg) {
for (auto& block : cfg.blocks) {
if (block->isLoopHeader) {
LoopPattern loop;
loop.header = block.get();

```
        if (block->predecessors.size() >= 2) {
            for (auto* pred : block->predecessors) {
                if (pred->isLoopEnd && pred->loopHeader == block.get()) {
                    loop.body = pred;
                } else {
                    
                }
            }
        }
        
        if (!block->instructions.empty()) {
            const auto& lastInstr = block->instructions.back();
            if (lastInstr.mnemonic == ZYDIS_MNEMONIC_JLE ||
                lastInstr.mnemonic == ZYDIS_MNEMONIC_JL ||
                lastInstr.mnemonic == ZYDIS_MNEMONIC_JGE ||
                lastInstr.mnemonic == ZYDIS_MNEMONIC_JG) {
                loop.loopType = PatternType::LOOP_FOR;
                loop.condExpr = "i < limit";
            } else {
                loop.loopType = PatternType::LOOP_WHILE;
                loop.condExpr = "condition";
            }
        }
        
        detectedLoops.push_back(loop);
    }
}
```

}

void PatternRecognizer::DetectConditionPatterns(ControlFlowGraph& cfg) {
for (auto& block : cfg.blocks) {
if (block->successors.size() == 2) {
ConditionPattern cond;
cond.condition = block.get();
cond.thenBranch = block->successors[0];
cond.elseBranch = block->successors[1];

```
        std::set<BasicBlock*> thenSuccessors;
        std::set<BasicBlock*> elseSuccessors;
        
        if (!cond.thenBranch->successors.empty()) {
            thenSuccessors.insert(cond.thenBranch->successors.begin(), 
                                 cond.thenBranch->successors.end());
        }
        if (!cond.elseBranch->successors.empty()) {
            elseSuccessors.insert(cond.elseBranch->successors.begin(),
                                 cond.elseBranch->successors.end());
        }
        
        for (auto* s : thenSuccessors) {
            if (elseSuccessors.count(s)) {
                cond.merge = s;
                break;
            }
        }
        
        if (!block->instructions.empty()) {
            const auto& lastInstr = block->instructions.back();
            ExpressionBuilder builder(FunctionInfo{});
            cond.conditionExpr = builder.BuildCondition(lastInstr);
        }
        
        detectedConditions.push_back(cond);
    }
}
```

}

std::string PatternRecognizer::GenerateForLoop(const LoopPattern& loop,
const FunctionInfo& funcInfo) {
std::stringstream ss;
ss << “for (” << loop.initExpr << “; “ << loop.condExpr << “; “ << loop.incrExpr << “) {\n”;
ss << “    // loop body\n”;
ss << “}\n”;
return ss.str();
}

std::string PatternRecognizer::GenerateWhileLoop(const LoopPattern& loop,
const FunctionInfo& funcInfo) {
std::stringstream ss;
ss << “while (” << loop.condExpr << “) {\n”;
ss << “    // loop body\n”;
ss << “}\n”;
return ss.str();
}

std::string PatternRecognizer::GenerateIfElse(const ConditionPattern& cond,
const FunctionInfo& funcInfo) {
std::stringstream ss;
ss << “if (” << cond.conditionExpr << “) {\n”;
ss << “    // then branch\n”;
if (cond.elseBranch) {
ss << “} else {\n”;
ss << “    // else branch\n”;
}
ss << “}\n”;
return ss.str();
}

std::string HighLevelConstructs::RecognizeStdString(
const std::vector<ZydisDecodedInstruction>& instructions) {

```
for (const auto& instr : instructions) {
    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
        return "std::string operation detected";
    }
}
return "";
```

}

std::string HighLevelConstructs::RecognizeStdVector(
const std::vector<ZydisDecodedInstruction>& instructions) {

```
for (const auto& instr : instructions) {
    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
        return "std::vector operation detected";
    }
}
return "";
```

}

CallingConvention::Convention CallingConvention::DetectConvention(
const FunctionInfo& funcInfo, const ControlFlowGraph& cfg) {

```
bool usesRCX = false, usesRDX = false, usesR8 = false, usesR9 = false;
bool usesStack = false;

for (const auto& block : cfg.blocks) {
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        
        for (int i = 0; i < instr.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (operands[i].reg.value == ZYDIS_REGISTER_RCX) usesRCX = true;
                if (operands[i].reg.value == ZYDIS_REGISTER_RDX) usesRDX = true;
                if (operands[i].reg.value == ZYDIS_REGISTER_R8) usesR8 = true;
                if (operands[i].reg.value == ZYDIS_REGISTER_R9) usesR9 = true;
            }
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[i].mem.base == ZYDIS_REGISTER_RSP) {
                usesStack = true;
            }
        }
        
        opIndex += instr.operand_count;
    }
}

if (usesRCX || usesRDX || usesR8 || usesR9) {
    return Convention::X64_WINDOWS;
}

return Convention::CDECL;
```

}

std::vector<Variable> CallingConvention::ExtractParameters(Convention conv,
const ControlFlowGraph& cfg) {
std::vector<Variable> params;

```
if (conv == Convention::X64_WINDOWS) {
    std::vector<ZydisRegister> paramRegs = {
        ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9
    };
    
    for (size_t i = 0; i < paramRegs.size(); i++) {
        Variable param;
        param.name = "param" + std::to_string(i);
        param.type = VarType::UINT64;
        param.isParameter = true;
        param.size = 8;
        params.push_back(param);
    }
}

return params;
```

}

void TypeRecovery::RecoverTypes(FunctionInfo& funcInfo, const ControlFlowGraph& cfg) {
std::map<ZydisRegister, std::vector<ZydisDecodedInstruction>> regInstructions;

```
for (const auto& block : cfg.blocks) {
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        
        for (int i = 0; i < instr.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                regInstructions[operands[i].reg.value].push_back(instr);
            }
        }
        
        opIndex += instr.operand_count;
    }
}

for (auto& param : funcInfo.parameters) {
    ZydisRegister reg = ZYDIS_REGISTER_RCX;
    
    if (regInstructions.count(reg)) {
        VarType inferredType = InferFromOperations(regInstructions[reg], reg);
        if (inferredType != VarType::UNKNOWN) {
            param.type = inferredType;
        }
    }
}
```

}

VarType TypeRecovery::InferFromOperations(
const std::vector<ZydisDecodedInstruction>& instrs, ZydisRegister reg) {

```
for (const auto& instr : instrs) {
    if (IsFloatOperation(instr.mnemonic)) {
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVSS ||
            instr.mnemonic == ZYDIS_MNEMONIC_ADDSS) {
            return VarType::FLOAT32;
        }
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVSD ||
            instr.mnemonic == ZYDIS_MNEMONIC_ADDSD) {
            return VarType::FLOAT64;
        }
    }
    
    if (IsPointerOperation(instr)) {
        return VarType::POINTER;
    }
}

return VarType::UINT64;
```

}

bool TypeRecovery::IsFloatOperation(ZydisMnemonic mnemonic) {
return (mnemonic == ZYDIS_MNEMONIC_MOVSS || mnemonic == ZYDIS_MNEMONIC_MOVSD ||
mnemonic == ZYDIS_MNEMONIC_ADDSS || mnemonic == ZYDIS_MNEMONIC_ADDSD ||
mnemonic == ZYDIS_MNEMONIC_SUBSS || mnemonic == ZYDIS_MNEMONIC_SUBSD ||
mnemonic == ZYDIS_MNEMONIC_MULSS || mnemonic == ZYDIS_MNEMONIC_MULSD ||
mnemonic == ZYDIS_MNEMONIC_DIVSS || mnemonic == ZYDIS_MNEMONIC_DIVSD);
}

bool TypeRecovery::IsPointerOperation(const ZydisDecodedInstruction& instr) {
return (instr.mnemonic == ZYDIS_MNEMONIC_LEA);
}

std::vector<RecoveredStruct> StructureRecovery::RecoverStructures(const ControlFlowGraph& cfg) {
std::vector<RecoveredStruct> structs;
std::map<int, std::vector<int>> baseToOffsets;

```
AnalyzeMemoryAccesses(cfg, baseToOffsets);

int structId = 0;
for (const auto& [base, offsets] : baseToOffsets) {
    if (offsets.size() >= 2) {
        RecoveredStruct s = BuildStructFromOffsets(offsets);
        s.name = "Struct" + std::to_string(structId++);
        structs.push_back(s);
    }
}

return structs;
```

}

void StructureRecovery::AnalyzeMemoryAccesses(const ControlFlowGraph& cfg,
std::map<int, std::vector<int>>& baseToOffsets) {

```
for (const auto& block : cfg.blocks) {
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        
        for (int i = 0; i < instr.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                int base = (int)operands[i].mem.base;
                if (operands[i].mem.disp.has_displacement) {
                    int offset = (int)operands[i].mem.disp.value;
                    baseToOffsets[base].push_back(offset);
                }
            }
        }
        
        opIndex += instr.operand_count;
    }
}
```

}

RecoveredStruct StructureRecovery::BuildStructFromOffsets(const std::vector<int>& offsets) {
RecoveredStruct s;

```
std::vector<int> sortedOffsets = offsets;
std::sort(sortedOffsets.begin(), sortedOffsets.end());
sortedOffsets.erase(std::unique(sortedOffsets.begin(), sortedOffsets.end()), 
                   sortedOffsets.end());

for (size_t i = 0; i < sortedOffsets.size(); i++) {
    StructMember member;
    member.name = "field_" + std::to_string(i);
    member.offset = sortedOffsets[i];
    
    if (i + 1 < sortedOffsets.size()) {
        member.size = sortedOffsets[i + 1] - sortedOffsets[i];
    } else {
        member.size = 8;
    }
    
    if (member.size == 1) member.type = VarType::UINT8;
    else if (member.size == 2) member.type = VarType::UINT16;
    else if (member.size == 4) member.type = VarType::UINT32;
    else member.type = VarType::UINT64;
    
    s.members.push_back(member);
}

if (!sortedOffsets.empty()) {
    s.totalSize = sortedOffsets.back() + 8;
}

return s;
```

}
