#include “AdvancedAnalysis.h”
#include <queue>
#include <algorithm>
#include <sstream>

SliceAnalyzer::Slice SliceAnalyzer::ComputeBackwardSlice(const ControlFlowGraph& cfg,
BasicBlock* start, size_t instrIndex, ZydisRegister targetReg) {

```
Slice slice;
slice.targetRegister = targetReg;

std::queue<std::pair<BasicBlock*, size_t>> worklist;
std::set<std::pair<BasicBlock*, size_t>> visited;

worklist.push({start, instrIndex});

while (!worklist.empty()) {
    auto [block, idx] = worklist.front();
    worklist.pop();
    
    if (visited.count({block, idx})) continue;
    visited.insert({block, idx});
    
    slice.blocks.push_back(block);
    slice.instructionIndices.push_back(idx);
    
    if (idx > 0) {
        const auto& instr = block->instructions[idx - 1];
        size_t opIdx = 0;
        for (size_t i = 0; i < idx - 1; i++) {
            opIdx += block->instructions[i].operand_count;
        }
        const auto* operands = &block->operands[opIdx];
        
        bool defines = false;
        for (int i = 0; i < instr.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[i].reg.value == targetReg &&
                (operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE)) {
                defines = true;
            }
        }
        
        if (!defines) {
            worklist.push({block, idx - 1});
        }
    } else {
        for (auto* pred : block->predecessors) {
            if (!pred->instructions.empty()) {
                worklist.push({pred, pred->instructions.size() - 1});
            }
        }
    }
}

return slice;
```

}

std::string SliceAnalyzer::GenerateSliceCode(const Slice& slice, const FunctionInfo& funcInfo) {
std::stringstream ss;
ss << “// Slice for register: “;
ExpressionBuilder builder(funcInfo);
ss << builder.GetRegisterName(slice.targetRegister) << “\n”;

```
for (size_t i = 0; i < slice.blocks.size(); i++) {
    BasicBlock* block = slice.blocks[i];
    size_t idx = slice.instructionIndices[i];
    
    if (idx < block->instructions.size()) {
        const auto& instr = block->instructions[idx];
        char buffer[256];
        
        size_t opIdx = 0;
        for (size_t j = 0; j < idx; j++) {
            opIdx += block->instructions[j].operand_count;
        }
        
        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterFormatInstruction(&formatter, &instr, 
            &block->operands[opIdx], instr.operand_count,
            buffer, sizeof(buffer), block->startAddr);
        
        ss << buffer << "\n";
    }
}

return ss.str();
```

}

void SymbolicExecutor::Execute(const ControlFlowGraph& cfg) {
if (!cfg.entryBlock) return;

```
std::queue<BasicBlock*> worklist;
std::set<BasicBlock*> visited;

worklist.push(cfg.entryBlock);

while (!worklist.empty()) {
    BasicBlock* block = worklist.front();
    worklist.pop();
    
    if (visited.count(block)) continue;
    visited.insert(block);
    
    ExecuteBlock(block);
    
    for (auto* succ : block->successors) {
        worklist.push(succ);
    }
}
```

}

void SymbolicExecutor::ExecuteBlock(BasicBlock* block) {
std::map<ZydisRegister, SymbolicValue> state;

```
for (auto* pred : block->predecessors) {
    auto& predState = symbolicStates[pred];
    for (const auto& [reg, value] : predState) {
        if (state.count(reg) == 0) {
            state[reg] = value;
        } else if (state[reg].expression != value.expression) {
            SymbolicValue phi;
            phi.expression = "phi(" + state[reg].expression + ", " + value.expression + ")";
            phi.isConcrete = false;
            state[reg] = phi;
        }
    }
}

size_t opIndex = 0;
for (const auto& instr : block->instructions) {
    const auto* operands = &block->operands[opIndex];
    
    if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            SymbolicValue value = EvaluateOperand(operands[1], state);
            state[operands[0].reg.value] = value;
        }
    } else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD ||
               instr.mnemonic == ZYDIS_MNEMONIC_SUB) {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            SymbolicValue left = state[operands[0].reg.value];
            SymbolicValue right = EvaluateOperand(operands[1], state);
            state[operands[0].reg.value] = ApplyOperation(instr.mnemonic, left, right);
        }
    } else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR) {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[0].reg.value == operands[1].reg.value) {
            SymbolicValue zero;
            zero.expression = "0";
            zero.isConcrete = true;
            zero.concreteValue = 0;
            state[operands[0].reg.value] = zero;
        }
    }
    
    opIndex += instr.operand_count;
}

symbolicStates[block] = state;
```

}

SymbolicExecutor::SymbolicValue SymbolicExecutor::EvaluateOperand(
const ZydisDecodedOperand& op, const std::map<ZydisRegister, SymbolicValue>& state) {

```
SymbolicValue value;

if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
    auto it = state.find(op.reg.value);
    if (it != state.end()) {
        return it->second;
    }
    
    value.isConcrete = false;
    ExpressionBuilder builder(FunctionInfo{});
    value.expression = builder.GetRegisterName(op.reg.value);
} else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    value.isConcrete = true;
    value.concreteValue = op.imm.value.u;
    value.expression = std::to_string(op.imm.value.u);
} else {
    value.isConcrete = false;
    value.expression = "mem_access";
}

return value;
```

}

SymbolicExecutor::SymbolicValue SymbolicExecutor::ApplyOperation(
ZydisMnemonic op, const SymbolicValue& left, const SymbolicValue& right) {

```
SymbolicValue result;

if (left.isConcrete && right.isConcrete) {
    result.isConcrete = true;
    
    if (op == ZYDIS_MNEMONIC_ADD) {
        result.concreteValue = left.concreteValue + right.concreteValue;
    } else if (op == ZYDIS_MNEMONIC_SUB) {
        result.concreteValue = left.concreteValue - right.concreteValue;
    }
    
    result.expression = std::to_string(result.concreteValue);
} else {
    result.isConcrete = false;
    
    if (op == ZYDIS_MNEMONIC_ADD) {
        result.expression = "(" + left.expression + " + " + right.expression + ")";
    } else if (op == ZYDIS_MNEMONIC_SUB) {
        result.expression = "(" + left.expression + " - " + right.expression + ")";
    }
}

return result;
```

}

std::vector<InductionVariableAnalyzer::InductionVariable>
InductionVariableAnalyzer::FindInductionVariables(const ControlFlowGraph& cfg,
BasicBlock* loopHeader) {
std::vector<InductionVariable> ivs;

```
std::set<BasicBlock*> loopBlocks;
std::queue<BasicBlock*> worklist;
worklist.push(loopHeader);

while (!worklist.empty()) {
    BasicBlock* block = worklist.front();
    worklist.pop();
    
    if (loopBlocks.count(block)) continue;
    loopBlocks.insert(block);
    
    for (auto* succ : block->successors) {
        if (succ != loopHeader) {
            worklist.push(succ);
        }
    }
}

std::set<ZydisRegister> candidates;

for (auto* block : loopBlocks) {
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_ADD || instr.mnemonic == ZYDIS_MNEMONIC_INC) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                candidates.insert(operands[0].reg.value);
            }
        }
        
        opIndex += instr.operand_count;
    }
}

for (auto reg : candidates) {
    if (IsInductionVariable(cfg, loopHeader, reg)) {
        InductionVariable iv;
        ExpressionBuilder builder(FunctionInfo{});
        iv.reg = reg;
        iv.name = builder.GetRegisterName(reg);
        iv.initialValue = 0;
        iv.stepValue = 1;
        iv.isBasic = true;
        iv.expression = iv.name + " += " + std::to_string(iv.stepValue);
        ivs.push_back(iv);
    }
}

return ivs;
```

}

bool InductionVariableAnalyzer::IsInductionVariable(const ControlFlowGraph& cfg,
BasicBlock* loopHeader, ZydisRegister reg) {

```
bool hasInit = false;
bool hasIncrement = false;

for (const auto& block : cfg.blocks) {
    size_t opIndex = 0;
    for (const auto& instr : block->instructions) {
        const auto* operands = &block->operands[opIndex];
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == reg &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                hasInit = true;
            }
        }
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_ADD || instr.mnemonic == ZYDIS_MNEMONIC_INC) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == reg) {
                hasIncrement = true;
            }
        }
        
        opIndex += instr.operand_count;
    }
}

return hasInit && hasIncrement;
```

}

RecursionDetector::RecursionInfo RecursionDetector::DetectRecursion(
const ControlFlowGraph& cfg, const FunctionInfo& funcInfo) {

```
RecursionInfo info;
info.isRecursive = false;
info.isTailRecursive = false;

for (const auto& block : cfg.blocks) {
    size_t opIndex = 0;
    for (size_t i = 0; i < block->instructions.size(); i++) {
        const auto& instr = block->instructions[i];
        const auto* operands = &block->operands[opIndex];
        
        if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uintptr_t target = (uintptr_t)operands[0].imm.value.u;
                if (target == funcInfo.address) {
                    info.isRecursive = true;
                    info.recursiveCalls.push_back(block.get());
                    
                    if (i + 1 < block->instructions.size() &&
                        block->instructions[i + 1].mnemonic == ZYDIS_MNEMONIC_RET) {
                        info.isTailRecursive = true;
                    }
                }
            }
        }
        
        opIndex += instr.operand_count;
    }
}

return info;
```

}

std::string RecursionDetector::ConvertToIterative(const RecursionInfo& info,
const ControlFlowGraph& cfg) {

```
std::stringstream ss;

if (info.isTailRecursive) {
    ss << "while (true) {\n";
    ss << "    if (base_case) {\n";
    ss << "        return result;\n";
    ss << "    }\n";
    ss << "    // Update parameters for next iteration\n";
    ss << "}\n";
} else {
    ss << "// Stack-based conversion needed for non-tail recursion\n";
    ss << "std::stack<State> callStack;\n";
    ss << "// ... implementation\n";
}

return ss.str();
```

}

std::string ExpressionSimplifier::Simplify(const std::string& expr) {
std::string result = expr;
result = FoldConstants(result);
result = EliminateIdentities(result);
result = ApplyAlgebraicRules(result);
return result;
}

std::string ExpressionSimplifier::FoldConstants(const std::string& expr) {
std::string result = expr;

```
size_t pos = result.find(" + 0");
while (pos != std::string::npos) {
    result.erase(pos, 4);
    pos = result.find(" + 0");
}

pos = result.find(" * 1");
while (pos != std::string::npos) {
    result.erase(pos, 4);
    pos = result.find(" * 1");
}

return result;
```

}

std::string ExpressionSimplifier::EliminateIdentities(const std::string& expr) {
return expr;
}

std::string ExpressionSimplifier::ApplyAlgebraicRules(const std::string& expr) {
return expr;
}

AliasAnalyzer::AliasResult AliasAnalyzer::CheckAlias(const ZydisDecodedOperand& ptr1,
const ZydisDecodedOperand& ptr2, const ControlFlowGraph& cfg) {

```
if (ptr1.type != ZYDIS_OPERAND_TYPE_MEMORY || 
    ptr2.type != ZYDIS_OPERAND_TYPE_MEMORY) {
    return AliasResult::NO_ALIAS;
}

if (ptr1.mem.base != ptr2.mem.base) {
    return AliasResult::NO_ALIAS;
}

if (ptr1.mem.disp.has_displacement && ptr2.mem.disp.has_displacement) {
    if (ptr1.mem.disp.value == ptr2.mem.disp.value) {
        return AliasResult::MUST_ALIAS;
    } else {
        return AliasResult::NO_ALIAS;
    }
}

return AliasResult::MAY_ALIAS;
```

}

void ConstantPropagator::Propagate(ControlFlowGraph& cfg) {
bool changed = true;

```
while (changed) {
    changed = false;
    
    for (auto& block : cfg.blocks) {
        PropagateInBlock(block.get());
    }
}
```

}

void ConstantPropagator::PropagateInBlock(BasicBlock* block) {
size_t opIndex = 0;

```
for (auto& instr : block->instructions) {
    auto* operands = &block->operands[opIndex];
    
    if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            
            ConstantValue cv;
            cv.isConstant = true;
            cv.value = operands[1].imm.value.u;
            constantValues[operands[0].reg.value] = cv;
        }
    } else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD) {
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            auto it1 = constantValues.find(operands[0].reg.value);
            
            if (it1 != constantValues.end() && it1->second.isConstant &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                
                ConstantValue result;
                result.isConstant = true;
                result.value = it1->second.value + operands[1].imm.value.u;
                constantValues[operands[0].reg.value] = result;
            }
        }
    }
    
    opIndex += instr.operand_count;
}
```

}

std::vector<VirtualTableReconstructor::VirtualTable>
VirtualTableReconstructor::ReconstructVTables(uintptr_t moduleBase, size_t moduleSize) {
std::vector<VirtualTable> vtables;

```
for (uintptr_t addr = moduleBase; addr < moduleBase + moduleSize; addr += 8) {
    if (IsVTablePointer(addr)) {
        VirtualTable vtable;
        vtable.vtableAddress = addr;
        vtable.className = "Class_" + std::to_string(vtables.size());
        
        auto entries = ExtractVTableEntries(addr);
        for (size_t i = 0; i < entries.size(); i++) {
            VirtualMethod method;
            method.name = "VirtualMethod" + std::to_string(i);
            method.vtableOffset = (int)(i * 8);
            method.address = entries[i];
            vtable.methods.push_back(method);
        }
        
        vtables.push_back(vtable);
    }
}

return vtables;
```

}

bool VirtualTableReconstructor::IsVTablePointer(uintptr_t address) {
__try {
uintptr_t* ptr = (uintptr_t*)address;
uintptr_t value = *ptr;

```
    if (value > 0x10000 && value < 0x7FFFFFFFFFFF) {
        return true;
    }
}
__except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
}

return false;
```

}

std::vector<uintptr_t> VirtualTableReconstructor::ExtractVTableEntries(uintptr_t vtableAddr) {
std::vector<uintptr_t> entries;

```
__try {
    uintptr_t* ptr = (uintptr_t*)vtableAddr;
    
    for (int i = 0; i < 100; i++) {
        uintptr_t entry = ptr[i];
        
        if (entry == 0 || entry < 0x10000) {
            break;
        }
        
        entries.push_back(entry);
    }
}
__except (EXCEPTION_EXECUTE_HANDLER) {
}

return entries;
```

}
