#pragma once
#include “Decompiler.h”
#include “PatternRecognition.h”
#include <map>
#include <string>
#include <vector>

class SliceAnalyzer {
public:
struct Slice {
std::vector<BasicBlock*> blocks;
std::vector<size_t> instructionIndices;
ZydisRegister targetRegister;
std::string sliceVariable;
};

```
Slice ComputeBackwardSlice(const ControlFlowGraph& cfg, BasicBlock* start, 
                          size_t instrIndex, ZydisRegister targetReg);

Slice ComputeForwardSlice(const ControlFlowGraph& cfg, BasicBlock* start,
                         size_t instrIndex, ZydisRegister targetReg);

std::string GenerateSliceCode(const Slice& slice, const FunctionInfo& funcInfo);
```

};

class SymbolicExecutor {
public:
struct SymbolicValue {
std::string expression;
bool isConcrete;
uint64_t concreteValue;
std::set<ZydisRegister> dependencies;
};

```
void Execute(const ControlFlowGraph& cfg);
SymbolicValue GetRegisterValue(BasicBlock* block, ZydisRegister reg);
```

private:
std::map<BasicBlock*, std::map<ZydisRegister, SymbolicValue>> symbolicStates;

```
void ExecuteBlock(BasicBlock* block);
SymbolicValue EvaluateOperand(const ZydisDecodedOperand& op, 
                             const std::map<ZydisRegister, SymbolicValue>& state);

SymbolicValue ApplyOperation(ZydisMnemonic op, const SymbolicValue& left, 
                           const SymbolicValue& right);
```

};

class InductionVariableAnalyzer {
public:
struct InductionVariable {
ZydisRegister reg;
std::string name;
int initialValue;
int stepValue;
std::string finalValue;
bool isBasic;
std::string expression;
};

```
std::vector<InductionVariable> FindInductionVariables(const ControlFlowGraph& cfg, 
                                                     BasicBlock* loopHeader);
```

private:
bool IsInductionVariable(const ControlFlowGraph& cfg, BasicBlock* loopHeader,
ZydisRegister reg);
};

class StrengthReductionOptimizer {
public:
void OptimizeMultiplications(ControlFlowGraph& cfg);
void OptimizeDivisions(ControlFlowGraph& cfg);
void ConvertToShifts(ControlFlowGraph& cfg);

private:
bool CanConvertToShift(int multiplier);
int GetShiftAmount(int multiplier);
};

class AliasAnalyzer {
public:
enum class AliasResult {
NO_ALIAS,
MAY_ALIAS,
MUST_ALIAS
};

```
AliasResult CheckAlias(const ZydisDecodedOperand& ptr1, const ZydisDecodedOperand& ptr2,
                      const ControlFlowGraph& cfg);

void BuildPointsToGraph(const ControlFlowGraph& cfg);
```

private:
struct PointerInfo {
ZydisRegister reg;
std::set<uintptr_t> pointsTo;
bool isParameter;
};

```
std::map<ZydisRegister, PointerInfo> pointsToInfo;
```

};

class ExpressionSimplifier {
public:
std::string Simplify(const std::string& expr);

private:
std::string FoldConstants(const std::string& expr);
std::string EliminateIdentities(const std::string& expr);
std::string ApplyAlgebraicRules(const std::string& expr);

```
bool IsConstant(const std::string& token);
int64_t EvaluateConstant(const std::string& token);
```

};

class RecursionDetector {
public:
struct RecursionInfo {
bool isRecursive;
bool isTailRecursive;
std::vector<BasicBlock*> recursiveCalls;
std::string baseCase;
std::string recursiveCase;
};

```
RecursionInfo DetectRecursion(const ControlFlowGraph& cfg, const FunctionInfo& funcInfo);
std::string ConvertToIterative(const RecursionInfo& info, const ControlFlowGraph& cfg);
```

};

class ExceptionHandlingAnalyzer {
public:
struct TryBlock {
BasicBlock* tryStart;
BasicBlock* tryEnd;
std::vector<BasicBlock*> catchBlocks;
BasicBlock* finallyBlock;
};

```
std::vector<TryBlock> DetectExceptionHandling(const ControlFlowGraph& cfg);
std::string GenerateExceptionCode(const TryBlock& tryBlock);
```

private:
bool IsCxxThrow(const ZydisDecodedInstruction& instr);
bool IsCxxCatch(const BasicBlock* block);
};

class VirtualTableReconstructor {
public:
struct VirtualMethod {
std::string name;
int vtableOffset;
uintptr_t address;
FunctionInfo info;
};

```
struct VirtualTable {
    std::string className;
    uintptr_t vtableAddress;
    std::vector<VirtualMethod> methods;
};

std::vector<VirtualTable> ReconstructVTables(uintptr_t moduleBase, size_t moduleSize);
```

private:
bool IsVTablePointer(uintptr_t address);
std::vector<uintptr_t> ExtractVTableEntries(uintptr_t vtableAddr);
};

class ConstantPropagator {
public:
void Propagate(ControlFlowGraph& cfg);

private:
struct ConstantValue {
bool isConstant;
int64_t value;
};

```
std::map<ZydisRegister, ConstantValue> constantValues;

void PropagateInBlock(BasicBlock* block);
bool TryEvaluateConstant(const ZydisDecodedInstruction& instr,
                       const ZydisDecodedOperand* operands,
                       ConstantValue& result);
```

};

class LoopUnroller {
public:
struct UnrollInfo {
int tripCount;
bool canFullyUnroll;
int unrollFactor;
};

```
UnrollInfo AnalyzeLoop(const ControlFlowGraph& cfg, BasicBlock* loopHeader);
std::string GenerateUnrolledCode(const ControlFlowGraph& cfg, 
                                const UnrollInfo& info, BasicBlock* loopHeader);
```

};

class InterprocedualAnalyzer {
public:
struct CallSite {
BasicBlock* block;
size_t instrIndex;
uintptr_t targetAddress;
std::vector<SymbolicExecutor::SymbolicValue> arguments;
SymbolicExecutor::SymbolicValue returnValue;
};

```
void AnalyzeCallGraph(const std::vector<FunctionInfo>& functions);
void PropagateConstants(const std::vector<FunctionInfo>& functions);
void InlineFunctions(ControlFlowGraph& cfg, const std::vector<FunctionInfo>& functions);

std::vector<CallSite> callSites;
```

private:
std::map<uintptr_t, FunctionInfo> functionMap;
std::map<uintptr_t, std::vector<uintptr_t>> callGraph;
};

class PolymorphismDetector {
public:
struct PolymorphicCall {
BasicBlock* callSite;
size_t instrIndex;
std::vector<uintptr_t> possibleTargets;
std::string baseClass;
std::string methodName;
};

```
std::vector<PolymorphicCall> DetectPolymorphicCalls(const ControlFlowGraph& cfg);
std::string GeneratePolymorphicCode(const PolymorphicCall& call);
```

};
