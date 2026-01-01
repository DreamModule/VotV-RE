#pragma once
#include “Decompiler.h”
#include <vector>
#include <map>

class PeepholeOptimizer {
public:
void Optimize(ControlFlowGraph& cfg);

private:
struct OptimizationRule {
std::vector<ZydisMnemonic> pattern;
std::vector<ZydisMnemonic> replacement;
bool (*matcher)(const std::vector<ZydisDecodedInstruction>&);
void (*applier)(std::vector<ZydisDecodedInstruction>&);
};

```
std::vector<OptimizationRule> rules;

void InitializeRules();
bool ApplyRule(BasicBlock* block, size_t index, const OptimizationRule& rule);

void EliminateRedundantMoves();
void EliminateDeadStores();
void FoldConstants();
void SimplifyArithmetic();
```

};

class CommonSubexpressionEliminator {
public:
void Eliminate(ControlFlowGraph& cfg);

private:
struct Expression {
ZydisMnemonic operation;
std::vector<std::string> operands;
std::string result;

```
    bool operator<(const Expression& other) const;
    bool operator==(const Expression& other) const;
};

std::map<Expression, std::string> availableExpressions;

void ComputeAvailableExpressions(const ControlFlowGraph& cfg);
void ReplaceRedundantExpressions(ControlFlowGraph& cfg);

Expression BuildExpression(const ZydisDecodedInstruction& instr,
                          const ZydisDecodedOperand* operands);
```

};

class RegisterAllocator {
public:
void AllocateRegisters(FunctionInfo& funcInfo, const ControlFlowGraph& cfg);

private:
struct LiveInterval {
ZydisRegister virtualReg;
int start;
int end;
ZydisRegister allocatedReg;
};

```
std::vector<LiveInterval> intervals;
std::set<ZydisRegister> availableRegs;

void ComputeLiveIntervals(const ControlFlowGraph& cfg);
void LinearScanAllocation();
void SpillRegisters(ControlFlowGraph& cfg);
```

};

class BranchOptimizer {
public:
void Optimize(ControlFlowGraph& cfg);

private:
void EliminateUnreachableBlocks(ControlFlowGraph& cfg);
void MergeBlocks(ControlFlowGraph& cfg);
void SimplifyBranches(ControlFlowGraph& cfg);
void ConvertToSwitchCase(ControlFlowGraph& cfg);

```
bool CanMergeBlocks(BasicBlock* a, BasicBlock* b);
```

};

class CodeMotionOptimizer {
public:
void LICMPass(ControlFlowGraph& cfg);
void CodeSinking(ControlFlowGraph& cfg);

private:
bool IsLoopInvariant(const ZydisDecodedInstruction& instr,
const std::set<BasicBlock*>& loopBlocks);

```
void HoistInstructions(BasicBlock* header, const std::set<BasicBlock*>& loopBlocks);
void SinkInstructions(ControlFlowGraph& cfg);
```

};

class InliningEngine {
public:
void InlineSmallFunctions(ControlFlowGraph& cfg,
const std::map<uintptr_t, FunctionInfo>& functions);

private:
bool ShouldInline(const FunctionInfo& func);
void InlineCall(BasicBlock* callSite, size_t instrIndex, const FunctionInfo& target);

```
int maxInlineSize = 100;
int maxRecursionDepth = 3;
```

};

class VectorizationOptimizer {
public:
void VectorizeLoops(ControlFlowGraph& cfg);

private:
struct VectorizableLoop {
BasicBlock* header;
std::vector<ZydisDecodedInstruction> vectorizableOps;
int vectorWidth;
};

```
bool CanVectorize(const std::set<BasicBlock*>& loopBlocks);
VectorizableLoop AnalyzeLoop(BasicBlock* header);
void GenerateVectorCode(const VectorizableLoop& loop);
```

};

class TailCallOptimizer {
public:
void OptimizeTailCalls(ControlFlowGraph& cfg);

private:
bool IsTailCall(const BasicBlock* block, size_t instrIndex);
void ConvertToJump(BasicBlock* block, size_t instrIndex);
};

class ProfilingDataOptimizer {
public:
void SetProfile(const std::map<BasicBlock*, int>& executionCounts);
void OptimizeUsingProfile(ControlFlowGraph& cfg);

private:
std::map<BasicBlock*, int> profile;

```
void ReorderBlocks(ControlFlowGraph& cfg);
void SpecializeHotPaths(ControlFlowGraph& cfg);
```

};
