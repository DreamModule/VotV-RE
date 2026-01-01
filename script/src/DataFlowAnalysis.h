#pragma once
#include <set>
#include <map>
#include <vector>
#include <Zydis/Zydis.h>

struct DataFlowState {
std::map<ZydisRegister, std::string> registerValues;
std::map<int, std::string> stackValues;
std::set<ZydisRegister> definedRegisters;
std::set<int> definedStackSlots;
};

class DataFlowAnalyzer {
public:
DataFlowAnalyzer();

```
void AnalyzeBlock(BasicBlock* block, DataFlowState& state);
void PropagateConstants(ControlFlowGraph& cfg);
void EliminateDeadCode(ControlFlowGraph& cfg);
void AnalyzeVariableLifetime(const ControlFlowGraph& cfg, FunctionInfo& funcInfo);

std::map<BasicBlock*, DataFlowState> blockStates;
```

private:
void ProcessInstruction(const ZydisDecodedInstruction& instr,
const ZydisDecodedOperand* operands,
DataFlowState& state);

```
bool IsRegisterDefined(ZydisRegister reg, const DataFlowState& state);
void DefineRegister(ZydisRegister reg, const std::string& value, DataFlowState& state);

std::string EvaluateExpression(const ZydisDecodedOperand& op, const DataFlowState& state);
```

};

class ReachingDefinitions {
public:
void Compute(const ControlFlowGraph& cfg);

```
struct Definition {
    BasicBlock* block;
    int instructionIndex;
    ZydisRegister reg;
    int stackOffset;
};

std::map<BasicBlock*, std::set<Definition>> reachingIn;
std::map<BasicBlock*, std::set<Definition>> reachingOut;
```

private:
std::set<Definition> gen[1000];
std::set<Definition> kill[1000];
};

class LivenessAnalysis {
public:
void Compute(const ControlFlowGraph& cfg);

```
std::map<BasicBlock*, std::set<ZydisRegister>> liveIn;
std::map<BasicBlock*, std::set<ZydisRegister>> liveOut;
```

private:
void ComputeUseAndDef(const BasicBlock* block,
std::set<ZydisRegister>& use,
std::set<ZydisRegister>& def);
};

class DominatorTree {
public:
void Build(const ControlFlowGraph& cfg);

```
bool Dominates(BasicBlock* a, BasicBlock* b) const;
BasicBlock* GetImmediateDominator(BasicBlock* block) const;
std::vector<BasicBlock*> GetDominanceFrontier(BasicBlock* block) const;

std::map<BasicBlock*, BasicBlock*> idom;
std::map<BasicBlock*, std::set<BasicBlock*>> dominators;
std::map<BasicBlock*, std::vector<BasicBlock*>> domFrontier;
```

private:
void ComputeDominators(const ControlFlowGraph& cfg);
void ComputeDominanceFrontier(const ControlFlowGraph& cfg);
};

class SSAConverter {
public:
void ConvertToSSA(ControlFlowGraph& cfg);

```
struct PhiNode {
    ZydisRegister reg;
    std::vector<std::pair<BasicBlock*, std::string>> incomingValues;
};

std::map<BasicBlock*, std::vector<PhiNode>> phiNodes;
```

private:
DominatorTree domTree;

```
void InsertPhiFunctions(ControlFlowGraph& cfg);
void RenameVariables(ControlFlowGraph& cfg);
```

};
