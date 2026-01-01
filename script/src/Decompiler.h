#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <sstream>
#include <Zydis/Zydis.h>

enum class VarType {
UNKNOWN,
INT8, INT16, INT32, INT64,
UINT8, UINT16, UINT32, UINT64,
FLOAT32, FLOAT64,
POINTER,
BOOL,
STRING,
VECTOR,
STRUCT
};

struct Variable {
std::string name;
VarType type;
int offset;
bool isParameter;
bool isReturn;
int size;
};

struct BasicBlock {
uintptr_t startAddr;
uintptr_t endAddr;
std::vector<ZydisDecodedInstruction> instructions;
std::vector<ZydisDecodedOperand> operands;
std::vector<BasicBlock*> successors;
std::vector<BasicBlock*> predecessors;
int blockId;
bool visited;
bool isLoopHeader;
bool isLoopEnd;
BasicBlock* loopHeader;
};

struct ControlFlowGraph {
std::vector<std::unique_ptr<BasicBlock>> blocks;
BasicBlock* entryBlock;
std::map<uintptr_t, BasicBlock*> addressToBlock;
};

struct FunctionInfo {
std::string name;
uintptr_t address;
size_t size;
std::vector<Variable> parameters;
Variable returnValue;
std::map<std::string, Variable> localVars;
int stackSize;
bool usesFramePointer;
};

class Decompiler {
public:
Decompiler();
~Decompiler();

```
bool Initialize();
bool DecompileFunction(uintptr_t address, size_t maxSize, const std::string& functionName, const std::string& outputDir);
bool DecompileModule(uintptr_t baseAddr, size_t moduleSize, const std::string& outputDir);
```

private:
ZydisDecoder decoder;
ZydisFormatter formatter;

```
std::unique_ptr<ControlFlowGraph> BuildCFG(uintptr_t address, size_t size);
void AnalyzeFunction(FunctionInfo& funcInfo, const ControlFlowGraph& cfg);
void InferTypes(FunctionInfo& funcInfo, const ControlFlowGraph& cfg);
void DetectLoops(ControlFlowGraph& cfg);
void PerformDataFlowAnalysis(const ControlFlowGraph& cfg, FunctionInfo& funcInfo);

std::string GenerateCppCode(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg);
std::string GenerateBlockCode(const BasicBlock* block, const FunctionInfo& funcInfo, int indent);
std::string GenerateAsmFile(const ControlFlowGraph& cfg, const FunctionInfo& funcInfo);

std::string TypeToString(VarType type);
std::string GetOperandValue(const ZydisDecodedOperand& operand, const FunctionInfo& funcInfo);
VarType InferTypeFromInstruction(const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op);

bool IsJumpInstruction(const ZydisDecodedInstruction& instr);
bool IsCallInstruction(const ZydisDecodedInstruction& instr);
bool IsRetInstruction(const ZydisDecodedInstruction& instr);
uintptr_t GetJumpTarget(const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* operands, uintptr_t instrAddr);

void SaveToFile(const std::string& path, const std::string& content);
std::string CreateSafeFileName(const std::string& name);
```

};

class ExpressionBuilder {
public:
ExpressionBuilder(const FunctionInfo& funcInfo) : funcInfo(funcInfo) {}

```
std::string BuildExpression(const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* operands);
std::string BuildCondition(const ZydisDecodedInstruction& instr);
```

private:
const FunctionInfo& funcInfo;
std::map<ZydisRegister, std::string> registerValues;

```
std::string GetRegisterName(ZydisRegister reg);
std::string GetOperandString(const ZydisDecodedOperand& op);
bool IsComparisonInstruction(const ZydisDecodedInstruction& instr);
```

};

class StructureAnalyzer {
public:
void AnalyzeIfElse(ControlFlowGraph& cfg);
void AnalyzeLoops(ControlFlowGraph& cfg);
void AnalyzeSwitch(ControlFlowGraph& cfg);

```
struct IfElseStructure {
    BasicBlock* condition;
    BasicBlock* thenBlock;
    BasicBlock* elseBlock;
    BasicBlock* mergeBlock;
};

struct LoopStructure {
    BasicBlock* header;
    BasicBlock* body;
    BasicBlock* exit;
    bool isDoWhile;
    bool isFor;
};

std::vector<IfElseStructure> ifElseStructures;
std::vector<LoopStructure> loopStructures;
```

};

class CodeGenerator {
public:
CodeGenerator(const FunctionInfo& info, const ControlFlowGraph& cfg);

```
std::string Generate();
```

private:
const FunctionInfo& funcInfo;
const ControlFlowGraph& cfg;
std::set<int> processedBlocks;
std::stringstream code;
int indentLevel;

```
void GenerateFunctionSignature();
void GenerateVariableDeclarations();
void GenerateBlockRecursive(const BasicBlock* block);
void GenerateInstruction(const ZydisDecodedInstruction& instr, const ZydisDecodedOperand* operands);

std::string Indent();
void IncIndent() { indentLevel++; }
void DecIndent() { if (indentLevel > 0) indentLevel--; }
```

};
