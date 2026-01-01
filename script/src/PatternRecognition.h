#pragma once
#include “Decompiler.h”
#include <functional>

enum class PatternType {
LOOP_FOR,
LOOP_WHILE,
LOOP_DO_WHILE,
IF_THEN,
IF_THEN_ELSE,
SWITCH_CASE,
TERNARY,
FUNCTION_CALL,
VIRTUAL_CALL,
ARRAY_ACCESS,
STRUCT_ACCESS,
POINTER_DEREF,
STRING_OPERATION,
MATH_OPERATION,
BITWISE_OPERATION,
COMPARISON,
LOGICAL_AND_OR,
MEMCPY,
MEMSET,
STRLEN,
CONSTRUCTOR,
DESTRUCTOR,
VTABLE_LOOKUP,
THISCALL_CONVENTION,
FASTCALL_CONVENTION
};

struct Pattern {
PatternType type;
std::string description;
std::vector<ZydisMnemonic> mnemonics;
std::function<bool(const BasicBlock*, size_t)> matcher;
std::function<std::string(const BasicBlock*, size_t, const FunctionInfo&)> generator;
};

class PatternRecognizer {
public:
PatternRecognizer();

```
void RegisterPattern(const Pattern& pattern);
bool RecognizePattern(const BasicBlock* block, size_t instrIndex, PatternType& outType);
std::string GenerateCode(const BasicBlock* block, size_t instrIndex, 
                       PatternType type, const FunctionInfo& funcInfo);

void DetectLoopPatterns(ControlFlowGraph& cfg);
void DetectConditionPatterns(ControlFlowGraph& cfg);
void DetectFunctionCallPatterns(ControlFlowGraph& cfg);

struct LoopPattern {
    BasicBlock* header;
    BasicBlock* body;
    BasicBlock* increment;
    BasicBlock* exit;
    PatternType loopType;
    std::string initExpr;
    std::string condExpr;
    std::string incrExpr;
};

struct ConditionPattern {
    BasicBlock* condition;
    BasicBlock* thenBranch;
    BasicBlock* elseBranch;
    BasicBlock* merge;
    std::string conditionExpr;
};

std::vector<LoopPattern> detectedLoops;
std::vector<ConditionPattern> detectedConditions;
```

private:
std::vector<Pattern> patterns;

```
void InitializePatterns();

bool MatchForLoop(const BasicBlock* block);
bool MatchWhileLoop(const BasicBlock* block);
bool MatchDoWhileLoop(const BasicBlock* block);
bool MatchIfThenElse(const BasicBlock* block);
bool MatchSwitchCase(const BasicBlock* block);
bool MatchMemcpy(const BasicBlock* block, size_t instrIndex);
bool MatchMemset(const BasicBlock* block, size_t instrIndex);
bool MatchVirtualCall(const BasicBlock* block, size_t instrIndex);

std::string GenerateForLoop(const LoopPattern& loop, const FunctionInfo& funcInfo);
std::string GenerateWhileLoop(const LoopPattern& loop, const FunctionInfo& funcInfo);
std::string GenerateIfElse(const ConditionPattern& cond, const FunctionInfo& funcInfo);
```

};

class HighLevelConstructs {
public:
static std::string RecognizeStdString(const std::vector<ZydisDecodedInstruction>& instructions);
static std::string RecognizeStdVector(const std::vector<ZydisDecodedInstruction>& instructions);
static std::string RecognizeStdMap(const std::vector<ZydisDecodedInstruction>& instructions);
static std::string RecognizeSmartPointer(const std::vector<ZydisDecodedInstruction>& instructions);
static std::string RecognizeException(const std::vector<ZydisDecodedInstruction>& instructions);
static std::string RecognizeRTTI(const std::vector<ZydisDecodedInstruction>& instructions);
};

class CallingConvention {
public:
enum class Convention {
CDECL,
STDCALL,
FASTCALL,
THISCALL,
VECTORCALL,
X64_WINDOWS,
X64_SYSTEMV
};

```
static Convention DetectConvention(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg);
static std::vector<Variable> ExtractParameters(Convention conv, const ControlFlowGraph& cfg);
static Variable DetermineReturnType(Convention conv, const ControlFlowGraph& cfg);
```

};

class TypeRecovery {
public:
void RecoverTypes(FunctionInfo& funcInfo, const ControlFlowGraph& cfg);

private:
VarType InferFromOperations(const std::vector<ZydisDecodedInstruction>& instrs, ZydisRegister reg);
VarType InferFromComparison(const ZydisDecodedInstruction& instr);
VarType InferFromMemoryAccess(const ZydisDecodedOperand& memOp);

```
bool IsFloatOperation(ZydisMnemonic mnemonic);
bool IsSignedOperation(ZydisMnemonic mnemonic);
bool IsPointerOperation(const ZydisDecodedInstruction& instr);
```

};

struct StructMember {
std::string name;
VarType type;
int offset;
int size;
};

struct RecoveredStruct {
std::string name;
int totalSize;
std::vector<StructMember> members;
};

class StructureRecovery {
public:
std::vector<RecoveredStruct> RecoverStructures(const ControlFlowGraph& cfg);

private:
void AnalyzeMemoryAccesses(const ControlFlowGraph& cfg,
std::map<int, std::vector<int>>& baseToOffsets);

```
RecoveredStruct BuildStructFromOffsets(const std::vector<int>& offsets);
```

};
