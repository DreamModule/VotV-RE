#pragma once
#include “Decompiler.h”
#include “PatternRecognition.h”
#include <sstream>
#include <map>

class CppCodeEmitter {
public:
CppCodeEmitter(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg);

```
std::string EmitFunction();
std::string EmitHeader();
std::string EmitImplementation();
```

private:
const FunctionInfo& funcInfo;
const ControlFlowGraph& cfg;
std::stringstream header;
std::stringstream impl;
int indentLevel;
std::set<int> emittedBlocks;

```
void EmitFunctionSignature();
void EmitLocalVariables();
void EmitBlockRecursive(const BasicBlock* block);
void EmitInstruction(const ZydisDecodedInstruction& instr, 
                    const ZydisDecodedOperand* operands);

std::string EmitOperand(const ZydisDecodedOperand& op);
std::string EmitMemoryOperand(const ZydisDecodedOperand& op);
std::string EmitRegisterOperand(ZydisRegister reg);
std::string EmitImmediateOperand(const ZydisDecodedOperand& op);

void EmitArithmeticOp(const ZydisDecodedInstruction& instr,
                     const ZydisDecodedOperand* operands);
void EmitComparisonOp(const ZydisDecodedInstruction& instr,
                     const ZydisDecodedOperand* operands);
void EmitBranchOp(const ZydisDecodedInstruction& instr,
                 const ZydisDecodedOperand* operands);
void EmitCallOp(const ZydisDecodedInstruction& instr,
               const ZydisDecodedOperand* operands);

std::string Indent();
void IncIndent() { indentLevel++; }
void DecIndent() { if (indentLevel > 0) indentLevel--; }
```

};

class AsmCodeEmitter {
public:
AsmCodeEmitter(const FunctionInfo& funcInfo, const ControlFlowGraph& cfg);

```
std::string EmitAssembly();
```

private:
const FunctionInfo& funcInfo;
const ControlFlowGraph& cfg;
ZydisFormatter formatter;

```
std::string FormatInstruction(const ZydisDecodedInstruction& instr,
                              const ZydisDecodedOperand* operands,
                              uintptr_t address);

std::string EmitBlockLabel(int blockId);
```

};

class PseudocodeEmitter {
public:
PseudocodeEmitter(const FunctionInfo& funcInfo,
const ControlFlowGraph& cfg,
const PatternRecognizer& patterns);

```
std::string EmitPseudocode();
```

private:
const FunctionInfo& funcInfo;
const ControlFlowGraph& cfg;
const PatternRecognizer& patterns;
std::stringstream code;
int indentLevel;

```
void EmitHighLevelStatement(const BasicBlock* block);
void EmitLoop(const PatternRecognizer::LoopPattern& loop);
void EmitCondition(const PatternRecognizer::ConditionPattern& cond);

std::string SimplifyExpression(const std::string& expr);
std::string InferVariableName(ZydisRegister reg);
```

};

class DocumentationGenerator {
public:
DocumentationGenerator(const FunctionInfo& funcInfo,
const ControlFlowGraph& cfg);

```
std::string GenerateDocumentation();
```

private:
const FunctionInfo& funcInfo;
const ControlFlowGraph& cfg;

```
std::string GenerateFunctionSummary();
std::string GenerateParameterDocs();
std::string GenerateReturnValueDocs();
std::string GenerateComplexityAnalysis();
std::string GenerateCallGraph();
```

};

class HeaderGenerator {
public:
void AddFunction(const FunctionInfo& func);
void AddStruct(const RecoveredStruct& s);
void AddEnum(const std::string& name, const std::map<int, std::string>& values);

```
std::string GenerateHeader(const std::string& guardName);
```

private:
std::vector<FunctionInfo> functions;
std::vector<RecoveredStruct> structs;
std::map<std::string, std::map<int, std::string>> enums;

```
std::string EmitStructDefinition(const RecoveredStruct& s);
std::string EmitEnumDefinition(const std::string& name,
                               const std::map<int, std::string>& values);
std::string EmitFunctionDeclaration(const FunctionInfo& func);
```

};

class ImplementationGenerator {
public:
void AddFunction(const FunctionInfo& func, const ControlFlowGraph& cfg);

```
std::string GenerateImplementation(const std::string& headerName);
```

private:
std::vector<std::pair<FunctionInfo, std::unique_ptr<ControlFlowGraph>>> functions;

```
std::string EmitFunctionImplementation(const FunctionInfo& func,
                                      const ControlFlowGraph& cfg);
```

};

class ProjectGenerator {
public:
ProjectGenerator(const std::string& projectName);

```
void AddSourceFile(const std::string& filename, const std::string& content);
void AddHeaderFile(const std::string& filename, const std::string& content);

void GenerateCMakeLists();
void GenerateREADME();
void GenerateVisualStudioProject();

void SaveProject(const std::string& outputDir);
```

private:
std::string projectName;
std::map<std::string, std::string> sourceFiles;
std::map<std::string, std::string> headerFiles;

```
std::string GenerateCMakeContent();
std::string GenerateReadmeContent();
std::string GenerateVcxprojContent();
```

};

class CompilableCodeGenerator {
public:
CompilableCodeGenerator(const std::vector<FunctionInfo>& functions,
const std::vector<ControlFlowGraph>& cfgs,
const std::vector<RecoveredStruct>& structs);

```
void Generate(const std::string& outputDir);
```

private:
const std::vector<FunctionInfo>& functions;
const std::vector<ControlFlowGraph>& cfgs;
const std::vector<RecoveredStruct>& structs;

```
void GenerateHeaders();
void GenerateImplementations();
void GenerateTypes();
void GenerateBuildSystem();

std::string outputDirectory;
```

};
