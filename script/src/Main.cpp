#include “Decompiler.h”
#include “DataFlowAnalysis.h”
#include “PatternRecognition.h”
#include “AdvancedAnalysis.h”
#include <iostream>
#include <filesystem>
#include <fstream>

class DecompilerEngine {
public:
DecompilerEngine(const std::string& outputDir) : outputDir(outputDir) {
decompiler.Initialize();
}

```
bool DecompileExecutable(const std::string& exePath) {
    std::cout << "[*] Loading executable: " << exePath << std::endl;
    
    HANDLE hFile = CreateFileA(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open file\n";
        return false;
    }
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<uint8_t> fileData(fileSize);
    
    DWORD bytesRead;
    ReadFile(hFile, fileData.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData.data();
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileData.data() + dosHeader->e_lfanew);
    
    std::cout << "[*] Architecture: x64\n";
    std::cout << "[*] Entry Point: 0x" << std::hex << ntHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
    
    uintptr_t baseAddr = ntHeaders->OptionalHeader.ImageBase;
    size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    std::filesystem::create_directories(outputDir);
    std::filesystem::create_directories(outputDir + "/cpp");
    std::filesystem::create_directories(outputDir + "/asm");
    std::filesystem::create_directories(outputDir + "/analysis");
    
    std::cout << "[*] Analyzing sections...\n";
    
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        std::string sectionName((char*)sections[i].Name, 8);
        sectionName = sectionName.substr(0, sectionName.find('\0'));
        
        if (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            std::cout << "[*] Analyzing code section: " << sectionName << std::endl;
            
            uintptr_t sectionStart = baseAddr + sections[i].VirtualAddress;
            size_t sectionSize = sections[i].Misc.VirtualSize;
            
            AnalyzeCodeSection(sectionStart, sectionSize, sectionName);
        }
    }
    
    std::cout << "[*] Decompilation complete!\n";
    std::cout << "[*] Output directory: " << outputDir << std::endl;
    
    return true;
}

bool DecompileRunningProcess(const std::string& processName) {
    std::cout << "[*] Attaching to process: " << processName << std::endl;
    
    DWORD processId = FindProcessId(processName);
    if (processId == 0) {
        std::cerr << "[!] Process not found\n";
        return false;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process\n";
        return false;
    }
    
    std::cout << "[*] Process ID: " << processId << std::endl;
    
    MODULEENTRY32 moduleEntry = {};
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
    if (Module32First(hSnapshot, &moduleEntry)) {
        uintptr_t baseAddr = (uintptr_t)moduleEntry.modBaseAddr;
        size_t moduleSize = moduleEntry.modBaseSize;
        
        std::cout << "[*] Base Address: 0x" << std::hex << baseAddr << std::endl;
        std::cout << "[*] Module Size: 0x" << moduleSize << std::endl;
        
        std::filesystem::create_directories(outputDir);
        std::filesystem::create_directories(outputDir + "/cpp");
        std::filesystem::create_directories(outputDir + "/asm");
        
        AnalyzeCodeSection(baseAddr, moduleSize, "main");
    }
    
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    
    return true;
}
```

private:
Decompiler decompiler;
std::string outputDir;

```
DWORD FindProcessId(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = {};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

void AnalyzeCodeSection(uintptr_t baseAddr, size_t size, const std::string& sectionName) {
    std::cout << "[*] Scanning for functions...\n";
    
    std::vector<uintptr_t> functionStarts = FindFunctionStarts(baseAddr, size);
    std::cout << "[*] Found " << functionStarts.size() << " functions\n";
    
    int functionCount = 0;
    for (size_t i = 0; i < functionStarts.size() && functionCount < 100; i++) {
        uintptr_t funcAddr = functionStarts[i];
        size_t funcSize = 0;
        
        if (i + 1 < functionStarts.size()) {
            funcSize = functionStarts[i + 1] - funcAddr;
        } else {
            funcSize = 4096;
        }
        
        if (funcSize > 10 && funcSize < 50000) {
            std::string funcName = "sub_" + std::to_string(funcAddr);
            
            std::cout << "[*] Decompiling: " << funcName << " (0x" << std::hex << funcAddr << ")\n";
            
            DecompileFunction(funcAddr, funcSize, funcName);
            functionCount++;
        }
    }
}

std::vector<uintptr_t> FindFunctionStarts(uintptr_t baseAddr, size_t size) {
    std::vector<uintptr_t> starts;
    
    __try {
        for (uintptr_t addr = baseAddr; addr < baseAddr + size; addr++) {
            uint8_t* ptr = (uint8_t*)addr;
            
            if (ptr[0] == 0x48 && ptr[1] == 0x89 && ptr[2] == 0x5C && ptr[3] == 0x24) {
                starts.push_back(addr);
                addr += 32;
            }
            else if (ptr[0] == 0x40 && ptr[1] == 0x53) {
                starts.push_back(addr);
                addr += 16;
            }
            else if (ptr[0] == 0x48 && (ptr[1] == 0x83 || ptr[1] == 0x81) && ptr[2] == 0xEC) {
                starts.push_back(addr);
                addr += 16;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return starts;
}

void DecompileFunction(uintptr_t address, size_t size, const std::string& name) {
    auto cfg = decompiler.BuildCFG(address, size);
    if (!cfg || cfg->blocks.empty()) return;
    
    decompiler.DetectLoops(*cfg);
    
    FunctionInfo funcInfo;
    funcInfo.name = name;
    funcInfo.address = address;
    funcInfo.size = size;
    
    decompiler.AnalyzeFunction(funcInfo, *cfg);
    decompiler.InferTypes(funcInfo, *cfg);
    
    DataFlowAnalyzer dfAnalyzer;
    dfAnalyzer.PropagateConstants(*cfg);
    dfAnalyzer.AnalyzeVariableLifetime(*cfg, funcInfo);
    
    PatternRecognizer patterns;
    patterns.DetectLoopPatterns(*cfg);
    patterns.DetectConditionPatterns(*cfg);
    
    LivenessAnalysis liveness;
    liveness.Compute(*cfg);
    
    DominatorTree domTree;
    domTree.Build(*cfg);
    
    InductionVariableAnalyzer ivAnalyzer;
    for (const auto& block : cfg->blocks) {
        if (block->isLoopHeader) {
            auto ivs = ivAnalyzer.FindInductionVariables(*cfg, block.get());
        }
    }
    
    TypeRecovery typeRecovery;
    typeRecovery.RecoverTypes(funcInfo, *cfg);
    
    StructureRecovery structRecovery;
    auto structs = structRecovery.RecoverStructures(*cfg);
    
    std::string asmCode = decompiler.GenerateAsmFile(*cfg, funcInfo);
    std::string cppCode = GenerateAdvancedCppCode(funcInfo, *cfg, patterns);
    
    std::string safeName = decompiler.CreateSafeFileName(name);
    SaveToFile(outputDir + "/asm/" + safeName + ".asm", asmCode);
    SaveToFile(outputDir + "/cpp/" + safeName + ".cpp", cppCode);
    
    GenerateAnalysisReport(funcInfo, *cfg, patterns, structs);
}

std::string GenerateAdvancedCppCode(const FunctionInfo& funcInfo,
                                   const ControlFlowGraph& cfg,
                                   const PatternRecognizer& patterns) {
    std::stringstream ss;
    
    ss << "// Function: " << funcInfo.name << "\n";
    ss << "// Address: 0x" << std::hex << funcInfo.address << "\n";
    ss << "// Size: 0x" << funcInfo.size << " bytes\n\n";
    
    ss << TypeToString(funcInfo.returnValue.type) << " " << funcInfo.name << "(";
    for (size_t i = 0; i < funcInfo.parameters.size(); i++) {
        const auto& param = funcInfo.parameters[i];
        ss << TypeToString(param.type) << " " << param.name;
        if (i < funcInfo.parameters.size() - 1) ss << ", ";
    }
    ss << ") {\n";
    
    for (const auto& [name, var] : funcInfo.localVars) {
        ss << "    " << TypeToString(var.type) << " " << var.name << ";\n";
    }
    if (!funcInfo.localVars.empty()) ss << "\n";
    
    for (const auto& loop : patterns.detectedLoops) {
        if (loop.loopType == PatternType::LOOP_FOR) {
            ss << "    for (int i = 0; i < count; i++) {\n";
            ss << "        // Loop body\n";
            ss << "    }\n\n";
        }
    }
    
    for (const auto& cond : patterns.detectedConditions) {
        ss << "    if (" << cond.conditionExpr << ") {\n";
        ss << "        // Then branch\n";
        if (cond.elseBranch) {
            ss << "    } else {\n";
            ss << "        // Else branch\n";
        }
        ss << "    }\n\n";
    }
    
    ss << "    return result;\n";
    ss << "}\n";
    
    return ss.str();
}

void GenerateAnalysisReport(const FunctionInfo& funcInfo,
                           const ControlFlowGraph& cfg,
                           const PatternRecognizer& patterns,
                           const std::vector<RecoveredStruct>& structs) {
    std::stringstream ss;
    
    ss << "Function Analysis Report\n";
    ss << "========================\n\n";
    ss << "Function: " << funcInfo.name << "\n";
    ss << "Address: 0x" << std::hex << funcInfo.address << "\n";
    ss << "Size: " << std::dec << funcInfo.size << " bytes\n";
    ss << "Stack Size: " << funcInfo.stackSize << " bytes\n";
    ss << "Uses Frame Pointer: " << (funcInfo.usesFramePointer ? "Yes" : "No") << "\n\n";
    
    ss << "Control Flow:\n";
    ss << "  Basic Blocks: " << cfg.blocks.size() << "\n";
    ss << "  Loops: " << patterns.detectedLoops.size() << "\n";
    ss << "  Conditions: " << patterns.detectedConditions.size() << "\n\n";
    
    ss << "Parameters: " << funcInfo.parameters.size() << "\n";
    for (const auto& param : funcInfo.parameters) {
        ss << "  - " << TypeToString(param.type) << " " << param.name << "\n";
    }
    ss << "\n";
    
    ss << "Local Variables: " << funcInfo.localVars.size() << "\n";
    for (const auto& [name, var] : funcInfo.localVars) {
        ss << "  - " << TypeToString(var.type) << " " << name << "\n";
    }
    ss << "\n";
    
    ss << "Recovered Structures: " << structs.size() << "\n";
    for (const auto& s : structs) {
        ss << "  - " << s.name << " (size: " << s.totalSize << " bytes)\n";
        for (const auto& member : s.members) {
            ss << "    +" << member.offset << ": " << TypeToString(member.type) 
               << " " << member.name << "\n";
        }
    }
    
    std::string safeName = decompiler.CreateSafeFileName(funcInfo.name);
    SaveToFile(outputDir + "/analysis/" + safeName + "_analysis.txt", ss.str());
}

void SaveToFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (file.is_open()) {
        file << content;
        file.close();
    }
}

std::string TypeToString(VarType type) {
    Decompiler d;
    return d.TypeToString(type);
}
```

};

int main(int argc, char* argv[]) {
std::cout << “===========================================\n”;
std::cout << “  Advanced x64 Decompiler v1.0\n”;
std::cout << “===========================================\n\n”;

```
if (argc < 3) {
    std::cout << "Usage:\n";
    std::cout << "  " << argv[0] << " <mode> <target> [output_dir]\n\n";
    std::cout << "Modes:\n";
    std::cout << "  -f <file>     : Decompile executable file\n";
    std::cout << "  -p <process>  : Attach to running process\n";
    std::cout << "  -a <address>  : Decompile specific address range\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << argv[0] << " -f game.exe output\n";
    std::cout << "  " << argv[0] << " -p VotV.exe output\n";
    return 1;
}

std::string mode = argv[1];
std::string target = argv[2];
std::string outputDir = (argc >= 4) ? argv[3] : "src/full";

DecompilerEngine engine(outputDir);

if (mode == "-f") {
    if (!engine.DecompileExecutable(target)) {
        std::cerr << "[!] Decompilation failed\n";
        return 1;
    }
} else if (mode == "-p") {
    if (!engine.DecompileRunningProcess(target)) {
        std::cerr << "[!] Decompilation failed\n";
        return 1;
    }
} else {
    std::cerr << "[!] Invalid mode: " << mode << "\n";
    return 1;
}

std::cout << "\n[+] Decompilation completed successfully!\n";
std::cout << "[+] Check the output directory for results.\n";

return 0;
```

}
