#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

class MemoryReader {
public:
static bool ReadMemory(HANDLE hProcess, uintptr_t address, void* buffer, size_t size);
static bool WriteMemory(HANDLE hProcess, uintptr_t address, const void* buffer, size_t size);
static bool IsMemoryReadable(uintptr_t address, size_t size);
static bool IsMemoryExecutable(uintptr_t address);

```
static std::vector<uint8_t> ReadBytes(uintptr_t address, size_t count);

template<typename T>
static T Read(uintptr_t address) {
    T value = {};
    __try {
        value = *(T*)address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return value;
}
```

};

class ProcessHelper {
public:
static DWORD FindProcessByName(const std::string& processName);
static HANDLE OpenProcessHandle(DWORD processId);
static uintptr_t GetModuleBase(DWORD processId, const std::string& moduleName);
static size_t GetModuleSize(DWORD processId, const std::string& moduleName);

```
static std::vector<MODULEENTRY32> EnumerateModules(DWORD processId);
static bool IsProcess64Bit(HANDLE hProcess);
```

};

class PatternScanner {
public:
static uintptr_t FindPattern(uintptr_t start, size_t size,
const std::string& pattern, const std::string& mask);

```
static uintptr_t FindPattern(uintptr_t start, size_t size,
                             const std::vector<uint8_t>& pattern);

static std::vector<uintptr_t> FindAllPatterns(uintptr_t start, size_t size,
                                              const std::string& pattern);

static uintptr_t ScanForString(uintptr_t start, size_t size, const std::string& str);
```

private:
static bool CompareBytes(const uint8_t* data, const uint8_t* pattern,
const char* mask, size_t length);
};

class DisassemblyUtils {
public:
static bool IsValidInstruction(const uint8_t* bytes, size_t length);
static size_t GetInstructionLength(const uint8_t* bytes);
static bool IsFunctionPrologue(const uint8_t* bytes);
static bool IsFunctionEpilogue(const uint8_t* bytes);

```
static std::string GetMnemonicName(ZydisMnemonic mnemonic);
static std::string GetRegisterName(ZydisRegister reg);
```

};

class FileUtils {
public:
static bool FileExists(const std::string& path);
static bool CreateDirectory(const std::string& path);
static bool WriteFile(const std::string& path, const std::string& content);
static std::string ReadFile(const std::string& path);

```
static std::vector<std::string> ListFiles(const std::string& directory, 
                                          const std::string& extension);

static std::string GetFileName(const std::string& path);
static std::string GetFileExtension(const std::string& path);
static std::string GetDirectory(const std::string& path);
```

};

class StringUtils {
public:
static std::string ToHex(uintptr_t value, int width = 16);
static std::string ToHex(const std::vector<uint8_t>& data);

```
static std::string Trim(const std::string& str);
static std::vector<std::string> Split(const std::string& str, char delimiter);
static std::string Join(const std::vector<std::string>& parts, const std::string& separator);

static std::string Replace(const std::string& str, const std::string& from, 
                          const std::string& to);

static bool StartsWith(const std::string& str, const std::string& prefix);
static bool EndsWith(const std::string& str, const std::string& suffix);

static std::string ToLower(const std::string& str);
static std::string ToUpper(const std::string& str);
```

};

class HexDumper {
public:
static std::string DumpHex(const uint8_t* data, size_t length, uintptr_t baseAddress = 0);
static std::string DumpInstructions(const std::vector<ZydisDecodedInstruction>& instructions,
uintptr_t baseAddress);
};

class Logger {
public:
enum class Level {
DEBUG,
INFO,
WARNING,
ERROR
};

```
static void Log(Level level, const std::string& message);
static void Debug(const std::string& message);
static void Info(const std::string& message);
static void Warning(const std::string& message);
static void Error(const std::string& message);

static void SetLogFile(const std::string& path);
static void SetLogLevel(Level level);
```

private:
static Level minLevel;
static std::string logFile;
static std::ofstream logStream;

```
static std::string LevelToString(Level level);
static std::string GetTimestamp();
```

};

class ProgressBar {
public:
ProgressBar(size_t total, const std::string& description = “”);

```
void Update(size_t current);
void Increment();
void SetDescription(const std::string& desc);
void Complete();
```

private:
size_t total;
size_t current;
std::string description;

```
void Draw();
```

};

class Benchmark {
public:
static void Start(const std::string& name);
static void End(const std::string& name);
static void PrintResults();

private:
struct Timer {
std::chrono::high_resolution_clock::time_point start;
std::chrono::high_resolution_clock::time_point end;
bool running;
};

```
static std::map<std::string, Timer> timers;
```

};
