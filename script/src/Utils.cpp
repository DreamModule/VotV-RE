#include “Utils.h”
#include <algorithm>
#include <chrono>
#include <map>

bool MemoryReader::ReadMemory(HANDLE hProcess, uintptr_t address, void* buffer, size_t size) {
SIZE_T bytesRead;
return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) &&
bytesRead == size;
}

bool MemoryReader::WriteMemory(HANDLE hProcess, uintptr_t address, const void* buffer, size_t size) {
SIZE_T bytesWritten;
return WriteProcessMemory(hProcess, (LPVOID)address, buffer, size, &bytesWritten) &&
bytesWritten == size;
}

bool MemoryReader::IsMemoryReadable(uintptr_t address, size_t size) {
__try {
volatile uint8_t test = *(uint8_t*)address;
return true;
}
__except (EXCEPTION_EXECUTE_HANDLER) {
return false;
}
}

bool MemoryReader::IsMemoryExecutable(uintptr_t address) {
MEMORY_BASIC_INFORMATION mbi;
if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
return (mbi.Protect & PAGE_EXECUTE) ||
(mbi.Protect & PAGE_EXECUTE_READ) ||
(mbi.Protect & PAGE_EXECUTE_READWRITE);
}
return false;
}

std::vector<uint8_t> MemoryReader::ReadBytes(uintptr_t address, size_t count) {
std::vector<uint8_t> bytes(count);
__try {
memcpy(bytes.data(), (void*)address, count);
}
__except (EXCEPTION_EXECUTE_HANDLER) {
bytes.clear();
}
return bytes;
}

DWORD ProcessHelper::FindProcessByName(const std::string& processName) {
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

```
PROCESSENTRY32 pe32;
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
```

}

HANDLE ProcessHelper::OpenProcessHandle(DWORD processId) {
return OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
}

uintptr_t ProcessHelper::GetModuleBase(DWORD processId, const std::string& moduleName) {
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

```
MODULEENTRY32 moduleEntry;
moduleEntry.dwSize = sizeof(MODULEENTRY32);

if (Module32First(hSnapshot, &moduleEntry)) {
    do {
        if (_stricmp(moduleEntry.szModule, moduleName.c_str()) == 0) {
            CloseHandle(hSnapshot);
            return (uintptr_t)moduleEntry.modBaseAddr;
        }
    } while (Module32Next(hSnapshot, &moduleEntry));
}

CloseHandle(hSnapshot);
return 0;
```

}

size_t ProcessHelper::GetModuleSize(DWORD processId, const std::string& moduleName) {
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

```
MODULEENTRY32 moduleEntry;
moduleEntry.dwSize = sizeof(MODULEENTRY32);

if (Module32First(hSnapshot, &moduleEntry)) {
    do {
        if (_stricmp(moduleEntry.szModule, moduleName.c_str()) == 0) {
            CloseHandle(hSnapshot);
            return moduleEntry.modBaseSize;
        }
    } while (Module32Next(hSnapshot, &moduleEntry));
}

CloseHandle(hSnapshot);
return 0;
```

}

std::vector<MODULEENTRY32> ProcessHelper::EnumerateModules(DWORD processId) {
std::vector<MODULEENTRY32> modules;

```
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
if (hSnapshot == INVALID_HANDLE_VALUE) return modules;

MODULEENTRY32 moduleEntry;
moduleEntry.dwSize = sizeof(MODULEENTRY32);

if (Module32First(hSnapshot, &moduleEntry)) {
    do {
        modules.push_back(moduleEntry);
    } while (Module32Next(hSnapshot, &moduleEntry));
}

CloseHandle(hSnapshot);
return modules;
```

}

bool ProcessHelper::IsProcess64Bit(HANDLE hProcess) {
BOOL isWow64 = FALSE;
IsWow64Process(hProcess, &isWow64);

#ifdef _WIN64
return !isWow64;
#else
return false;
#endif
}

uintptr_t PatternScanner::FindPattern(uintptr_t start, size_t size,
const std::string& pattern, const std::string& mask) {
std::vector<uint8_t> patternBytes;

```
for (size_t i = 0; i < pattern.length(); i += 2) {
    std::string byteStr = pattern.substr(i, 2);
    if (byteStr != "??") {
        patternBytes.push_back((uint8_t)strtol(byteStr.c_str(), nullptr, 16));
    } else {
        patternBytes.push_back(0);
    }
}

__try {
    for (uintptr_t addr = start; addr < start + size - patternBytes.size(); addr++) {
        if (CompareBytes((uint8_t*)addr, patternBytes.data(), mask.c_str(), patternBytes.size())) {
            return addr;
        }
    }
}
__except (EXCEPTION_EXECUTE_HANDLER) {
}

return 0;
```

}

bool PatternScanner::CompareBytes(const uint8_t* data, const uint8_t* pattern,
const char* mask, size_t length) {
for (size_t i = 0; i < length; i++) {
if (mask[i] == ‘x’ && data[i] != pattern[i]) {
return false;
}
}
return true;
}

std::vector<uintptr_t> PatternScanner::FindAllPatterns(uintptr_t start, size_t size,
const std::string& pattern) {
std::vector<uintptr_t> results;

```
__try {
    for (uintptr_t addr = start; addr < start + size; addr++) {
        bool match = true;
        for (size_t i = 0; i < pattern.length(); i++) {
            if (((uint8_t*)addr)[i] != pattern[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            results.push_back(addr);
            addr += pattern.length();
        }
    }
}
__except (EXCEPTION_EXECUTE_HANDLER) {
}

return results;
```

}

bool DisassemblyUtils::IsFunctionPrologue(const uint8_t* bytes) {
return (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x5C && bytes[3] == 0x24) ||
(bytes[0] == 0x40 && bytes[1] == 0x53) ||
(bytes[0] == 0x48 && (bytes[1] == 0x83 || bytes[1] == 0x81) && bytes[2] == 0xEC) ||
(bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5);
}

bool DisassemblyUtils::IsFunctionEpilogue(const uint8_t* bytes) {
return (bytes[0] == 0xC3) ||
(bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xC4 && bytes[4] == 0xC3) ||
(bytes[0] == 0x5D && bytes[1] == 0xC3);
}

bool FileUtils::FileExists(const std::string& path) {
DWORD attrib = GetFileAttributesA(path.c_str());
return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool FileUtils::CreateDirectory(const std::string& path) {
return CreateDirectoryA(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool FileUtils::WriteFile(const std::string& path, const std::string& content) {
std::ofstream file(path);
if (!file.is_open()) return false;
file << content;
file.close();
return true;
}

std::string FileUtils::ReadFile(const std::string& path) {
std::ifstream file(path);
if (!file.is_open()) return “”;

```
std::stringstream buffer;
buffer << file.rdbuf();
return buffer.str();
```

}

std::string FileUtils::GetFileName(const std::string& path) {
size_t pos = path.find_last_of(”/\”);
return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

std::string StringUtils::ToHex(uintptr_t value, int width) {
std::stringstream ss;
ss << “0x” << std::hex << std::setfill(‘0’) << std::setw(width) << value;
return ss.str();
}

std::string StringUtils::ToHex(const std::vector<uint8_t>& data) {
std::stringstream ss;
for (auto byte : data) {
ss << std::hex << std::setfill(‘0’) << std::setw(2) << (int)byte << “ “;
}
return ss.str();
}

std::string StringUtils::Trim(const std::string& str) {
size_t first = str.find_first_not_of(” \t\n\r”);
if (first == std::string::npos) return “”;
size_t last = str.find_last_not_of(” \t\n\r”);
return str.substr(first, last - first + 1);
}

std::vector<std::string> StringUtils::Split(const std::string& str, char delimiter) {
std::vector<std::string> parts;
std::stringstream ss(str);
std::string part;

```
while (std::getline(ss, part, delimiter)) {
    parts.push_back(part);
}

return parts;
```

}

std::string StringUtils::Join(const std::vector<std::string>& parts, const std::string& separator) {
std::stringstream ss;
for (size_t i = 0; i < parts.size(); i++) {
ss << parts[i];
if (i < parts.size() - 1) ss << separator;
}
return ss.str();
}

bool StringUtils::StartsWith(const std::string& str, const std::string& prefix) {
return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

bool StringUtils::EndsWith(const std::string& str, const std::string& suffix) {
return str.size() >= suffix.size() &&
str.substr(str.size() - suffix.size()) == suffix;
}

std::string HexDumper::DumpHex(const uint8_t* data, size_t length, uintptr_t baseAddress) {
std::stringstream ss;

```
for (size_t i = 0; i < length; i += 16) {
    ss << StringUtils::ToHex(baseAddress + i, 16) << ": ";
    
    for (size_t j = 0; j < 16 && i + j < length; j++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i + j] << " ";
    }
    
    ss << "  ";
    
    for (size_t j = 0; j < 16 && i + j < length; j++) {
        uint8_t c = data[i + j];
        ss << (char)(isprint(c) ? c : '.');
    }
    
    ss << "\n";
}

return ss.str();
```

}

Logger::Level Logger::minLevel = Logger::Level::INFO;
std::string Logger::logFile = “”;
std::ofstream Logger::logStream;

void Logger::Log(Level level, const std::string& message) {
if (level < minLevel) return;

```
std::stringstream ss;
ss << "[" << GetTimestamp() << "] "
   << "[" << LevelToString(level) << "] "
   << message;

std::string logLine = ss.str();
std::cout << logLine << std::endl;

if (logStream.is_open()) {
    logStream << logLine << std::endl;
    logStream.flush();
}
```

}

void Logger::Debug(const std::string& message) { Log(Level::DEBUG, message); }
void Logger::Info(const std::string& message) { Log(Level::INFO, message); }
void Logger::Warning(const std::string& message) { Log(Level::WARNING, message); }
void Logger::Error(const std::string& message) { Log(Level::ERROR, message); }

void Logger::SetLogFile(const std::string& path) {
logFile = path;
logStream.open(path, std::ios::app);
}

void Logger::SetLogLevel(Level level) {
minLevel = level;
}

std::string Logger::LevelToString(Level level) {
switch (level) {
case Level::DEBUG: return “DEBUG”;
case Level::INFO: return “INFO”;
case Level::WARNING: return “WARN”;
case Level::ERROR: return “ERROR”;
default: return “UNKNOWN”;
}
}

std::string Logger::GetTimestamp() {
auto now = std::chrono::system_clock::now();
auto time = std::chrono::system_clock::to_time_t(now);
std::stringstream ss;
ss << std::put_time(std::localtime(&time), “%Y-%m-%d %H:%M:%S”);
return ss.str();
}

ProgressBar::ProgressBar(size_t total, const std::string& description)
: total(total), current(0), description(description) {
Draw();
}

void ProgressBar::Update(size_t current) {
this->current = current;
Draw();
}

void ProgressBar::Increment() {
current++;
Draw();
}

void ProgressBar::SetDescription(const std::string& desc) {
description = desc;
Draw();
}

void ProgressBar::Complete() {
current = total;
Draw();
std::cout << std::endl;
}

void ProgressBar::Draw() {
int barWidth = 50;
float progress = (float)current / total;
int pos = (int)(barWidth * progress);

```
std::cout << "\r[";
for (int i = 0; i < barWidth; i++) {
    if (i < pos) std::cout << "=";
    else if (i == pos) std::cout << ">";
    else std::cout << " ";
}
std::cout << "] " << int(progress * 100.0) << "% " << description;
std::cout.flush();
```

}

std::map<std::string, Benchmark::Timer> Benchmark::timers;

void Benchmark::Start(const std::string& name) {
timers[name].start = std::chrono::high_resolution_clock::now();
timers[name].running = true;
}

void Benchmark::End(const std::string& name) {
auto it = timers.find(name);
if (it != timers.end() && it->second.running) {
it->second.end = std::chrono::high_resolution_clock::now();
it->second.running = false;
}
}

void Benchmark::PrintResults() {
std::cout << “\n=== Benchmark Results ===\n”;
for (const auto& [name, timer] : timers) {
if (!timer.running) {
auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
timer.end - timer.start).count();
std::cout << name << “: “ << duration << “ ms\n”;
}
}
}
