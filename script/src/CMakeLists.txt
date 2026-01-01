cmake_minimum_required(VERSION 3.15)
project(AdvancedDecompiler CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
add_compile_options(/W4 /O2 /MT)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
add_compile_options(-Wall -Wextra -O3 -march=native)
endif()

find_package(Threads REQUIRED)

include(FetchContent)

FetchContent_Declare(
zydis
GIT_REPOSITORY https://github.com/zyantific/zydis.git
GIT_TAG v4.1.0
)
FetchContent_MakeAvailable(zydis)

set(DECOMPILER_SOURCES
Main.cpp
Decompiler.cpp
DataFlowAnalysis.cpp
PatternRecognition.cpp
AdvancedAnalysis.cpp
Optimizations.cpp
)

set(DECOMPILER_HEADERS
Decompiler.h
DataFlowAnalysis.h
PatternRecognition.h
AdvancedAnalysis.h
Optimizations.h
)

add_executable(Decompiler ${DECOMPILER_SOURCES} ${DECOMPILER_HEADERS})

target_link_libraries(Decompiler
PRIVATE
Zydis
Threads::Threads
)

if(WIN32)
target_link_libraries(Decompiler PRIVATE
psapi
dbghelp
)
endif()

target_include_directories(Decompiler PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(Decompiler PROPERTIES
RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

install(TARGETS Decompiler RUNTIME DESTINATION bin)
