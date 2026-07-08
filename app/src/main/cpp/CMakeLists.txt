cmake_minimum_required(VERSION 3.22.1)

project("native-lib")

# Configure Capstone before including it
include(FetchContent)

set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "Build static library" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build shared library" FORCE)
set(CAPSTONE_BUILD_DIET OFF CACHE BOOL "Build diet library" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Disable default architectures" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "Enable ARM support" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "Enable ARM64 support" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "Enable x86 support" FORCE)

FetchContent_Declare(
    capstone
    URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.1.tar.gz
)

FetchContent_MakeAvailable(capstone)

add_library(
    native-lib
    SHARED
    native-lib.cpp
)

find_library(
    log-lib
    log
)

target_include_directories(
    native-lib
    PRIVATE
    ${capstone_SOURCE_DIR}/include
)

target_link_libraries(
    native-lib
    capstone
    ${log-lib}
)
