cmake_minimum_required(VERSION 3.20)

project(Elit-f LANGUAGES CXX)

if(NOT DEFINED DARTLIB)
        message(FATAL_ERROR "DARTLIB not defined. Usage: cmake -DDARTLIB=dartvm_xxx ..")
endif()
if(NOT ${DARTLIB} MATCHES "^dartvm")
        message(FATAL_ERROR "DARTLIB must start with 'dartvm'")
endif()

set(BINNAME "elitf_${DARTLIB}${NAME_SUFFIX}")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH LLVM_BIN_DIR)
endif()

find_package(${DARTLIB} REQUIRED PATHS "${CMAKE_SOURCE_DIR}/packages")

find_package(PkgConfig REQUIRED)
pkg_search_module(CAPSTONE REQUIRED capstone)
link_directories(${CAPSTONE_LIBDIR})
include_directories(AFTER ${CAPSTONE_INCLUDEDIR})

# libfmt is required because some targets (e.g. Termux/old clang) have no <format>
pkg_search_module(FMT QUIET fmt)
if(NOT FMT_FOUND)
        find_path(FMT_INCLUDE_DIR fmt/format.h)
        if(NOT FMT_INCLUDE_DIR)
                message(FATAL_ERROR "libfmt headers not found. Install libfmt-dev (or set FMT_INCLUDE_DIR)")
        endif()
        include_directories(SYSTEM ${FMT_INCLUDE_DIR})
else()
        link_directories(${FMT_LIBDIR})
        include_directories(SYSTEM ${FMT_INCLUDE_DIRS})
endif()

file(GLOB_RECURSE SRCS "src/*.cpp" "src/*.h")

add_executable(${BINNAME} ${SRCS})

target_precompile_headers(${BINNAME} PRIVATE "src/pch.h")

if(FMT_FOUND AND NOT FMT_HEADER_ONLY)
        target_link_libraries(${BINNAME} PRIVATE ${DARTLIB} capstone ${FMT_LIBRARIES})
else()
        target_link_libraries(${BINNAME} PRIVATE ${DARTLIB} capstone)
endif()

if(ANDROID)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -llog")
endif()

set(cc_opts
        -O3 -fno-rtti
        -fvisibility=hidden -fvisibility-inlines-hidden -fno-omit-frame-pointer
)
target_compile_options(${BINNAME} PRIVATE ${cc_opts})

set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/bin" CACHE PATH "" FORCE)

cmake_path(SET DEST_DIR NORMALIZE "${CMAKE_SOURCE_DIR}/bin")

set(FRIDA_TEMPLATE_DIR "${CMAKE_SOURCE_DIR}/scripts")
set(defines NDEBUG FRIDA_TEMPLATE_DIR="${FRIDA_TEMPLATE_DIR}")

if(OLD_MAP_SET_NAME)
        set(defines ${defines} OLD_MAP_SET_NAME)
        if(OLD_MAP_NO_IMMUTABLE)
                set(defines ${defines} OLD_MAP_NO_IMMUTABLE)
        endif()
endif()
if(NO_LAST_INTERNAL_ONLY_CID)
        set(defines ${defines} NO_LAST_INTERNAL_ONLY_CID)
endif()
if(HAS_SHARED_CLASS_TABLE)
        set(defines ${defines} HAS_SHARED_CLASS_TABLE)
endif()
if(HAS_TYPE_REF)
        set(defines ${defines} HAS_TYPE_REF)
endif()
if(HAS_RECORD_TYPE)
        set(defines ${defines} HAS_RECORD_TYPE)
endif()
if(NO_INIT_LATE_STATIC_FIELD)
        set(defines ${defines} NO_INIT_LATE_STATIC_FIELD)
endif()
if(NO_CODE_ANALYSIS)
        set(defines ${defines} NO_CODE_ANALYSIS)
endif()
if(NO_METHOD_EXTRACTOR_STUB)
        set(defines ${defines} NO_METHOD_EXTRACTOR_STUB)
endif()
if(UNIFORM_INTEGER_ACCESS)
        set(defines ${defines} UNIFORM_INTEGER_ACCESS)
endif()
# define for Dart VM older than 3.5 (single marking stack block; newer VM has old/new blocks and must stay undefined)
if(OLD_MARKING_STACK_BLOCK)
        set(defines ${defines} OLD_MARKING_STACK_BLOCK)
endif()
if(IDA_FCN)
        set(defines ${defines} IDA_FCN)
endif()

target_compile_definitions(${BINNAME} PRIVATE ${defines})

install(TARGETS ${BINNAME} RUNTIME DESTINATION ${DEST_DIR})
