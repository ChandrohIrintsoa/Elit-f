cmake_minimum_required (VERSION 3.20)

project(elitf)
if (NOT DEFINED DARTLIB)
        message(FATAL_ERROR "Please define DARTLIB to build the Elit-f project")
endif()
if (NOT ${DARTLIB} MATCHES "^dartvm")
        message(FATAL_ERROR "DARTLIB name should start with 'dartvm'")
endif()

set(BINNAME "elitf_${DARTLIB}${NAME_SUFFIX}")

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/bin" CACHE PATH "" FORCE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        if (APPLE)
                cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH LLVM_BIN_DIR)
                add_link_options(-L${LLVM_BIN_DIR}/../lib/c++ -dead_strip)
        endif()
endif()

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("#include <format>
#include <string>
int main() { return std::format(\"{}\", 42) == \"42\" ? 0 : 1; }" ELITF_HAS_STD_FORMAT)
if(NOT ELITF_HAS_STD_FORMAT)
        find_package(fmt 9 CONFIG REQUIRED)
endif()

find_package(${DARTLIB} REQUIRED PATHS "${PROJECT_SOURCE_DIR}/packages")
if (MSVC)
        add_library(capstone SHARED IMPORTED)
        set_target_properties(capstone PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/external/capstone/capstone.dll")
        set_target_properties(capstone PROPERTIES IMPORTED_IMPLIB "${PROJECT_SOURCE_DIR}/external/capstone/capstone_dll.lib")
        target_include_directories(capstone INTERFACE "${PROJECT_SOURCE_DIR}/external/capstone/include/capstone")
else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
                pkg_search_module(CAPSTONE QUIET capstone)
        endif()
        find_path(CAPSTONE_INCLUDE_DIR capstone.h
                HINTS ${CAPSTONE_INCLUDE_DIRS} ${CAPSTONE_INCLUDEDIR}
                PATH_SUFFIXES capstone include/capstone
                REQUIRED)
        find_library(CAPSTONE_LIBRARY NAMES capstone
                HINTS ${CAPSTONE_LIBRARY_DIRS} ${CAPSTONE_LIBDIR}
                REQUIRED)
        add_library(capstone UNKNOWN IMPORTED)
        set_target_properties(capstone PROPERTIES
                IMPORTED_LOCATION "${CAPSTONE_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIR}")

endif()

set(SRCDIR "src")
include(sourcelist.cmake)
list(TRANSFORM SRCS PREPEND "${SRCDIR}/")
add_executable(${BINNAME} ${SRCS})

target_link_libraries(${BINNAME} PRIVATE ${DARTLIB} capstone)
if(NOT ELITF_HAS_STD_FORMAT)
        target_link_libraries(${BINNAME} PRIVATE fmt::fmt)
        target_compile_definitions(${BINNAME} PRIVATE ELITF_USE_FMT)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Android")
        target_link_libraries(${BINNAME} PRIVATE log)
endif()

if (MSVC)
        target_link_libraries(${BINNAME} PRIVATE ntdll)
        string(REPLACE "/GR" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        if (CMAKE_GENERATOR MATCHES "Visual Studio")
                set(cc_opts /GR- /MD /D SEMIDBG)
                set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${BINNAME})
                set_target_properties(${BINNAME} PROPERTIES VS_DEBUGGER_COMMAND_ARGUMENTS "${DBG_CMD}")
        else()
                set(cc_opts /Oy /GR- /sdl- /Oi /GL /Gy /Zc:wchar_t /Zc:inline)
                target_link_options(${BINNAME} PRIVATE /LTCG /OPT:REF /OPT:ICF)
        endif()
else()
        set(cc_opts
                -O3 -fno-rtti
                -fvisibility=hidden -fvisibility-inlines-hidden -fno-omit-frame-pointer
        )
endif()

get_filename_component(FRIDA_TEMPLATE_DIR "${PROJECT_SOURCE_DIR}/scripts/" ABSOLUTE)
set(defines NDEBUG FRIDA_TEMPLATE_DIR="${FRIDA_TEMPLATE_DIR}")
if (OLD_MAP_SET_NAME)
        set(defines ${defines} OLD_MAP_SET_NAME)
        if (OLD_MAP_NO_IMMUTABLE)
                set(defines ${defines} OLD_MAP_NO_IMMUTABLE)
        endif()
endif()
if (NO_LAST_INTERNAL_ONLY_CID)
        set(defines ${defines} NO_LAST_INTERNAL_ONLY_CID)
endif()
if (HAS_SHARED_CLASS_TABLE)
        set(defines ${defines} HAS_SHARED_CLASS_TABLE)
endif()
if (HAS_TYPE_REF)
        set(defines ${defines} HAS_TYPE_REF)
endif()
if (HAS_RECORD_TYPE)
        set(defines ${defines} HAS_RECORD_TYPE)
endif()
if (NO_INIT_LATE_STATIC_FIELD)
        set(defines ${defines} NO_INIT_LATE_STATIC_FIELD)
endif()
if (NO_CODE_ANALYSIS)
        set(defines ${defines} NO_CODE_ANALYSIS)
endif()
if (NO_METHOD_EXTRACTOR_STUB)
        set(defines ${defines} NO_METHOD_EXTRACTOR_STUB)
endif()
if (UNIFORM_INTEGER_ACCESS)
        set(defines ${defines} UNIFORM_INTEGER_ACCESS)
endif()
if (OLD_MARKING_STACK_BLOCK)
        set(defines ${defines} OLD_MARKING_STACK_BLOCK)
endif()
if (BLUTTER_DART_SINGLE_SNAPSHOT)
        set(defines ${defines} BLUTTER_DART_SINGLE_SNAPSHOT)
endif()
if (IDA_FCN)
        set(defines ${defines} IDA_FCN)
endif()
target_compile_definitions(${BINNAME} PRIVATE ${defines})

target_compile_options(${BINNAME} PRIVATE ${cc_opts})

cmake_path(SET DST_DIR NORMALIZE "${PROJECT_SOURCE_DIR}/bin")
install (TARGETS ${BINNAME} RUNTIME DESTINATION ${DST_DIR})

