cmake_minimum_required(VERSION 3.28)
project(device_key LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(NAPI_VERSION=10 NODE_ADDON_API_CPP_EXCEPTIONS_ALL)

# ── Node-API headers from npm packages (no cmake-js) ─────────────────────────
unset(NODE_EXECUTABLE CACHE)
find_program(NODE_EXECUTABLE bun node REQUIRED)

execute_process(
    COMMAND ${NODE_EXECUTABLE} -p "require('node-addon-api').include"
    OUTPUT_VARIABLE _naa_raw OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)
string(REPLACE "\"" "" NODE_ADDON_API_DIR "${_naa_raw}")

execute_process(
    COMMAND ${NODE_EXECUTABLE} -p "require('node-api-headers').include_dir"
    OUTPUT_VARIABLE NAPI_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)
if (NOT EXISTS "${NAPI_INCLUDE_DIR}/node_api.h")
    message(FATAL_ERROR "node_api.h not found: ${NAPI_INCLUDE_DIR}")
endif ()

# ── Sources: one backend per OS, all behind src/backend.hpp ──────────────────
set(SOURCES src/addon.cpp)
set(PLATFORM_LIBS "")

if (WIN32)
    if (NOT MSVC)
        message(FATAL_ERROR "Windows builds need MSVC")
    endif ()
    list(APPEND SOURCES src/backend_windows.cpp src/win_delay_load_hook.cpp)

    # N-API import library, resolved against the host process at first call (node.exe, bun.exe, electron.exe).
    execute_process(
        COMMAND ${NODE_EXECUTABLE} -p "require('node-api-headers').def_paths.node_api_def"
        OUTPUT_VARIABLE NAPI_DEF OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    set(NAPI_LIB "${CMAKE_BINARY_DIR}/napi.lib")

    # The target machine (x64 or ARM64) given explicitly: lib.exe assumes x64 without it.
    execute_process(
        COMMAND ${CMAKE_AR} /def:${NAPI_DEF} /out:${NAPI_LIB} /machine:${CMAKE_CXX_COMPILER_ARCHITECTURE_ID} ${CMAKE_STATIC_LINKER_FLAGS}
        RESULT_VARIABLE _rc
    )
    if (NOT _rc EQUAL 0)
        message(FATAL_ERROR "lib.exe failed to generate the N-API import library (rc=${_rc})")
    endif ()
    list(APPEND PLATFORM_LIBS "${NAPI_LIB}" ncrypt)
elseif (APPLE)
    list(APPEND SOURCES src/backend_macos.cpp)
    list(APPEND PLATFORM_LIBS "-framework Security" "-framework CoreFoundation")
elseif (UNIX)
    list(APPEND SOURCES src/backend_linux.cpp)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TSS2 REQUIRED IMPORTED_TARGET tss2-esys tss2-mu tss2-tctildr)
    list(APPEND PLATFORM_LIBS PkgConfig::TSS2)
else ()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif ()

add_library(${PROJECT_NAME} SHARED ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
# SYSTEM: our own warnings stay strict without failing on the Node-API headers' warnings.
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE "${NODE_ADDON_API_DIR}" "${NAPI_INCLUDE_DIR}")
target_link_libraries(${PROJECT_NAME} PRIVATE ${PLATFORM_LIBS})

# CI test builds only (hosted runners have no TPM): a software key store through the same calls, the software key
# storage provider on Windows, swtpm on Linux. Off by default, so a release binary always uses the TPM.
option(DEVICE_KEY_SOFTWARE_PROVIDER "Test build: a software key store (Windows software KSP, swtpm) instead of the TPM" OFF)
if (DEVICE_KEY_SOFTWARE_PROVIDER)
    target_compile_definitions(${PROJECT_NAME} PRIVATE DEVICE_KEY_SOFTWARE_PROVIDER)
endif ()

if (WIN32)
    target_link_options(${PROJECT_NAME} PRIVATE /DELAYLOAD:NODE.EXE)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
elseif (APPLE)
    # N-API symbols come from the host process.
    target_link_options(${PROJECT_NAME} PRIVATE -undefined dynamic_lookup)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror)
else ()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror)
endif ()

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION . LIBRARY DESTINATION .)
