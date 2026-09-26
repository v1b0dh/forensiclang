cmake_minimum_required(VERSION 3.20)
project(jocky_runtime C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Platform detection ────────────────────────────────────────────
if(WIN32)
    add_compile_definitions(_WIN32 UNICODE _UNICODE)
    set(PLATFORM_LIBS vssapi ole32)
else()
    set(PLATFORM_LIBS "")
endif()

# ── Find libpcap ─────────────────────────────────────────────────
find_library(PCAP_LIB NAMES pcap wpcap)
if(NOT PCAP_LIB)
    message(WARNING "libpcap not found — network module will not be built")
endif()

# ── Core sources ─────────────────────────────────────────────────
set(RUNTIME_SOURCES
    modules/artifacts/artifact.c
    modules/memory/memory_collect.c
    modules/disk/disk_collect.c
    modules/timeline.c
)

# Network module is optional (requires pcap)
if(PCAP_LIB)
    list(APPEND RUNTIME_SOURCES modules/network/network_capture.c)
    add_compile_definitions(JOCKY_HAVE_PCAP)
endif()

# ── Static library (linked against compiled JOCKY scripts) ───────
add_library(jocky_runtime STATIC ${RUNTIME_SOURCES})

target_include_directories(jocky_runtime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/artifacts
    ${CMAKE_CURRENT_SOURCE_DIR}/modules
)

target_link_libraries(jocky_runtime
    ${PLATFORM_LIBS}
    $<$<BOOL:${PCAP_LIB}>:${PCAP_LIB}>
)

# Compiler flags
if(MSVC)
    target_compile_options(jocky_runtime PRIVATE /W4 /WX-)
else()
    target_compile_options(jocky_runtime PRIVATE
        -Wall -Wextra -Wno-unused-parameter
        -fstack-protector-strong
    )
endif()

# ── Install ───────────────────────────────────────────────────────
install(TARGETS jocky_runtime ARCHIVE DESTINATION lib)
install(FILES
    modules/artifacts/artifact.h
    DESTINATION include/jocky
)

# ── Tests (ctest) ─────────────────────────────────────────────────
enable_testing()
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../tests/c)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../tests/c tests)
endif()
