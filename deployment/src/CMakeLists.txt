cmake_minimum_required(VERSION 3.12)
project(Kyron_TwoDevice C)
set(CMAKE_C_STANDARD 11)

# ── IMPL_BASE: path to implementation1/implementation/ ───────────────────
# Override at cmake time:
#   cmake .. -DIMPL_BASE=/your/path/to/implementation1/implementation
if(NOT DEFINED IMPL_BASE)
    # Default: assumes this CMakeLists.txt is at
    #   <repo>/two_device_deployment/src/CMakeLists.txt
    #   and implementation is at
    #   <repo>/implementation1/implementation/
    set(IMPL_BASE "${CMAKE_SOURCE_DIR}/../../implementation1/implementation")
endif()
message(STATUS "IMPL_BASE = ${IMPL_BASE}")

# ── Mosquitto ──────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# ── Include paths ──────────────────────────────────────────────────────────
#   pqc_test_wrapper.h → needs ascon/api.h (include/), kyber/api.h (src/), dilithium/api.h (src/)
#   mqtt_pqc_client.h  → needs pqc_test_wrapper.h (impl src/), mosquitto.h
include_directories(
    ${CMAKE_SOURCE_DIR}              # this src/ — mqtt_pqc_client.h
    ${IMPL_BASE}/src                 # kyber/api.h, dilithium/api.h, pqc_test_wrapper.h
    ${IMPL_BASE}/include             # ascon/api.h
    ${IMPL_BASE}/kyber_sdk           # randombytes.h (kyber)
    ${IMPL_BASE}/ascon_sdk           # randombytes.h (ascon)
    ${MOSQUITTO_INCLUDE_DIRS}
)

# ── Pre-compiled SDK static libraries ─────────────────────────────────────
set(KYBER_LIB     ${IMPL_BASE}/kyber_sdk/libkyber.a)
set(ASCON_LIB     ${IMPL_BASE}/ascon_sdk/libascon.a)
set(DILITHIUM_LIB ${IMPL_BASE}/dilithium_sdk/libdilithium.a)

foreach(LIB ${KYBER_LIB} ${ASCON_LIB} ${DILITHIUM_LIB})
    if(NOT EXISTS ${LIB})
        message(FATAL_ERROR "SDK library not found: ${LIB}\n"
                "Build the SDKs first in ${IMPL_BASE}/*_sdk/  then re-run cmake.")
    endif()
endforeach()

# ── Common source shared by both binaries ─────────────────────────────────
set(RANDOMBYTES_SRC ${IMPL_BASE}/ascon_sdk/randombytes.c)

set(SHARED_SRC
    ${CMAKE_SOURCE_DIR}/mqtt_pqc_client.c
    ${IMPL_BASE}/src/pqc_test_wrapper.c
    ${RANDOMBYTES_SRC}
)

# ── Link helper ───────────────────────────────────────────────────────────
macro(pqc_target NAME MAIN)
    add_executable(${NAME} ${MAIN} ${SHARED_SRC})
    target_link_libraries(${NAME}
        ${KYBER_LIB}
        ${DILITHIUM_LIB}
        ${ASCON_LIB}
        ${MOSQUITTO_LIBRARIES}
        sqlite3
        m
    )
    target_compile_options(${NAME} PRIVATE -Wall -Wno-unused-function)
endmacro()

# ── Targets ───────────────────────────────────────────────────────────────
pqc_target(mqtt_pqc_publisher  ${CMAKE_SOURCE_DIR}/mqtt_pqc_publisher.c)
pqc_target(mqtt_pqc_subscriber ${CMAKE_SOURCE_DIR}/mqtt_pqc_subscriber.c)

message(STATUS "")
message(STATUS "=== Kyron Two-Device Build ===")
message(STATUS "  Targets  : mqtt_pqc_publisher, mqtt_pqc_subscriber")
message(STATUS "  IMPL_BASE: ${IMPL_BASE}")
message(STATUS "  kyber    : ${KYBER_LIB}")
message(STATUS "  ascon    : ${ASCON_LIB}")
message(STATUS "  dilithium: ${DILITHIUM_LIB}")
message(STATUS "")
