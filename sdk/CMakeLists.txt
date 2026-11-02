cmake_minimum_required(VERSION 3.12)
project(Kyron_MQTT C)
set(CMAKE_C_STANDARD 11)

# ── mosquitto ────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

# ── Paths ─────────────────────────────────────────────────────────────────────
# CMAKE_SOURCE_DIR is sdk/src when configured with: cmake -S sdk/src -B build
# Build the static libraries in kyber_sdk, dilithium_sdk and ascon_sdk first.
set(BASE ${CMAKE_SOURCE_DIR}/..)   # = sdk/

# ── Include paths ─────────────────────────────────────────────────────────────
#
# pqc_test_wrapper.h does:
#   #include "ascon/api.h"      → found at  include/ascon/api.h   (add include/)
#   #include "kyber/api.h"      → found at  src/kyber/api.h       (add src/)
#   #include "dilithium/api.h"  → found at  src/dilithium/api.h   (add src/)
#
# mqtt_pqc_client.h does:
#   #include "pqc_test_wrapper.h" → found at src/                 (add src/)
#   #include <mosquitto.h>        → found via MOSQUITTO_INCLUDE_DIRS
#
# kyber/api.h internally may include "randombytes.h"
#   → found at kyber_sdk/randombytes.h                            (add kyber_sdk/)
#
include_directories(
    ${CMAKE_SOURCE_DIR}             # src/  ← kyber/api.h, dilithium/api.h, common/
    ${BASE}/include                 # include/ ← ascon/api.h
    ${BASE}/kyber_sdk               # kyber_sdk/ ← randombytes.h used by kyber
    ${BASE}/ascon_sdk               # ascon_sdk/ ← randombytes.h used by ascon
    ${MOSQUITTO_INCLUDE_DIRS}
)

# ── Pre-compiled static libraries ────────────────────────────────────────────
set(KYBER_LIB     ${BASE}/kyber_sdk/libkyber.a)
set(ASCON_LIB     ${BASE}/ascon_sdk/libascon.a)
set(DILITHIUM_LIB ${BASE}/dilithium_sdk/libdilithium.a)

foreach(LIB ${KYBER_LIB} ${ASCON_LIB} ${DILITHIUM_LIB})
    if(NOT EXISTS ${LIB})
        message(FATAL_ERROR "Static library not found: ${LIB}")
    endif()
endforeach()

# ── randombytes ───────────────────────────────────────────────────────────────
# Use ascon_sdk/randombytes.c as the single source of truth
set(RANDOMBYTES_SRC ${BASE}/ascon_sdk/randombytes.c)

# ── Source files (we do NOT touch pqc_test_wrapper.*) ────────────────────────
set(WRAPPER_SRC
    ${CMAKE_SOURCE_DIR}/pqc_test_wrapper.c   # your file, untouched
    ${RANDOMBYTES_SRC}
)

set(MQTT_SRC
    ${CMAKE_SOURCE_DIR}/mqtt_pqc_client.c    # module 6 adapter
)

# ── Build macro ───────────────────────────────────────────────────────────────
macro(pqc_target NAME MAIN)
    add_executable(${NAME} ${MAIN} ${MQTT_SRC} ${WRAPPER_SRC})
    target_link_libraries(${NAME}
        ${KYBER_LIB}
        ${DILITHIUM_LIB}
        ${ASCON_LIB}
        ${MOSQUITTO_LIBRARIES}
        m
    )
    target_compile_options(${NAME} PRIVATE -Wall -Wno-unused-function)
endmacro()

pqc_target(mqtt_pqc_publisher  ${CMAKE_SOURCE_DIR}/mqtt_pqc_publisher.c)
pqc_target(mqtt_pqc_subscriber ${CMAKE_SOURCE_DIR}/mqtt_pqc_subscriber.c)

message(STATUS "")
message(STATUS "=== Kyron Module 6 — include paths ===")
message(STATUS "  src/        : ${CMAKE_SOURCE_DIR}")
message(STATUS "  include/    : ${BASE}/include")
message(STATUS "  kyber_sdk/  : ${BASE}/kyber_sdk")
message(STATUS "  ascon_sdk/  : ${BASE}/ascon_sdk")
message(STATUS "  libkyber    : ${KYBER_LIB}")
message(STATUS "  libascon    : ${ASCON_LIB}")
message(STATUS "  libdilithium: ${DILITHIUM_LIB}")
message(STATUS "")
