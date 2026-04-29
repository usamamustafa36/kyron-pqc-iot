cmake_minimum_required(VERSION 3.12)
project(Kyron_MQTT C)
set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)

set(BASE ${CMAKE_SOURCE_DIR}/..)

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${BASE}/include
    ${BASE}/kyber_sdk
    ${BASE}/dilithium_sdk
    ${BASE}/ascon_sdk
    ${BASE}/ascon_sdk/ascon
    ${MOSQUITTO_INCLUDE_DIRS}
)

set(KYBER_LIB     ${BASE}/kyber_sdk/libkyber.a)
set(ASCON_LIB     ${BASE}/ascon_sdk/libascon.a)
set(DILITHIUM_LIB ${BASE}/dilithium_sdk/libdilithium.a)

foreach(LIB ${KYBER_LIB} ${ASCON_LIB} ${DILITHIUM_LIB})
    if(NOT EXISTS ${LIB})
        message(FATAL_ERROR "Missing library: ${LIB}")
    endif()
endforeach()

set(RANDOMBYTES_SRC ${BASE}/ascon_sdk/randombytes.c)

set(WRAPPER_SRC
    ${CMAKE_SOURCE_DIR}/pqc_test_wrapper.c
    ${RANDOMBYTES_SRC}
)

set(MQTT_SRC
    ${CMAKE_SOURCE_DIR}/mqtt_pqc_client.c
)

macro(pqc_target NAME MAIN)
    add_executable(${NAME} ${MAIN} ${MQTT_SRC} ${WRAPPER_SRC})
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

pqc_target(mqtt_pqc_publisher  ${CMAKE_SOURCE_DIR}/mqtt_pqc_publisher.c)
pqc_target(mqtt_pqc_subscriber ${CMAKE_SOURCE_DIR}/mqtt_pqc_subscriber.c)

message(STATUS "=== Kyron Module 6 — configured ===")
