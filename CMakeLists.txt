cmake_minimum_required(VERSION 3.20)

project(opgave8_cryptography LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
    pkg_check_modules(MOSQUITTO QUIET libmosquitto)
endif()

if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY sodium libsodium)
    if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
        set(SODIUM_FOUND TRUE)
        set(SODIUM_INCLUDE_DIRS "${SODIUM_INCLUDE_DIR}")
        set(SODIUM_LIBRARIES "${SODIUM_LIBRARY}")
    endif()
endif()

if(NOT SODIUM_FOUND)
    message(FATAL_ERROR "libsodium was not found. Install libsodium and make sure sodium.h and the sodium library are on the compiler path.")
endif()

if(NOT MOSQUITTO_FOUND)
    find_path(MOSQUITTO_INCLUDE_DIR mosquitto.h)
    find_library(MOSQUITTO_LIBRARY mosquitto libmosquitto)
    if(MOSQUITTO_INCLUDE_DIR AND MOSQUITTO_LIBRARY)
        set(MOSQUITTO_FOUND TRUE)
        set(MOSQUITTO_INCLUDE_DIRS "${MOSQUITTO_INCLUDE_DIR}")
        set(MOSQUITTO_LIBRARIES "${MOSQUITTO_LIBRARY}")
    endif()
endif()

if(NOT MOSQUITTO_FOUND)
    message(FATAL_ERROR "libmosquitto was not found. Install mosquitto/libmosquitto before building the MQTT examples.")
endif()

add_library(crypto_common
    src/crypto_utils.cpp
)
target_include_directories(crypto_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(crypto_common PUBLIC ${SODIUM_LIBRARIES})
target_compile_options(crypto_common PRIVATE -Wall -Wextra -pedantic)

function(add_crypto_demo target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE crypto_common)
    target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
endfunction()

add_crypto_demo(password_server src/password_server.cpp)
add_crypto_demo(password_client src/password_client.cpp)
add_crypto_demo(chap_demo src/chap_demo.cpp)
add_crypto_demo(encrypt_mac src/encrypt_mac.cpp)

function(add_mqtt_demo target source)
    add_executable(${target} ${source})
    target_include_directories(${target} PRIVATE ${MOSQUITTO_INCLUDE_DIRS})
    target_link_libraries(${target} PRIVATE crypto_common ${MOSQUITTO_LIBRARIES})
    target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
endfunction()

add_mqtt_demo(mqtt_hash_server src/mqtt_hash_server.cpp)
add_mqtt_demo(mqtt_hash_client src/mqtt_hash_client.cpp)
add_mqtt_demo(mqtt_chap_server src/mqtt_chap_server.cpp)
add_mqtt_demo(mqtt_chap_client src/mqtt_chap_client.cpp)
