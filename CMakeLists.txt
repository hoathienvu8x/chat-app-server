cmake_minimum_required(VERSION 3.10)
project(chat_app_server C)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(chat_app_server hashmap.c main.c)

target_link_libraries(chat_app_server  ${OPENSSL_CRYPTO_LIBRARY} )