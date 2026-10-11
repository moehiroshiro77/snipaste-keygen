cmake_minimum_required(VERSION 3.20)
project(snipaste_keygen C)

set(CMAKE_C_STANDARD 11)

# gnu inline asm is used, so clang is required (msvc x64 cannot)
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "build with clang: -DCMAKE_C_COMPILER=clang")
endif()

add_executable(snipaste_keygen
    main.c pe.c aes.c envelope.c stub.c selfactivate.c ui.c dialog.c)

target_include_directories(snipaste_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(snipaste_keygen PRIVATE -O2 -w)
