cmake_minimum_required(VERSION 3.29)
project(Three-Round-Multiparty-ECDSA LANGUAGES CXX)

option(TRECDSA_BUILD_TESTS "Build tests" ON)
option(TRECDSA_WARNINGS_AS_ERRORS "Treat warnings as errors for project targets" OFF)
option(TRECDSA_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(include/bicycl EXCLUDE_FROM_ALL)

find_library(GMP_LIBRARY gmp REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(trecdsa_project_options INTERFACE)
target_compile_features(trecdsa_project_options INTERFACE cxx_std_14)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(trecdsa_project_options INTERFACE -Wall -Wextra -Wpedantic)
    if(TRECDSA_WARNINGS_AS_ERRORS)
        target_compile_options(trecdsa_project_options INTERFACE -Werror)
    endif()
    target_compile_options(trecdsa_project_options INTERFACE
        $<$<CONFIG:Debug>:-O0 -g3 -fno-omit-frame-pointer>
        $<$<CONFIG:Release>:-O3 -DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
    )
    if(TRECDSA_ENABLE_SANITIZERS)
        target_compile_options(trecdsa_project_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(trecdsa_project_options INTERFACE -fsanitize=address,undefined)
    endif()
elseif(MSVC)
    target_compile_options(trecdsa_project_options INTERFACE /W4 /permissive- /EHsc)
    if(TRECDSA_WARNINGS_AS_ERRORS)
        target_compile_options(trecdsa_project_options INTERFACE /WX)
    endif()
endif()

add_library(trecdsa_core
    src/Party.cpp
    src/Protocol.cpp
    src/Utils.cpp
)

target_include_directories(trecdsa_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(trecdsa_core
    PUBLIC
        trecdsa_project_options
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)

add_executable(trecdsa_cli apps/cli/main.cpp)
target_link_libraries(trecdsa_cli PRIVATE trecdsa_core)
set_target_properties(trecdsa_cli PROPERTIES OUTPUT_NAME Three-Round-Multiparty-ECDSA)

if(TRECDSA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
