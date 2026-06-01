cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()

project(corosh
    VERSION 0.1.0
    LANGUAGES CXX
)

if(NOT DEFINED CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD LESS 20)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(COROSH_BUILD_TESTS    "Build tests"    ON)
option(COROSH_BUILD_EXAMPLES "Build examples" ON)

find_package(Boost REQUIRED COMPONENTS capy corosio system)
find_package(libssh REQUIRED)

add_library(corosh
    src/acceptor.cpp
    src/corosh.cpp
    src/channel.cpp
    src/error.cpp
    src/message.cpp
    src/session.cpp
    src/sftp.cpp
)


target_compile_features(corosh PUBLIC cxx_std_20)

target_include_directories(corosh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(corosh
    PUBLIC
        Boost::system
        Boost::capy
        Boost::corosio
        ssh
)

if(COROSH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(COROSH_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
