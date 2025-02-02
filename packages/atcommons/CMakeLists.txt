# Configurable options
option(ATCOMMONS_BUILD_TESTS "Build tests for atcommons" OFF)

# Set include directory and file sources
set(ATCOMMONS_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(
  ATCOMMONS_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_operation.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_status.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_namespace.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_params.c
  ${CMAKE_CURRENT_LIST_DIR}/src/enroll_command_builder.c
)

# Project setup
cmake_minimum_required(VERSION 3.24)
set(CMAKE_C_STANDARD 99)
cmake_policy(SET CMP0135 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/package_util.cmake)
if(ESP_PLATFORM)
  add_atsdk_espidf_component(
    PACKAGE_NAME atcommons
    PACKAGE_DESCRIPTION "Atsign technology common utilities and implementations"
    PACKAGE_VERSION 0.0.1
    INCLUDE_DIR ${ATCOMMONS_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCOMMONS_SOURCES}
  )
  return()
endif()

build_atsdk_package(
    PACKAGE_NAME atcommons
    PACKAGE_DESCRIPTION "Atsign technology common utilities and implementations"
    PACKAGE_VERSION 0.0.1
    PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIR ${ATCOMMONS_INCLUDE_DIR}
    PACKAGE_SOURCES ${ATCOMMONS_SOURCES}
    DEPS atlogger
    EXTERNAL_DEPS cjson
    INSTALL_TARGETS cjson atlogger
    BUILD_TESTS ${ATCOMMONS_BUILD_TESTS}
)

if(ATCOMMONS_BUILD_TESTS)
  enable_testing()
endif()
