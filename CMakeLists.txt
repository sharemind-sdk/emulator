#
# This file is a part of the Sharemind framework.
# Copyright (C) Cybernetica AS
#
# All rights are reserved. Reproduction in whole or part is prohibited
# without the written consent of the copyright owner. The usage of this
# code is subject to the appropriate license agreement.
#

CMAKE_MINIMUM_REQUIRED(VERSION "2.8.12")
PROJECT(SHAREMIND_EMULATOR "CXX")
SET(SHAREMIND_EMULATOR_VERSION "0.1")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

ADD_COMPILE_OPTIONS(
  "-std=c++11" "-Wall" "-Wextra" "-O2"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-ggdb>"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-fno-omit-frame-pointer>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-DNDEBUG>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-fomit-frame-pointer>"
)

FIND_PROGRAM(HELP2MAN help2man)
FIND_PACKAGE(Boost 1.56 REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders REQUIRED)
FIND_PACKAGE(SharemindLibController REQUIRED)
FIND_PACKAGE(SharemindLibmodapiCxx 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibvmCxx 0.3.0 REQUIRED)

INCLUDE_DIRECTORIES(
    ${Boost_INCLUDE_DIRS}
    ${SharemindCxxHeaders_INCLUDE_DIRS}
    ${SharemindLibController_INCLUDE_DIRS}
    ${SharemindLibmodapiCxx_INCLUDE_DIRS}
    ${SharemindLibvmCxx_INCLUDE_DIRS}
)
ADD_DEFINITIONS(
    ${SharemindCxxHeaders_DEFINITIONS}
    ${SharemindLibController_DEFINITIONS}
    ${SharemindLibmodapiCxx_DEFINITIONS}
    ${SharemindLibvmCxx_DEFINITIONS}
    "-DSHAREMIND_EMULATOR_VERSION=\"${SHAREMIND_EMULATOR_VERSION}\""
)
SET(Emulator_LIBRARIES
    ${SharemindLibmodapiCxx_LIBRARIES}
    ${SharemindLibvmCxx_LIBRARIES}
)

################################################################################
# Emulator
################################################################################

FILE(GLOB_RECURSE SHAREMIND_EMULATOR_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE SHAREMIND_EMULATOR_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET("include_Emulator_headers_in_IDE"
                  SOURCES ${SHAREMIND_EMULATOR_HEADERS})
FILE(GLOB_RECURSE SHAREMIND_EMULATOR_DOCS
     "${CMAKE_CURRENT_SOURCE_DIR}/doc/*")
ADD_CUSTOM_TARGET("include_Emulator_docs_in_IDE"
                  SOURCES ${SHAREMIND_EMULATOR_DOCS})

ADD_EXECUTABLE(Emulator ${SHAREMIND_EMULATOR_SOURCES})
TARGET_LINK_LIBRARIES(Emulator ${Emulator_LIBRARIES})

INSTALL(TARGETS Emulator RUNTIME DESTINATION "bin")

FUNCTION(GetEmulatorLdLibraryPath out)
    SET(L "")
    FOREACH(l IN LISTS Emulator_LIBRARIES)
        STRING(STRIP "${l}" l)
        STRING(LENGTH "${l}" len)
        IF(${len} GREATER 2)
            STRING(SUBSTRING "${l}" 0 2 begin)
            IF("GenerateManPage_${begin}" STREQUAL "GenerateManPage_-L")
                STRING(SUBSTRING "${l}" 2 -1 l)
                IF(L)
                    SET(L "${L}:${l}")
                ELSE()
                    SET(L "${l}")
                ENDIF()
            ENDIF()
        ENDIF()
    ENDFOREACH()
    SET("${out}" "${L}" PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(GenerateManPage)
    SET(V "${SHAREMIND_EMULATOR_VERSION}")
    GetEmulatorLdLibraryPath(L)
    ADD_CUSTOM_COMMAND(TARGET Emulator POST_BUILD
            COMMAND env "LD_LIBRARY_PATH=${L}" "LC_ALL=POSIX" ${HELP2MAN}
                    "--include=${CMAKE_CURRENT_SOURCE_DIR}/doc/Emulator.h2m"
                    "--output=${CMAKE_CURRENT_BINARY_DIR}/Emulator.1"
                    "--no-discard-stderr"
                    "--no-info"
                    "--name=manual page for Sharemind Emulator ${V}"
                    ${CMAKE_CURRENT_BINARY_DIR}/Emulator
            COMMENT "Generating manual page for Emulator")
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/Emulator.1"
            DESTINATION "share/man/man1")
ENDFUNCTION()

IF(HELP2MAN)
    GenerateManPage()
ENDIF()
