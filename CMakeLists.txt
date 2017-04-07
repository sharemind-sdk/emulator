#
# Copyright (C) 2015 Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
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
FIND_PACKAGE(Boost 1.50 REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders REQUIRED)
FIND_PACKAGE(SharemindLibIController 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibfmodapiCxx 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibmodapiCxx 0.3.0 REQUIRED)
FIND_PACKAGE(SharemindLibProcessFacility 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibRandom REQUIRED)
FIND_PACKAGE(SharemindLibvmCxx 0.5.0 REQUIRED)

INCLUDE_DIRECTORIES(
    ${Boost_INCLUDE_DIRS}
    ${SharemindCxxHeaders_INCLUDE_DIRS}
    ${SharemindLibIController_INCLUDE_DIRS}
    ${SharemindLibfmodapiCxx_INCLUDE_DIRS}
    ${SharemindLibmodapiCxx_INCLUDE_DIRS}
    ${SharemindLibProcessFacility_INCLUDE_DIRS}
    ${SharemindLibRandom_INCLUDE_DIRS}
    ${SharemindLibvmCxx_INCLUDE_DIRS}
)
ADD_DEFINITIONS(
    ${SharemindCxxHeaders_DEFINITIONS}
    ${SharemindLibIController_DEFINITIONS}
    ${SharemindLibfmodapiCxx_DEFINITIONS}
    ${SharemindLibmodapiCxx_DEFINITIONS}
    ${SharemindLibProcessFacility_DEFINITIONS}
    ${SharemindLibRandom_DEFINITIONS}
    ${SharemindLibvmCxx_DEFINITIONS}
    "-DSHAREMIND_EMULATOR_VERSION=\"${SHAREMIND_EMULATOR_VERSION}\""
)
SET(Emulator_LIBRARIES
    ${SharemindLibfmodapiCxx_LIBRARIES}
    ${SharemindLibIController_LIBRARIES}
    ${SharemindLibmodapiCxx_LIBRARIES}
    ${SharemindLibProcessFacility_LIBRARIES}
    ${SharemindLibRandom_LIBRARIES}
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

ADD_EXECUTABLE(sharemind-emulator ${SHAREMIND_EMULATOR_SOURCES})
TARGET_LINK_LIBRARIES(sharemind-emulator ${Emulator_LIBRARIES})

INSTALL(TARGETS sharemind-emulator RUNTIME DESTINATION "bin")

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
    ADD_CUSTOM_COMMAND(TARGET sharemind-emulator POST_BUILD
            COMMAND env "LD_LIBRARY_PATH=${L}" "LC_ALL=POSIX" ${HELP2MAN}
                    "--include=${CMAKE_CURRENT_SOURCE_DIR}/doc/sharemind-emulator.h2m"
                    "--output=${CMAKE_CURRENT_BINARY_DIR}/sharemind-emulator.1"
                    "--no-discard-stderr"
                    "--no-info"
                    "--name=manual page for sharemind-emulator ${V}"
                    ${CMAKE_CURRENT_BINARY_DIR}/sharemind-emulator
            COMMENT "Generating manual page for sharemind-emulator")
    INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/sharemind-emulator.1"
            DESTINATION "share/man/man1")
ENDFUNCTION()

IF(HELP2MAN)
    GenerateManPage()
ENDIF()
