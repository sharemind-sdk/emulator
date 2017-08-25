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

CMAKE_MINIMUM_REQUIRED(VERSION "3.0.0")
PROJECT(SHAREMIND_EMULATOR "CXX")

SET(CPACK_PACKAGE_VERSION_MAJOR "1")
SET(CPACK_PACKAGE_VERSION_MINOR "0")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(SHAREMIND_EMULATOR_VERSION
    "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PROGRAM(HELP2MAN help2man)
FIND_PACKAGE(Boost 1.50 COMPONENTS system filesystem REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders REQUIRED)
FIND_PACKAGE(SharemindLibConfiguration REQUIRED)
FIND_PACKAGE(SharemindLibIController 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibFModapiCxx 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibModapiCxx 0.3.0 REQUIRED)
FIND_PACKAGE(SharemindLibProcessFacility 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibRandom REQUIRED)
FIND_PACKAGE(SharemindLibVmCxx 0.5.0 REQUIRED)
FIND_PROGRAM(objcopy NAMES "objcopy" "${CMAKE_LIBRARY_ARCHITECTURE}-objcopy")
IF(NOT objcopy)
    MESSAGE(FATAL_ERROR "Required program not found: objcopy")
ELSE()
    MESSAGE(STATUS "Found objcopy: ${objcopy}")
ENDIF()

ADD_COMPILE_OPTIONS(
  "-std=c++11" "-Wall" "-Wextra" "-O2"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-ggdb>"
  "$<$<NOT:$<STREQUAL:$<CONFIGURATION>,Release>>:-fno-omit-frame-pointer>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-DNDEBUG>"
  "$<$<STREQUAL:$<CONFIGURATION>,Release>:-fomit-frame-pointer>"
)
INCLUDE(CheckCXXCompilerFlag)
FUNCTION(CHECK_ADD_COMPILER_FLAG flag)
    STRING(SUBSTRING "${flag}" 1 -1 FlagName)
    CHECK_CXX_COMPILER_FLAG("${flag}" CXX_COMPILER_HAS_${FlagName}_FLAG)
    IF(CXX_COMPILER_HAS_${FlagName}_FLAG)
        ADD_COMPILE_OPTIONS("${flag}")
    ENDIF()
ENDFUNCTION()
CHECK_ADD_COMPILER_FLAG("-Wzero-as-null-pointer-constant")
CHECK_ADD_COMPILER_FLAG("-Wsuggest-override")
CHECK_ADD_COMPILER_FLAG("-Wno-noexcept-type")

INCLUDE_DIRECTORIES(
    ${Boost_INCLUDE_DIRS}
    ${SharemindCxxHeaders_INCLUDE_DIRS}
    ${SharemindLibConfiguration_INCLUDE_DIRS}
    ${SharemindLibIController_INCLUDE_DIRS}
    ${SharemindLibFModapiCxx_INCLUDE_DIRS}
    ${SharemindLibModapiCxx_INCLUDE_DIRS}
    ${SharemindLibProcessFacility_INCLUDE_DIRS}
    ${SharemindLibRandom_INCLUDE_DIRS}
    ${SharemindLibVmCxx_INCLUDE_DIRS}
)
ADD_DEFINITIONS(
    ${SharemindCxxHeaders_DEFINITIONS}
    ${SharemindLibConfiguration_DEFINITIONS}
    ${SharemindLibIController_DEFINITIONS}
    ${SharemindLibFModapiCxx_DEFINITIONS}
    ${SharemindLibModapiCxx_DEFINITIONS}
    ${SharemindLibProcessFacility_DEFINITIONS}
    ${SharemindLibRandom_DEFINITIONS}
    ${SharemindLibVmCxx_DEFINITIONS}
    "-DSHAREMIND_EMULATOR_VERSION=\"${SHAREMIND_EMULATOR_VERSION}\""
)
SET(Emulator_LIBRARIES
    ${Boost_LIBRARIES}
    ${SharemindLibConfiguration_LIBRARIES}
    ${SharemindLibFModapiCxx_LIBRARIES}
    ${SharemindLibIController_LIBRARIES}
    ${SharemindLibModapiCxx_LIBRARIES}
    ${SharemindLibProcessFacility_LIBRARIES}
    ${SharemindLibRandom_LIBRARIES}
    ${SharemindLibVmCxx_LIBRARIES}
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
INSTALL(TARGETS sharemind-emulator RUNTIME DESTINATION "bin" COMPONENT "bin")

ADD_CUSTOM_COMMAND(TARGET sharemind-emulator POST_BUILD
    COMMAND "${objcopy}" "--compress-debug-sections"
                         "$<TARGET_FILE:sharemind-emulator>"
                         "$<TARGET_FILE:sharemind-emulator>.debug"
    COMMAND "${objcopy}"
                "--strip-unneeded"
                "--remove-section=.comment"
                "--remove-section=.note"
                "--remove-section=.note.*"
                "--add-gnu-debuglink=$<TARGET_FILE:sharemind-emulator>.debug"
                "$<TARGET_FILE:sharemind-emulator>"
)
INSTALL(FILES "$<TARGET_FILE:sharemind-emulator>.debug" DESTINATION "lib/debug"
        COMPONENT "debug")

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
            DESTINATION "share/man/man1"
            COMPONENT "bin")
ENDFUNCTION()

IF(HELP2MAN)
    GenerateManPage()
ENDIF()


# Packaging:
SET(CPACK_PACKAGE_VENDOR "Cybernetica AS")
SET(CPACK_PACKAGE_CONTACT "Sharemind packaging <sharemind-packaging@cyber.ee>")
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_NAME "sharemind-emulator")
SET(CPACK_DEBIAN_PACKAGE_RELEASE "cyber1")
SET(CPACK_DEBIAN_COMPRESSION_TYPE "xz")
SET(CPACK_DEB_COMPONENT_INSTALL "ON")
SET(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

SET(CPACK_DEBIAN_BIN_PACKAGE_NAME "sharemind-emulator")
SET(CPACK_COMPONENT_BIN_DESCRIPTION "Sharemind Emulator")
SET(CPACK_COMPONENT_DEBUG_DESCRIPTION "Sharemind Emulator debug symbols")

SET(BV "${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.0")
SET(CPACK_DEBIAN_BIN_PACKAGE_DEPENDS
    "libboost-filesystem${BV}"
    "libboost-system${BV}"
    "libc6 (>= 2.19)"
    "libsharemind-configuration (>= 0.1.0)"
    "libsharemind-fmodapi (>= 0.3.0)"
    "libsharemind-modapi (>= 0.3.0)"
    "libsharemind-random (>= 0.2.0)"
    "libsharemind-vm (>= 0.5.0)"
    "libstdc++6 (>= 4.8.0)"
)
STRING(REPLACE ";" ", " CPACK_DEBIAN_BIN_PACKAGE_DEPENDS
       "${CPACK_DEBIAN_BIN_PACKAGE_DEPENDS}")
SET(CPACK_DEBIAN_DEBUG_PACKAGE_DEPENDS
    "sharemind-emulator (= ${SHAREMIND_EMULATOR_VERSION})")
SET(CPACK_DEBIAN_BIN_PACKAGE_SECTION "net")
SET(CPACK_DEBIAN_DEBUG_PACKAGE_SECTION "debug")
INCLUDE(CPack)
