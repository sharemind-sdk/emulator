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

CMAKE_MINIMUM_REQUIRED(VERSION 3.0)
PROJECT(SharemindEmulator VERSION 1.3.0 LANGUAGES CXX)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.3 REQUIRED)


FIND_PROGRAM(HELP2MAN help2man)
FIND_PACKAGE(Boost 1.50 COMPONENTS system filesystem REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders 0.4.0 REQUIRED)
FIND_PACKAGE(SharemindLibAccessControlProcessFacility 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibConfiguration 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibFModapi 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibModapiCxx 0.3.0 REQUIRED)
FIND_PACKAGE(SharemindLibProcessFacility 0.1.0 REQUIRED)
FIND_PACKAGE(SharemindLibRandom 0.3.0 REQUIRED)
FIND_PACKAGE(SharemindLibVm 0.8.0 REQUIRED)
FIND_PACKAGE(SharemindModuleApis 1.0.0 REQUIRED)


# Emulator:
SharemindNormalizeVersion(VERSION "${PROJECT_VERSION}"
                          OUTPUT_VARIABLE SharemindEmulator_NVERSION)
SharemindSetCxx11CompileOptions()
FILE(GLOB_RECURSE SharemindEmulator_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE SharemindEmulator_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
SharemindNewUniqueList(SharemindEmulator_LIBRARIES
    ${Boost_LIBRARIES}
    ${SharemindLibAccessControlProcessFacility_LIBRARIES}
    ${SharemindLibConfiguration_LIBRARIES}
    ${SharemindLibFModapi_LIBRARIES}
    ${SharemindLibModapiCxx_LIBRARIES}
    ${SharemindLibProcessFacility_LIBRARIES}
    ${SharemindLibRandom_LIBRARIES}
    ${SharemindLibVm_LIBRARIES}
    ${SharemindModuleApis_LIBRARIES}
)
SharemindAddExecutable("sharemind-emulator"
    SOURCES
        ${SharemindEmulator_SOURCES}
        ${SharemindEmulator_HEADERS}
    INCLUDE_DIRECTORIES
        ${Boost_INCLUDE_DIRS}
        ${SharemindCxxHeaders_INCLUDE_DIRS}
        ${SharemindLibAccessControlProcessFacility_INCLUDE_DIRS}
        ${SharemindLibConfiguration_INCLUDE_DIRS}
        ${SharemindLibFModapi_INCLUDE_DIRS}
        ${SharemindLibModapiCxx_INCLUDE_DIRS}
        ${SharemindLibProcessFacility_INCLUDE_DIRS}
        ${SharemindLibRandom_INCLUDE_DIRS}
        ${SharemindLibVm_INCLUDE_DIRS}
        ${SharemindModuleApis_INCLUDE_DIRS}
    COMPILE_DEFINITIONS
        "SHAREMIND_EMULATOR_VERSION=\"${SharemindEmulator_NVERSION}\""
        "SHAREMIND_EMULATOR_PROGRAM_NAME=\"sharemind-emulator\""
    LEGACY_DEFINITIONS
        ${SharemindCxxHeaders_DEFINITIONS}
        ${SharemindLibAccessControlProcessFacility_DEFINITIONS}
        ${SharemindLibConfiguration_DEFINITIONS}
        ${SharemindLibFModapi_DEFINITIONS}
        ${SharemindLibModapiCxx_DEFINITIONS}
        ${SharemindLibProcessFacility_DEFINITIONS}
        ${SharemindLibRandom_DEFINITIONS}
        ${SharemindLibVm_DEFINITIONS}
        ${SharemindModuleApis_DEFINITIONS}
        "-DSHAREMIND_INTERNAL_"
    LINK_LIBRARIES
        ${SharemindEmulator_LIBRARIES}
)


# Documentation:
FILE(GLOB_RECURSE SharemindEmulator_DOCS
     "${CMAKE_CURRENT_SOURCE_DIR}/doc/*")
ADD_CUSTOM_TARGET("include_SharemindEmulator_docs_in_IDE"
                  SOURCES ${SharemindEmulator_DOCS})
INSTALL(FILES "${CMAKE_CURRENT_SOURCE_DIR}/doc/emulator.conf.example"
              "${CMAKE_CURRENT_SOURCE_DIR}/doc/argument-stream-decipher.py"
              "${CMAKE_CURRENT_SOURCE_DIR}/doc/emulator-access-control.conf.example"
        DESTINATION "share/doc/sharemind-emulator-${SharemindEmulator_NVERSION}"
        COMPONENT "bin")


# Manual pages:
FUNCTION(GetEmulatorLdLibraryPath out)
    SET(L "")
    FOREACH(l IN LISTS SharemindEmulator_LIBRARIES)
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
    SET(V "${SharemindEmulator_NVERSION}")
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
SharemindSetupPackaging()
SET(BV
    "${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.${Boost_SUBMINOR_VERSION}"
)

SharemindAddComponentPackage(bin
    NAME "sharemind-emulator"
    DESCRIPTION "Sharemind Emulator"
    DEB_SECTION "net"
    DEB_DEPENDS
        "libboost-filesystem${BV}"
        "libboost-system${BV}"
        "libc6 (>= 2.19)"
        "libsharemind-configuration (>= 0.2.0)"
        "libsharemind-fmodapi (>= 0.2.0)"
        "libsharemind-modapi (>= 0.3.0)"
        "libsharemind-random (>= 0.3.0)"
        "libsharemind-vm (>= 0.8.0)"
        "libstdc++6 (>= 4.8.0)"
)
SharemindAddComponentPackage(debug
    NAME "sharemind-emulator-dbg"
    DESCRIPTION "Sharemind Emulator debug symbols"
    DEB_SECTION "debug"
    DEB_DEPENDS
        "sharemind-emulator (= ${SharemindEmulator_DEB_bin_PACKAGE_VERSION})"
)
SharemindPackagingFinalize()
