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
PROJECT(SharemindEmulator VERSION 1.5.0 LANGUAGES CXX)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.6 REQUIRED)


FIND_PROGRAM(HELP2MAN help2man)
FIND_PACKAGE(Boost 1.62 COMPONENTS system filesystem REQUIRED)
FIND_PACKAGE(SharemindCxxHeaders 0.9.0 REQUIRED)
FIND_PACKAGE(SharemindLibAccessControlProcessFacility 0.4.0 REQUIRED)
FIND_PACKAGE(SharemindLibConfiguration 0.6.0 REQUIRED)
FIND_PACKAGE(SharemindLibFModapi 0.5.0 REQUIRED)
FIND_PACKAGE(SharemindLibModapiCxx 0.5.0 REQUIRED)
FIND_PACKAGE(SharemindLibProcessFacility 0.2.0 REQUIRED)
FIND_PACKAGE(SharemindLibRandom 0.6.0 REQUIRED)
FIND_PACKAGE(SharemindLibVm 0.11.0 REQUIRED)
FIND_PACKAGE(SharemindModuleApis 1.1.0 REQUIRED)


# Emulator:
SharemindNormalizeVersion(VERSION "${PROJECT_VERSION}"
                          OUTPUT_VARIABLE SharemindEmulator_NVERSION)
FILE(GLOB_RECURSE SharemindEmulator_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
FILE(GLOB_RECURSE SharemindEmulator_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
SharemindAddExecutable(sharemind-emulator
    SOURCES
        ${SharemindEmulator_SOURCES}
        ${SharemindEmulator_HEADERS}
    )
TARGET_COMPILE_DEFINITIONS(sharemind-emulator
    PRIVATE
        "SHAREMIND_EMULATOR_VERSION=\"${SharemindEmulator_NVERSION}\""
        "SHAREMIND_EMULATOR_PROGRAM_NAME=\"sharemind-emulator\""
        "SHAREMIND_INTERNAL_"
    )
TARGET_LINK_LIBRARIES(sharemind-emulator
    PRIVATE
        Boost::boost
        Boost::filesystem
        Boost::system
        Sharemind::CxxHeaders
        Sharemind::LibAccessControlProcessFacility
        Sharemind::LibConfiguration
        Sharemind::LibFModapi
        Sharemind::LibModapiCxx
        Sharemind::LibProcessFacility
        Sharemind::LibRandom
        Sharemind::LibVm
        Sharemind::ModuleApis
    )


# Documentation:
FILE(GLOB_RECURSE SharemindEmulator_DOCS
     "${CMAKE_CURRENT_SOURCE_DIR}/doc/*")
ADD_CUSTOM_TARGET("include_SharemindEmulator_docs_in_IDE"
                  SOURCES ${SharemindEmulator_DOCS})
INSTALL(FILES "${CMAKE_CURRENT_SOURCE_DIR}/doc/emulator.conf.example"
              "${CMAKE_CURRENT_SOURCE_DIR}/doc/argument-stream-decipher.py"
              "${CMAKE_CURRENT_SOURCE_DIR}/doc/emulator-access-control.conf.example"
        DESTINATION "share/doc/sharemind-emulator"
        COMPONENT "bin")


# Manual pages:
FUNCTION(GetEmulatorLdLibraryPath out)
    SET(LD_LIBRARY_PATH)
    GET_PROPERTY(LINK_LIBRARIES TARGET "sharemind-emulator" PROPERTY LINK_LIBRARIES)
    FOREACH(LINK_LIBRARY IN LISTS LINK_LIBRARIES)
        GET_PROPERTY(LINK_LIBRARY_TYPE TARGET "${LINK_LIBRARY}" PROPERTY TYPE)
        IF("${LINK_LIBRARY_TYPE}" MATCHES "^(STATIC|MODULE|SHARED|OBJECT)_LIBRARY$")
            GET_PROPERTY(LINK_LIBRARY TARGET "${LINK_LIBRARY}" PROPERTY LOCATION)
            GET_FILENAME_COMPONENT(LINK_LIBRARY_DIR "${LINK_LIBRARY}" DIRECTORY)
            LIST(APPEND LD_LIBRARY_PATH "${LINK_LIBRARY_DIR}")
        ENDIF()
    ENDFOREACH()
    LIST(REMOVE_DUPLICATES LD_LIBRARY_PATH)
    STRING(REPLACE ";" ":" LD_LIBRARY_PATH "${LD_LIBRARY_PATH}")
    SET("${out}" "${LD_LIBRARY_PATH}" PARENT_SCOPE)
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

# Configuration files:
INSTALL(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/packaging/configs/sharemind/"
        DESTINATION "/etc/sharemind/"
        COMPONENT "bin"
        EXCLUDE_FROM_ALL)

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
        "libsharemind-vm (>= 0.11.0)"
        "libstdc++6 (>= 4.8.0)"
    DEB_RECOMMENDS
        "libsharemind-facility-loghard (>= 0.4.0)"
        "libsharemind-facility-datastoremanager (>= 0.2.0)"
        "libsharemind-facility-executionprofiler (>= 0.2.0)"
    DEB_EXTRA_CONTROL_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/conffiles"
)
SharemindAddComponentPackage(debug
    NAME "sharemind-emulator-dbg"
    DESCRIPTION "Sharemind Emulator debug symbols"
    DEB_SECTION "debug"
    DEB_DEPENDS
        "sharemind-emulator (= ${SharemindEmulator_DEB_bin_PACKAGE_VERSION})"
)
SharemindPackagingFinalize()
