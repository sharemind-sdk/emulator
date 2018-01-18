/*
 * Copyright (C) 2015 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <iostream>
#include <sharemind/EndianMacros.h>
#include <sharemind/FunctionAttributes.h>
#include <sharemind/MicrosecondTime.h>
#include <sharemind/Random/CryptographicRandom.h>
#include <system_error>
#include <unistd.h>
#include "Syscalls.h"


#define EMULATOR_SYSCALL(...) \
    SHAREMIND_HIDDEN_FUNCTION(SHAREMIND_MODULE_API_0x1_SYSCALL(__VA_ARGS__))

namespace sharemind {

inline void writeData(int const outFd, char const * buf, std::size_t size) {
    if (size > 0u) {
        for (;;) {
            auto const written = ::write(outFd, buf, size);
            if (written > 0) {
                std::size_t const uWritten = static_cast<std::size_t>(written);
                assert(uWritten <= size);
                size -= uWritten;
                if (size == 0u)
                    return;
                buf += uWritten;
            } else {
                assert(written == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    throw std::system_error{errno, std::system_category()};
            }
        }
    };
}

inline void writeSwapUint64(int const outFd, std::uint64_t v) {
    v = hostToLittleEndian(v);
    char d[sizeof(v)];
    memcpy(d, &v, sizeof(v));
    writeData(outFd, d, sizeof(v));
}

inline void writeDataWithSize(int const outFd,
                              char const * data,
                              std::size_t const size)
{
    writeSwapUint64(outFd, size);
    writeData(outFd, data, size);
}

SimpleUnorderedStringMap<Datum> processArguments;
int processResultsStream = STDOUT_FILENO;

/* Mandatory ref parameter: output buffer */
SHAREMIND_HIDDEN_FUNCTION(
template <void (*F)(void * buf, std::size_t bufSize) noexcept>
SHAREMIND_MODULE_API_0x1_SYSCALL(blockingRandomize_,
                                 args, num_args, refs, crs,
                                 returnValue, c))
{
    (void) c;
    (void) args;

    if (crs // Check for 0 cref arguments
        || returnValue || num_args // Check for return value, and no arguments
        || !refs || refs[1u].pData) // Check for 1 ref arguments
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    (*F)(refs[0u].pData, refs[0u].size);
    return SHAREMIND_MODULE_API_0x1_OK;
}

/* Mandatory ref parameter: output buffer
   Return value: Number of bytes of randomness written to buffer. */
SHAREMIND_HIDDEN_FUNCTION(
template <std::size_t (*F)(void * buf, std::size_t bufSize) noexcept>
SHAREMIND_MODULE_API_0x1_SYSCALL(nonblockingRandomize_,
                                 args, num_args, refs, crs,
                                 returnValue, c))
{
    (void) c;
    (void) args;

    if (crs // Check for 0 cref arguments
        || !returnValue || num_args // Check for return value, and no arguments
        || !refs || refs[1u].pData) // Check for 1 ref arguments
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    auto const r((*F)(refs[0u].pData, refs[0u].size));
    assert(r <= refs[0u].size);
    static_assert(std::numeric_limits<decltype(r)>::max()
                  <= std::numeric_limits<std::uint64_t>::max(), "");
    returnValue->uint64[0u] = r;
    return SHAREMIND_MODULE_API_0x1_OK;
}

extern "C" {

#define PASS_SYSCALL(name, to) \
    EMULATOR_SYSCALL(name, args, num_args, refs, crefs, ret, c)\
    { return (to)(args, num_args, refs, crefs, ret, c); }

PASS_SYSCALL(blockingRandomize,
             blockingRandomize_<sharemind::cryptographicRandom>);
PASS_SYSCALL(blockingURandomize,
             blockingRandomize_<sharemind::cryptographicURandom>);
PASS_SYSCALL(nonblockingRandomize,
             nonblockingRandomize_<sharemind::cryptographicRandomNonblocking>);
PASS_SYSCALL(nonblockingURandomize,
             nonblockingRandomize_<sharemind::cryptographicURandomNonblocking>);

EMULATOR_SYSCALL(Process_logMicroseconds, args, num_args, refs, crefs,
                 returnValue, c)
{
    (void) args;
    (void) num_args;
    (void) refs;
    (void) crefs;
    (void) returnValue;
    assert(c);
    (void) c;
    std::cerr << "Global time is " << getUsTime() << " us."<< std::endl;
    return SHAREMIND_MODULE_API_0x1_OK;
}

/*
  Mandatory cref parameter: argument key string
  Optional ref parameter: argument data buffer
  Return value: argument data length
*/
EMULATOR_SYSCALL(Process_argument, args, num_args, refs, crs, returnValue, c) {
    (void) args;

    if (!crs || crs[1u].pData // Check for one cref argument
        || !returnValue || num_args // Check for return value, and no arguments
        || (refs && refs[1u].pData) // Check for < 2 ref arguments
        || crs[0u].size == 0u
        || static_cast<char const *>(crs[0u].pData)[crs[0u].size - 1u]!= '\0')
    {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }

    assert(c);
    (void) c;

    try {
        struct MyStringRange {
            char const * begin() const noexcept
            { return static_cast<char const *>(cref.pData); }
            char const * end() const noexcept
            { return static_cast<char const *>(cref.pData) + cref.size - 1u; }

            SharemindModuleApi0x1CReference const & cref;
        };
        auto const it = processArguments.find(MyStringRange{crs[0u]});
        if (it != processArguments.end()) {
            std::string const argumentName{
                        static_cast<char const *>(crs[0u].pData),
                        crs[0u].size - 1u};
            std::cerr << "Argument \"" << argumentName << "\" not found!"
                      << std::endl;
            return SHAREMIND_MODULE_API_0x1_GENERAL_ERROR;
        }

        auto const & argument = it->second;
        std::size_t const argSize = argument.size();
        returnValue->uint64[0u] = argSize;
        if (refs) {
            assert(refs[0u].size > 0u);
            std::size_t const toCopy = std::min(refs[0u].size, argSize);
            std::copy(static_cast<char const *>(argument.constData()),
                      static_cast<char const *>(argument.constData()) + toCopy,
                      static_cast<char *>(refs[0u].pData));
        }
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (std::bad_alloc const &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_MODULE_ERROR;
    }
}

/*
  Mandatory cref parameter: result key string
  Mandatory cref parameter: result pdName string
  Mandatory cref parameter: result typeName string
  Mandatory cref parameter: result data buffer
  Mandatory stack argument: begin index in data
  Mandatory stack argument: end index in data
  No return value
*/
EMULATOR_SYSCALL(Process_setResult, args, num_args, refs, crefs, returnValue, c)
{
    typedef char const * const CCP;
    if (// Check for four cref arguments:
        !crefs || (static_cast<void>(assert(crefs[0u].pData)), !crefs[1u].pData)
            || !crefs[2u].pData || !crefs[3u].pData || crefs[4u].pData
        // Check for two arguments:
        || num_args != 2u
        // Check for no return value, no refs:
        || returnValue || refs
        // Check cref sizes:
        || crefs[0u].size == 0u || crefs[1u].size == 0u || crefs[2u].size == 0u
        || static_cast<CCP>(crefs[0u].pData)[crefs[0u].size - 1u] != '\0'
        || static_cast<CCP>(crefs[1u].pData)[crefs[1u].size - 1u] != '\0'
        || static_cast<CCP>(crefs[2u].pData)[crefs[2u].size - 1u] != '\0')
    {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }

    std::uint64_t const begin = args[0u].uint64[0u];
    std::uint64_t const end = args[1u].uint64[0u];

    if (begin > end || end > crefs[3u].size)
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    assert(c);
    (void) c;
    try {
        writeDataWithSize(processResultsStream,
                          static_cast<char const *>(crefs[0u].pData),
                          crefs[0u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<char const *>(crefs[1u].pData),
                          crefs[1u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<char const *>(crefs[2u].pData),
                          crefs[2u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<char const *>(crefs[3u].pData) + begin,
                          end - begin);
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (std::bad_alloc const &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_MODULE_ERROR;
    }
}

EMULATOR_SYSCALL(Process_logString, args, num_args, refs, crefs, returnValue, c)
{
    (void) args;

    if (!crefs // Mandatory checks
        || num_args || refs || returnValue // Optional checks
        || crefs[1u].pData) // Optional checks
    {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }

    assert(c);
    (void) c;

    if (crefs[0u].size == std::numeric_limits<std::size_t>::max())
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;

    try {
        std::string buffer;
        buffer.reserve(crefs[0u].size + 1u);

        char const * sstart = static_cast<char const *>(crefs[0u].pData);
        char const * scur = sstart;
        char const * ssend = sstart + crefs[0u].size;
        std::size_t slen = 0u;
        while (scur != ssend) {
            switch (*scur) {
                case '\n':
                    buffer.assign(sstart, slen);
                    std::cerr << buffer << std::endl;
                    sstart = ++scur;
                    slen = 0u;
                    break;
                case '\0':
                    if (slen > 0u) {
                        buffer.assign(sstart, slen);
                        std::cerr << buffer << std::endl;
                    }
                    return SHAREMIND_MODULE_API_0x1_OK;
                default:
                    slen++;
                    scur++;
                    break;
            }
        }
        if (slen > 0u) {
            buffer.assign(sstart, slen);
            std::cerr << buffer << std::endl;
        }
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (std::bad_alloc const &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_MODULE_ERROR;
    }
}

} // extern "C"

#define BINDING_INIT(f) { #f, { &(f), nullptr } }

std::map<std::string, SharemindSyscallWrapper const> const
    staticSyscallWrappers
{
    BINDING_INIT(blockingRandomize),
    BINDING_INIT(blockingURandomize),
    BINDING_INIT(nonblockingRandomize),
    BINDING_INIT(nonblockingURandomize),
    BINDING_INIT(Process_argument),
    BINDING_INIT(Process_setResult),
    BINDING_INIT(Process_logString),
    BINDING_INIT(Process_logMicroseconds)
};

} // namespace sharemind {
