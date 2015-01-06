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
#include <sharemind/MicrosecondTime.h>
#include <system_error>
#include <unistd.h>
#include "Syscalls.h"


namespace sharemind {

inline void writeData(const int outFd, const char * buf, size_t size) {
    if (size > 0u) {
        for (;;) {
            const auto written = ::write(outFd, buf, size);
            if (written > 0) {
                const size_t uWritten = static_cast<size_t>(written);
                assert(uWritten <= size);
                size -= uWritten;
                if (size == 0u)
                    return;
                buf += uWritten;
            } else {
                assert(written == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    throw std::system_error(errno, std::system_category());
            }
        }
    };
}

inline void writeSwapUint64(const int outFd, uint64_t v) {
    v = hostToLittleEndian(v);
    char d[sizeof(v)];
    memcpy(d, &v, sizeof(v));
    writeData(outFd, d, sizeof(v));
}

inline void writeDataWithSize(const int outFd,
                              const char * data,
                              const size_t size)
{
    writeSwapUint64(outFd, size);
    writeData(outFd, data, size);
}

IController::ValueMap processArguments;
int processResultsStream = STDOUT_FILENO;

extern "C" {

SHAREMIND_MODULE_API_0x1_SYSCALL(Process_logMicroseconds,
                                 args, num_args, refs, crefs,
                                 returnValue, c)
{
    (void) args;
    (void) num_args;
    (void) refs;
    (void) crefs;
    (void) returnValue;
    assert(c);
    std::cerr << "Global time is " << getUsTime() << " us."<< std::endl;
    return SHAREMIND_MODULE_API_0x1_OK;
}

/*
  Mandatory cref parameter: argument key string
  Optional ref parameter: argument data buffer
  Return value: argument data length
*/
SHAREMIND_MODULE_API_0x1_SYSCALL(Process_argument,
                                 args, num_args, refs, crs,
                                 returnValue, c)
{
    (void) args;

    if (!crs || crs[1u].pData // Check for one cref argument
        || !returnValue || num_args // Check for return value, and no arguments
        || (refs && refs[1u].pData) // Check for < 2 ref arguments
        || crs[0u].size == 0u
        || static_cast<const char *>(crs[0u].pData)[crs[0u].size - 1u]!= '\0')
    {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }

    assert(c);

    try {
        const std::string argumentName(static_cast<const char *>(crs[0u].pData),
                                       crs[0u].size - 1u);
        const auto a = processArguments.maybeAt(argumentName);
        if (!a)
            return SHAREMIND_MODULE_API_0x1_GENERAL_ERROR;

        const size_t argSize = a->size();
        returnValue->uint64[0u] = argSize;
        if (refs) {
            assert(refs[0u].size > 0u);
            const size_t toCopy = std::min(refs[0u].size, argSize);
            std::copy(static_cast<const char *>(a->data()),
                      static_cast<const char *>(a->data()) + toCopy,
                      static_cast<char *>(refs[0u].pData));
        }
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (const std::bad_alloc &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_SHAREMIND_ERROR;
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
SHAREMIND_MODULE_API_0x1_SYSCALL(Process_setResult,
                                 args, num_args, refs, crefs,
                                 returnValue, c)
{
    typedef const char * const CCP;
    if (// Check for four cref arguments:
        !crefs || (assert(crefs[0u].pData), !crefs[1u].pData)
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

    const uint64_t begin = args[0u].uint64[0u];
    const uint64_t end = args[1u].uint64[0u];

    if (begin > end || end > crefs[3u].size)
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;

    assert(c);
    try {
        writeDataWithSize(processResultsStream,
                          static_cast<const char *>(crefs[0u].pData),
                          crefs[0u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<const char *>(crefs[1u].pData),
                          crefs[1u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<const char *>(crefs[2u].pData),
                          crefs[2u].size - 1u);
        writeDataWithSize(processResultsStream,
                          static_cast<const char *>(crefs[3u].pData) + begin,
                          end - begin);
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (const std::bad_alloc &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_SHAREMIND_ERROR;
    }
}

SHAREMIND_MODULE_API_0x1_SYSCALL(Process_logString,
                                 args, num_args, refs, crefs,
                                 returnValue, c)
{
    (void) args;

    if (!crefs // Mandatory checks
        || num_args || refs || returnValue // Optional checks
        || crefs[1u].pData) // Optional checks
    {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }

    assert(c);

    if (crefs[0u].size == std::numeric_limits<size_t>::max())
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;

    try {
        std::string buffer;
        buffer.reserve(crefs[0u].size + 1u);

        const char * sstart = static_cast<const char *>(crefs[0u].pData);
        const char * scur = sstart;
        const char * ssend = sstart + crefs[0u].size;
        size_t slen = 0u;
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
    } catch (const std::bad_alloc &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_SHAREMIND_ERROR;
    }
}

} // extern "C"

#define BINDING_INIT(f) { #f, { &(f), nullptr } }

const std::map<std::string, const SharemindSyscallWrapper>
    staticSyscallWrappers
{
    BINDING_INIT(Process_argument),
    BINDING_INIT(Process_setResult),
    BINDING_INIT(Process_logString),
    BINDING_INIT(Process_logMicroseconds)
};

} // namespace sharemind {
