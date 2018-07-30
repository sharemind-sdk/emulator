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
#include <sharemind/AssertReturn.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/MicrosecondTime.h>
#include <sharemind/Random/CryptographicRandom.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include "EmulatorException.h"
#include "Syscalls.h"

#define EMULATOR_SYSCALL(name) \
    void name( \
            std::vector<::SharemindCodeBlock> & args, \
            std::vector<Vm::Reference> & refs, \
            std::vector<Vm::ConstReference> & crefs, \
            SharemindCodeBlock * const returnValue, \
            Vm::SyscallContext & c)

#define PASS_SYSCALL(name, to) \
    EMULATOR_SYSCALL(name) { return (to)(args, refs, crefs, returnValue, c); }

namespace sharemind {
namespace {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused"
#pragma GCC diagnostic ignored "-Wunused-function"
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"
#endif
class ArgumentNotFoundException: public EmulatorException {

public: /* Methods: */

    template <typename ArgumentName>
    ArgumentNotFoundException(ArgumentName && argumentName)
        : m_message(
              std::make_shared<std::string>(
                  concat("Argument \"",
                         std::forward<ArgumentName>(argumentName),
                         "\" not found!")))
    {}

    ArgumentNotFoundException(ArgumentNotFoundException &&)
            noexcept(std::is_nothrow_move_constructible<Exception>::value) =
                    default;
    ArgumentNotFoundException(ArgumentNotFoundException const &)
            noexcept(std::is_nothrow_copy_constructible<Exception>::value) =
                    default;

    ArgumentNotFoundException & operator=(ArgumentNotFoundException &&)
            noexcept(std::is_nothrow_move_assignable<Exception>::value) =
                    default;
    ArgumentNotFoundException & operator=(ArgumentNotFoundException const &)
            noexcept(std::is_nothrow_copy_assignable<Exception>::value) =
                    default;

    char const * what() const noexcept final override
    { return assertReturn(m_message)->c_str(); }

private: /* Fields: */

    std::shared_ptr<std::string const> m_message;

};
SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(EmulatorException,
                                               InvalidCallException);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(
        EmulatorException,,
        InvalidCallException,
        "Invalid arguments, references, constant references or return value "
        "specified for system call!")
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#pragma GCC diagnostic pop

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

/* Mandatory ref parameter: output buffer */
template <void (*F)(void * buf, std::size_t bufSize) noexcept>
EMULATOR_SYSCALL(blockingRandomize_) {
    (void) c;
    if (!crefs.empty() || returnValue || !args.empty() || refs.size() != 1u)
        throw InvalidCallException();

    (*F)(refs[0u].data.get(), refs[0u].size);
}

/* Mandatory ref parameter: output buffer
   Return value: Number of bytes of randomness written to buffer. */
template <std::size_t (*F)(void * buf, std::size_t bufSize) noexcept>
EMULATOR_SYSCALL(nonblockingRandomize_) {
    (void) c;

    if (!crefs.empty() || !returnValue || !args.empty() || refs.size() != 1u)
        throw InvalidCallException();

    auto const r((*F)(refs[0u].data.get(), refs[0u].size));
    assert(r <= refs[0u].size);
    static_assert(std::numeric_limits<decltype(r)>::max()
                  <= std::numeric_limits<std::uint64_t>::max(), "");
    returnValue->uint64[0u] = r;
}

PASS_SYSCALL(blockingRandomize,
             blockingRandomize_<sharemind::cryptographicRandom>);
PASS_SYSCALL(blockingURandomize,
             blockingRandomize_<sharemind::cryptographicURandom>);
PASS_SYSCALL(nonblockingRandomize,
             nonblockingRandomize_<sharemind::cryptographicRandomNonblocking>);
PASS_SYSCALL(nonblockingURandomize,
             nonblockingRandomize_<sharemind::cryptographicURandomNonblocking>);

EMULATOR_SYSCALL(Process_logMicroseconds) {
    (void) args;
    (void) refs;
    (void) crefs;
    (void) returnValue;
    (void) c;
    std::cerr << "Global time is " << getUsTime() << " us." << std::endl;
}

/*
  Mandatory cref parameter: argument key string
  Optional ref parameter: argument data buffer
  Return value: argument data length
*/
EMULATOR_SYSCALL(Process_argument) {
    if ((crefs.size() != 1u) || !returnValue || !args.empty()
        || (refs.size() > 1u)
        || (crefs[0u].size == 0u)
        || static_cast<char const *>(crefs[0u].data.get())[crefs[0u].size - 1u]!= '\0')
    {
        throw InvalidCallException();
    }

    (void) c;

    struct MyStringRange {
        char const * begin() const noexcept
        { return static_cast<char const *>(cref.data.get()); }
        char const * end() const noexcept
        { return static_cast<char const *>(cref.data.get()) + cref.size - 1u; }

        Vm::ConstReference const & cref;
    };
    auto const it = processArguments.find(MyStringRange{crefs[0u]});
    if (it == processArguments.end())
        throw ArgumentNotFoundException(
                    std::string(static_cast<char const *>(crefs[0u].data.get()),
                                crefs[0u].size - 1u));

    auto const & argument = it->second;
    std::size_t const argSize = argument.size();
    returnValue->uint64[0u] = argSize;
    if (!refs.empty()) {
        assert(refs[0u].size > 0u);
        std::size_t const toCopy = std::min(refs[0u].size, argSize);
        std::copy(static_cast<char const *>(argument.constData()),
                  static_cast<char const *>(argument.constData()) + toCopy,
                  static_cast<char *>(refs[0u].data.get()));
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
EMULATOR_SYSCALL(Process_setResult) {
    typedef char const * const CCP;
    if ((crefs.size() != 4u) || (args.size() != 2u) || returnValue
        || !refs.empty()
        || crefs[0u].size == 0u || crefs[1u].size == 0u || crefs[2u].size == 0u
        || static_cast<CCP>(crefs[0u].data.get())[crefs[0u].size - 1u] != '\0'
        || static_cast<CCP>(crefs[1u].data.get())[crefs[1u].size - 1u] != '\0'
        || static_cast<CCP>(crefs[2u].data.get())[crefs[2u].size - 1u] != '\0')
    {
        throw InvalidCallException();
    }

    std::uint64_t const begin = args[0u].uint64[0u];
    std::uint64_t const end = args[1u].uint64[0u];

    if (begin > end || end > crefs[3u].size)
        throw InvalidCallException();

    (void) c;
    writeDataWithSize(processResultsStream,
                      static_cast<char const *>(crefs[0u].data.get()),
                      crefs[0u].size - 1u);
    writeDataWithSize(processResultsStream,
                      static_cast<char const *>(crefs[1u].data.get()),
                      crefs[1u].size - 1u);
    writeDataWithSize(processResultsStream,
                      static_cast<char const *>(crefs[2u].data.get()),
                      crefs[2u].size - 1u);
    writeDataWithSize(processResultsStream,
                      static_cast<char const *>(crefs[3u].data.get()) + begin,
                      end - begin);
}

EMULATOR_SYSCALL(Process_logString) {
    if ((crefs.size() != 1u) || !args.empty() || !refs.empty() || returnValue)
        throw InvalidCallException();

    (void) c;

    if (crefs[0u].size == std::numeric_limits<std::size_t>::max())
        throw std::bad_array_new_length();

    std::string buffer;
    buffer.reserve(crefs[0u].size + 1u);

    char const * sstart = static_cast<char const *>(crefs[0u].data.get());
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
                return;
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
}

using SyscallFunctionPtr =
        void (*)(
                std::vector<::SharemindCodeBlock> & arguments,
                std::vector<Vm::Reference> & references,
                std::vector<Vm::ConstReference> & constReferences,
                SharemindCodeBlock * returnValue,
                Vm::SyscallContext & context);

template <SyscallFunctionPtr F>
class SyscallWrapper final: public Vm::SyscallWrapper {

public: /* Methods: */

    void operator()(
            std::vector<::SharemindCodeBlock> & arguments,
            std::vector<Vm::Reference> & references,
            std::vector<Vm::ConstReference> & constReferences,
            SharemindCodeBlock * returnValue,
            Vm::SyscallContext & context) const final override
    {
        return (*F)(arguments,
                    references,
                    constReferences,
                    returnValue,
                    context);
    }

};

template <SyscallFunctionPtr F>
std::shared_ptr<Vm::SyscallWrapper> createSyscallWrapper()
{ return std::make_shared<SyscallWrapper<F> >(); }

} // anonymous namespace

SimpleUnorderedStringMap<Datum> processArguments;
int processResultsStream = STDOUT_FILENO;

#define BINDING_INIT(f) { #f, createSyscallWrapper<&f>() }

SimpleUnorderedStringMap<std::shared_ptr<Vm::SyscallWrapper> > syscallWrappers {
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
