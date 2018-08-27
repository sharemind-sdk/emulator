/*
 * Copyright (C) Cybernetica
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

#include "CommandLineArguments.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <list>
#include <sharemind/compiler-support/GccNoreturn.h>
#include <sharemind/compiler-support/GccPR54277.h>
#include <sharemind/Concat.h>
#include <sharemind/Concepts.h>
#include <sharemind/Datum.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/ScopeExit.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
#include "EmulatorException.h"


#ifndef SHAREMIND_EMULATOR_VERSION
#error SHAREMIND_EMULATOR_VERSION not defined!
#endif

namespace {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"
#endif
DEFINE_EXCEPTION_STR(UsageException);
DEFINE_EXCEPTION_CONST_MSG(InputStringTooBigException, "Input string too big!");
DEFINE_EXCEPTION_STR(OutputFileOpenException);
DEFINE_EXCEPTION_STR(OutputFileException);
DEFINE_EXCEPTION_STR(InputFileOpenException);
DEFINE_EXCEPTION_STR(InputFileException);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#pragma GCC diagnostic pop

struct InputData {
    virtual ~InputData() noexcept {}
    virtual std::size_t read(void * buf, std::size_t size) = 0;
    virtual void writeToFileDescriptor(int const fd,
                                       char const * const filename) = 0;
};

class BufferInputData final: public InputData {

public: /* Methods: */

    inline void write(char const c) { m_data.push_back(c); }

    inline void write(void const * const data, std::size_t const size) {
        char const * const d = static_cast<char const *>(data);
        write(d, d + size);
    }

    template <typename Iter> inline void write(Iter first, Iter last)
    { m_data.insert(m_data.end(), first, last); }

    std::size_t read(void * buf, std::size_t size) final override {
        assert(size > 0u);
        std::size_t const dataLeft = m_data.size() - m_pos;
        if (dataLeft == 0u)
            return 0u;
        std::size_t const toRead = std::min(size, dataLeft);
        std::memcpy(buf, m_data.data() + m_pos, toRead);
        m_pos += toRead;
        return toRead;
    }

    void writeToFileDescriptor(int const fd,
                               char const * const filename) final override
    { writeToFileDescriptor(fd, filename, m_data.data(), m_data.size()); }

    static void writeToFileDescriptor(int const fd,
                                      char const * const filename,
                                      char const * buf,
                                      std::size_t size)
    {
        do {
            auto const r = ::write(fd, buf, size);
            if (r > 0) {
                assert(static_cast<std::size_t>(r) <= size);
                size -= static_cast<std::size_t>(r);
                if (size == 0u)
                    return;
                buf += r;
            } else {
                assert(r == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    NESTED_SYSTEM_ERROR(OutputFileException,
                                        "write() failed to output file \"",
                                        filename, "\"!");
            }
        } while (size > 0u);
    }

private: /* Fields: */

    std::vector<char> m_data;
    std::size_t m_pos = 0u;

};

class FileInputData final: public InputData {

public: /* Methods: */

    inline FileInputData(int const fd, char const * const filename)
        : m_fd{fd}
        , m_filename{filename}
    {}

    inline FileInputData(char const * const filename)
        : m_fd{open(filename)}
        , m_filename{filename}
    {}

    inline ~FileInputData() noexcept final override { ::close(m_fd); }

    inline std::size_t read(void * buf, std::size_t size) final override {
        assert(size > 0u);
        for (;;) {
            auto const r = ::read(m_fd, buf, size);
            static_assert(std::numeric_limits<decltype(r)>::max()
                          <= std::numeric_limits<std::size_t>::max(), "");
            if (r >= 0)
                return static_cast<std::size_t>(r);
            assert(r == -1);
            if ((errno != EAGAIN) && (errno != EINTR))
                NESTED_SYSTEM_ERROR(InputFileException,
                                    "Unable to read() from input file \"",
                                    m_filename, "\"!");
        }
    }

    void writeToFileDescriptor(int const fd,
                               char const * const filename) final override
    {
        constexpr std::size_t buf8k_size = 8192u;
        static char buf8k[buf8k_size];

        for (;;) {
            auto const rr = ::read(m_fd, buf8k, buf8k_size);
            if (rr == 0u) {
                return;
            } else if (rr > 0u) {
                BufferInputData::writeToFileDescriptor(
                            fd,
                            filename,
                            buf8k,
                            static_cast<std::size_t>(rr));
            } else {
                assert(rr == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    NESTED_SYSTEM_ERROR(InputFileException,
                                        "Unable to read() given input file \"",
                                        m_filename, "\"!");
            }
        }
    }

    static int open(char const * const filename) {
        char * const realPath = ::realpath(filename, nullptr);
        if (!realPath)
            NESTED_SYSTEM_ERROR(InputFileOpenException,
                                "realpath() failed on \"", filename, "\"!");
        SHAREMIND_SCOPE_EXIT(::free(realPath));
        int const fd = ::open(realPath, O_RDONLY);
        if (fd != -1)
            return fd;
        NESTED_SYSTEM_ERROR(InputFileOpenException,
                            "Unable to open() given input file \"", filename,
                            "\"!");
    }

private: /* Fields: */

    int const m_fd;
    char const * const m_filename;

};

class InputStream {

public: /* Types: */

    SHAREMIND_DECLARE_EXCEPTION_NOINLINE(EmulatorException, Exception);
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-function"
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-member-function"
    #endif
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   IntegralParseException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   NotEnoughInputException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   DuplicateArgumentException);
    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif
    #pragma GCC diagnostic pop

private: /* Types: */

    enum State { INIT, BUFFER, FILE, STDIN };

public: /* Methods: */

    inline ~InputStream() noexcept { for (auto const p : m_data) delete p; }

    template <typename ... Args> inline void writeData(Args && ... args) {
        BufferInputData & buffer =
                (m_state == BUFFER)
                ? *static_cast<BufferInputData *>(*m_data.rbegin())
                : [this]() -> BufferInputData & {
                    auto const bit = new BufferInputData{};
                    try {
                        SHAREMIND_GCCPR54277_WORKAROUND m_data.push_back(bit);
                        SHAREMIND_GCCPR54277_WORKAROUND m_state = BUFFER;
                        return *bit;
                    } catch (...) {
                        delete bit;
                        throw;
                    }
                }();
        buffer.write(std::forward<Args>(args)...);
    }

    template <typename ... Args>
    inline void writeFile(Args && ... args) {
        auto const fit = new FileInputData{std::forward<Args>(args)...};
        try {
            m_data.push_back(fit);
            m_state = FILE;
        } catch (...) {
            delete fit;
            throw;
        }
    }

    template <typename T, bool bigEndian = false>
    inline void writeIntegral(T value) {
        value = bigEndian ? sharemind::hostToBigEndian(value)
                          : sharemind::hostToLittleEndian(value);
        char data[sizeof(value)];
        std::memcpy(data, &value, sizeof(value));
        writeData(data, data + sizeof(value));
    }

    template <typename T, bool bigEndian = false>
    inline void writeIntegral(char const * const input) {
        std::istringstream iss{std::string{input}};
        T integer;
        if ((iss >> integer).fail())
            throw IntegralParseException();
        writeIntegral<T, bigEndian>(integer);
    }

    inline void readData(void * buf, std::size_t size) {
        assert(buf);
        assert(size > 0u);
        while (!m_data.empty()) {
            InputData * const i = m_data.front();
            std::size_t const r = i->read(buf, size);
            assert(r <= size);
            if (r == size)
                return;
            m_data.pop_front();
            delete i;
            buf = static_cast<char *>(buf) + r;
            size -= r;
        }
        throw NotEnoughInputException();
    }

    inline std::uint64_t readSwapUint64() {
        char buf[sizeof(std::uint64_t)];
        readData(buf, sizeof(std::uint64_t));
        std::uint64_t out;
        std::memcpy(&out, buf, sizeof(std::uint64_t));
        return sharemind::littleEndianToHost(out);
    }

    inline std::size_t readSize() {
        static_assert(std::numeric_limits<std::uint64_t>::max()
                      <= std::numeric_limits<std::size_t>::max(), "");
        return readSwapUint64();
    }

    inline std::string readString() {
        std::size_t const size = readSwapUint64();
        if (size == 0u)
            return {};
        std::string str;
        str.resize(size);
        readData(&str[0u], size);
        return str;
    }

    CommandLineArguments::ProcessArguments readArguments() {
        CommandLineArguments::ProcessArguments r;
        for (;;) {
            std::string argName;
            {
                char buf[sizeof(std::uint64_t)];
                // Peek:
                try {
                    readData(buf, 1u);
                } catch (NotEnoughInputException const &) {
                    break;
                }
                readData(&buf[1u], sizeof(std::uint64_t) - 1u);
                std::uint64_t out;
                std::memcpy(&out, buf, sizeof(std::uint64_t));
                static_assert(std::numeric_limits<std::uint64_t>::max()
                              <= std::numeric_limits<std::size_t>::max(), "");
                std::size_t const size = sharemind::littleEndianToHost(out);
                argName.resize(size);
                readData(&argName[0u], size);
            }
            if (r.find(argName) != r.end())
                throw DuplicateArgumentException();
            readString(); // Ignore protection domain name
            readString(); // Ignore type name
            std::size_t const size = readSize();
            sharemind::Datum data;
            data.resize(size);
            readData(static_cast<char *>(data.data()), size);
            r.emplace(std::move(argName), std::move(data));
        }
        return r;
    }

    void writeToFileDescriptor(int const fd, char const * const filename) {
        while (!m_data.empty()) {
            InputData * const i = m_data.front();
            i->writeToFileDescriptor(fd, filename);
            m_data.pop_front();
            delete i;
        }
    }

private: /* Fields: */

    State m_state = INIT;
    std::list<InputData *> m_data;

};
SHAREMIND_DEFINE_EXCEPTION_NOINLINE(EmulatorException,
                                    InputStream::,
                                    Exception);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                              InputStream::,
                                              NotEnoughInputException,
                                              "Not enought input!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(
        Exception,
        InputStream::,
        IntegralParseException,
        "Failed to parse integral from input!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(
        Exception,
        InputStream::,
        DuplicateArgumentException,
        "Duplicate argument(s) given in input!");

inline std::string programNameFromArgv0(char const * const argv0) {
    if (!argv0 || !*argv0)
        return SHAREMIND_EMULATOR_PROGRAM_NAME;
    return argv0;
}

inline void printUsage(std::string const & programName) {
    assert(!programName.empty());
    std::cout
         << "Usage: " << programName << " [OPTIONS] FILENAME\n"
            "Runs the bytecode specified by FILENAME in an execution context "
                "specified by the given configuration file given by the "
                "--conf= argument.\n\n"
            "Required arguments:\n\n"
            "  --conf=FILENAME, -c  Reads the configuration file from the "
            "given location.\n\n"
            "Optional arguments:\n\n"
            "  --help, --usage, -h  Outputs this text to standard output and "
                "exits successfully.\n\n"
            "  --version, -V        Outputs version information to standard "
                "output and exits successfully.\n\n"
            "  --stdin, -t          Writes the contents from the standard "
                "input to the argument stream. Can be given only once.\n\n"
            "  --cstr=STRING, -s    Writes the literal STRING to the argument "
                "stream.\n\n"
            "  --xstr=HEXBYTES, -x  Writes the given hexadecimal bytes to the "
                "argument stream.\n\n"
            "  --int16=VALUE, --int32=VALUE, --int64=VALUE, --uint16=VALUE"
                ", --uint32=VALUE, --uint64=VALUE\n"
            "                       Writes the decimal VALUE to the argument "
                "stream as a little-endian value of the respective type.\n\n"
            "  --bint16=VALUE, --bint32=VALUE, --bint64=VALUE, --buint16=VALUE"
                ", --buint32=VALUE, --buint64=VALUE\n"
            "                       Writes the decimal VALUE to the argument "
                "stream as a big-endian value of the respective type.\n\n"
            "  --size=VALUE, -z     Identical to --uint64=VALUE.\n\n"
            "  -2                   Identical to --size=2 --uint16=VALUE.\n\n"
            "  -4                   Identical to --size=4 --uint32=VALUE.\n\n"
            "  -8                   Identical to --size=8 --uint64=VALUE.\n\n"
            "  --str=STRING, -S     Identical to --size=VALUE --cstr=STRING, "
                "where VALUE is the length of the given STRING.\n\n"
            "  --cfile=FILENAME, -i\n"
            "                       Writes the given binary file to the "
                "argument stream.\n\n"
            "  --file=FILENAME, -I  Identical to --size=VALUE "
                "--cfile=FILENAME, where VALUE is the size of the given "
                "file.\n\n"
            "  --outFile=FILENAME, -o\n"
            "                       Writes the output to the given file "
                "instead of the standard output.\n\n"
            "  --force, -f          Overwrites (truncates) the file given by "
                "--outFile=FILENAME if the file already exists.\n\n"
            "  --append, -a         Appends to the file given by "
                "--outFile=FILENAME if the file already exists.\n\n"
            "  --discard, -d        Identical to --append "
                "--outFile=/dev/null.\n\n"
            "  --printArgs, -p      Stops processing any further arguments, "
                "outputs the argument stream and exits successfully.\n\n"
            "  --user, -u           Specifies the user to use for access "
                "control checks. Overrides the default given by the "
                "AccessControl.DefaultUser configuration option.\n\n"
         << std::flush;
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-template"
#endif
SHAREMIND_DEFINE_CONCEPT(UnsignedCanHoldUnsigned) {
    template <typename T, typename U>
    auto check(T &&, U &&) ->
            SHAREMIND_REQUIRE(
                std::numeric_limits<typename std::decay<T>::type>::max()
                >= std::numeric_limits<typename std::decay<U>::type>::max());
};

template <typename SizeType>
inline auto argumentSizeCheck(SizeType const) noexcept
        -> SHAREMIND_REQUIRE_CONCEPTS_R(
                void,
                sharemind::Unsigned(SizeType),
                UnsignedCanHoldUnsigned(std::uint64_t, SizeType))
{}

template <typename SizeType>
inline auto argumentSizeCheck(SizeType const size)
        -> SHAREMIND_REQUIRE_CONCEPTS_R(
                void,
                sharemind::Unsigned(SizeType),
                sharemind::Not(UnsignedCanHoldUnsigned(std::uint64_t, SizeType)))
{
    if (size > std::numeric_limits<std::uint64_t>::max())
        throw InputStringTooBigException();
}
#ifdef __clang__
#pragma clang diagnostic pop
#endif

} // anonymous namespace

int openOutFile(char const * const filename, int const openFlag) {
    int const fd = ::open(filename,
                          O_WRONLY | O_CREAT | openFlag,
                          S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd == -1)
        NESTED_SYSTEM_ERROR(OutputFileOpenException,
                            "Unable to open() given output file \"", filename,
                            "\"!");
    return fd;
}

CommandLineArguments::CommandLineArguments(int const argc,
                                           char const * const argv[])
{
    assert(argc >= 1);
    InputStream inputData;
    bool haveStdin = false;

    for (std::size_t i = 1u; i < static_cast<std::size_t>(argc); i++) {
        char const * opt = argv[i];
        if (opt[0u] != '-') {
            if (m_bytecodeFilename)
                throw UsageException{"Multiple bytecode FILENAME arguments "
                                     "given!"};
            m_bytecodeFilename = opt;
            continue;
        }

        char const * argument = nullptr;
        opt++;
        if (opt[0u] != '-') {
            if (opt[1u] != '\0')
                goto parseCommandLine_invalid;

#define SHORTOPT(name,label) case name: goto parseCommandLine_ ## label
#define SHORTOPT_ARG(name,sName,aName,label) \
    case name: \
        if (++i >= static_cast<std::size_t>(argc)) \
            throw UsageException{sName " option is missing " aName \
                                 " argument"}; \
        argument = argv[i]; \
        goto parseCommandLine_ ## label

            switch (opt[0u]) {
                SHORTOPT_ARG('c', "A -c", "a FILENAME", conf);
                SHORTOPT_ARG('u', "An -u", "a USERNAME", user);
                SHORTOPT('h', help);
                SHORTOPT('V', version);
                SHORTOPT('t', stdin);
                SHORTOPT_ARG('s', "A -s", "a STRING", cstr);
                SHORTOPT_ARG('x', "A -x", "a HEXBYTES", xstr);
                SHORTOPT_ARG('z', "A -z", "a VALUE", size);
                SHORTOPT_ARG('2', "A -2", "a VALUE", 2);
                SHORTOPT_ARG('4', "A -4", "a VALUE", 4);
                SHORTOPT_ARG('8', "An -8", "a VALUE", 8);
                SHORTOPT_ARG('S', "A -S", "a STRING", str);
                SHORTOPT_ARG('i', "An -i", "a FILENAME", cfile);
                SHORTOPT_ARG('I', "An -I", "a FILENAME", file);
                SHORTOPT_ARG('o', "An -o", "a FILENAME", outFile);
                SHORTOPT('f', force);
                SHORTOPT('a', append);
                SHORTOPT('d', discard);
                SHORTOPT('p', printArgs);
                default: goto parseCommandLine_invalid;
            }
        }
        opt++;

#define LONGOPT(name,label) \
    if ((std::strcmp(opt, name) == 0)) { \
        goto parseCommandLine_ ## label; \
    } else (void) 0
#define LONGOPT_ARG(name,label, aName) \
    if ((std::strncmp(opt, name, sizeof(name) - 1u) == 0)) { \
        if (opt[sizeof(name) - 1u] == '=') { \
            argument = opt + sizeof(name); \
            goto parseCommandLine_ ## label; \
        } else if (opt[sizeof(name) - 1u] == '\0') { \
            if (++i >= static_cast<std::size_t>(argc)) \
                throw UsageException{"--" name " option is missing " aName \
                                     " argument"}; \
            argument = argv[i]; \
            goto parseCommandLine_ ## label; \
        } \
    } else (void) 0

        LONGOPT_ARG("conf", conf, "a FILENAME");
        LONGOPT_ARG("user", user, "a USER");
        LONGOPT("help", help);
        LONGOPT("usage", help);
        LONGOPT("version", version);
        LONGOPT("stdin", stdin);
        LONGOPT_ARG("cstr", cstr, "a STRING");
        LONGOPT_ARG("xstr", xstr, "a HEXBYTES");

#define HANDLE_INTARG(type) LONGOPT_ARG(#type, type, "a VALUE"); \
                            LONGOPT_ARG("b" #type, b ## type, "a VALUE")
        HANDLE_INTARG(int16);
        HANDLE_INTARG(int32);
        HANDLE_INTARG(int64);
        HANDLE_INTARG(uint16);
        HANDLE_INTARG(uint32);
        HANDLE_INTARG(uint64);

        LONGOPT_ARG("size", size, "a VALUE");
        LONGOPT_ARG("str", str, "a STRING");
        LONGOPT_ARG("cfile", cfile, "a FILENAME");
        LONGOPT_ARG("file", file, "a FILENAME");
        LONGOPT_ARG("outFile", outFile, "a FILENAME");
        LONGOPT("printArgs", printArgs);
        LONGOPT("force", force);
        LONGOPT("append", append);
        LONGOPT("discard", discard);

parseCommandLine_invalid:

        throwConcatException<UsageException>("Unrecognized argument given: ",
                                             argv[i]);

parseCommandLine_conf:

        assert(argument);
        if (m_configurationFilename)
            throw UsageException{"Multiple --conf=FILENAME arguments given!"};
        m_configurationFilename = argument;
        continue;

parseCommandLine_user:

        assert(argument);
        if (m_user)
            throw UsageException{"Multiple --user=USERNAME arguments given!"};
        m_user = argument;
        continue;

parseCommandLine_help:

        printUsage(programNameFromArgv0(argv[0u]));
        m_justExit = true;
        return;

parseCommandLine_version:

        std::cout << programNameFromArgv0(argv[0u])
                  << " " SHAREMIND_EMULATOR_VERSION << std::endl;
        m_justExit = true;
        return;

parseCommandLine_stdin:

        if (haveStdin)
            throw UsageException{"Multiple --stdin arguments given!"};
        inputData.writeFile(STDIN_FILENO, "<STDIN>");
        haveStdin = true;
        continue;

parseCommandLine_cstr:

        inputData.writeData(argument, argument + std::strlen(argument));
        continue;

parseCommandLine_xstr:

        for (char const * str = argument; *str; str += 2u) {
            auto const getVal = [=](char const s) {
                switch (s) {
                case '0': return 0x0;
                case '1': return 0x1;
                case '2': return 0x2;
                case '3': return 0x3;
                case '4': return 0x4;
                case '5': return 0x5;
                case '6': return 0x6;
                case '7': return 0x7;
                case '8': return 0x8;
                case '9': return 0x9;
                case 'a': return 0xa;
                case 'b': return 0xb;
                case 'c': return 0xc;
                case 'd': return 0xd;
                case 'e': return 0xe;
                case 'f': return 0xf;
                case 'A': return 0xa;
                case 'B': return 0xb;
                case 'C': return 0xc;
                case 'D': return 0xd;
                case 'E': return 0xe;
                case 'F': return 0xf;
                default:
                    throwConcatException<UsageException>(
                        "Invalid --xstr=HEXBYTES argument given: ",
                        argument);
                }
            };
            inputData.writeData(static_cast<char>((getVal(*str) * 0xf)
                                                  + getVal(*(str + 1u))));
        }
        continue;

#define PROCESS_INTARG_(argname,type,big) \
    parseCommandLine_ ## argname: \
        try { \
            inputData.writeIntegral<std::type ## _t, big>(argument); \
        } catch (InputStream::IntegralParseException const &) { \
            throwConcatException<UsageException>( \
                        "Invalid --" #argname "=VALUE argument given: ", \
                        argument); \
        } \
        continue;

#define PROCESS_INTARG(type) \
    PROCESS_INTARG_(type, type, false) \
    PROCESS_INTARG_(b ## type, type, true)
PROCESS_INTARG(int16)
PROCESS_INTARG(int32)
PROCESS_INTARG(int64)
PROCESS_INTARG(uint16)
PROCESS_INTARG(uint32)
parseCommandLine_size:
PROCESS_INTARG(uint64)

#define PROCESS_SINT(width,bitwidth) \
    parseCommandLine_ ## width: \
        inputData.writeIntegral<std::uint64_t>(width ## u); \
        goto parseCommandLine_uint ## bitwidth

PROCESS_SINT(2, 16);
PROCESS_SINT(4, 32);
PROCESS_SINT(8, 64);

parseCommandLine_str:

        {
            auto const size = std::strlen(argument);
            argumentSizeCheck(size);
            inputData.writeIntegral(static_cast<std::uint64_t>(size));
            if (size > 0u)
                inputData.writeData(argument, argument + size);
        }
        continue;

parseCommandLine_cfile:

        inputData.writeFile(argument);
        continue;

parseCommandLine_file:

        {
            int const fd = FileInputData::open(argument);
            struct ::stat st;
            auto const ret = fstat(fd, &st);
            if (ret != 0) {
                assert(ret == -1);
                NESTED_SYSTEM_ERROR(InputFileOpenException,
                                    "Unable to fstat() given input file \"",
                                    argument, "\"!");
            }
            using UnsignedOffT = std::make_unsigned<off_t>::type;
            static_assert(static_cast<UnsignedOffT>(
                              std::numeric_limits<off_t>::max())
                          <= std::numeric_limits<std::uint64_t>::max(),
                          "");
            std::uint64_t const size =
                    sharemind::hostToLittleEndian(
                        static_cast<std::uint64_t>(st.st_size));
            inputData.writeData(&size, sizeof(size));
            inputData.writeFile(fd, argument);
        }
        continue;

parseCommandLine_outFile:

        if (m_outFilename)
            throw UsageException{"Multiple --output=FILENAME arguments given!"};
        m_outFilename = argument;
        continue;

#define SETOUTFILEFLAG(thisFlag,sThisFlag,otherFlag,sOtherFlag) \
    do { \
        if (m_outOpenFlag == (otherFlag)) \
            throw UsageException{"Can't use both --" sOtherFlag " and --" \
                                 sThisFlag "!"}; \
        m_outOpenFlag = (thisFlag); \
    } while (false)

parseCommandLine_force:

        SETOUTFILEFLAG(O_TRUNC, "force", O_APPEND, "append");
        continue;

parseCommandLine_append:

        SETOUTFILEFLAG(O_APPEND, "append", O_TRUNC, "force");
        continue;

parseCommandLine_discard:

        SETOUTFILEFLAG(O_APPEND, "append", O_TRUNC, "force");
        argument = "/dev/null";
        goto parseCommandLine_outFile;

parseCommandLine_printArgs:


        inputData.writeToFileDescriptor(m_outFilename
                                        ? openOutFile(m_outFilename,
                                                      m_outOpenFlag)
                                        : STDOUT_FILENO,
                                        m_outFilename);
        m_justExit = true;
        return;
    }
    if (!m_bytecodeFilename)
        throw UsageException{"No bytecode FILENAME argument given!"};
    if (!*m_bytecodeFilename)
        throw UsageException("Empty bytecode FILENAME given!");
    m_processArguments = inputData.readArguments();
}
