/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
 */

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <iterator>
#include <iostream>
#include <iosfwd>
#include <list>
#include <memory>
#include <sharemind/compiler-support/GccVersion.h>
#include <sharemind/Concat.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/Exception.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <sharemind/libvm/libvmcxx.h>
#include <sharemind/ScopeExit.h>
#include <signal.h>
#include <sstream>
#include <sys/stat.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
#include "Configuration.h"
#include "Syscalls.h"


#ifndef SHAREMIND_EMULATOR_VERSION
#error SHAREMIND_EMULATOR_VERSION not defined!
#endif

namespace sharemind {

constexpr const size_t buf8k_size = 8192u;
char buf8k[buf8k_size];

SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, UsageException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, ModuleLoadException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, ModuleInitException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, PdCreateException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, PdStartException);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     PdkNotFoundException,
                                     "Protection domain kind not found!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     InputStringTooBigException,
                                     "Input string too big!");
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, OutputFileOpenException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, OutputFileException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, InputFileOpenException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, InputFileException);
struct GracefulException {};
struct WriteIntegralArgumentException {};
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     SigEmptySetException,
                                     "sigemptyset() failed!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     SigActionException,
                                     "sigaction() failed!");

#define NESTED_THROW_CONCAT_EXCEPTION(Exception,str,...) \
    std::throw_with_nested(Exception{str "!", str ": ", __VA_ARGS__});

#define NESTED_SYSTEM_ERROR(Exception,str,...) \
    do { \
        try { \
            throw std::system_error(errno, std::system_category()); \
        } catch (...) { \
            NESTED_THROW_CONCAT_EXCEPTION(Exception, str, __VA_ARGS__); \
        } \
    } while(false)
#define NESTED_SYSTEM_ERROR2(...) \
    do { \
        try { \
            throw std::system_error(errno, std::system_category()); \
        } catch (...) { \
            std::throw_with_nested(__VA_ARGS__); \
        } \
    } while(false)

const char * programName = nullptr;

SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     InputException,
                                     "Invalid input to program!");

struct InputData {
    virtual ~InputData() noexcept {}
    virtual size_t read(void * buf, size_t size) = 0;
    virtual void writeToFileDescriptor(const int fd,
                                       const char * const filename) = 0;
};

class BufferInputData final: public InputData {

public: /* Methods: */

    inline void write(const char c) { m_data.push_back(c); }

    inline void write(const void * const data, const size_t size) {
        const char * const d = static_cast<const char *>(data);
        write(d, d + size);
    }

    template <typename Iter> inline void write(Iter first, Iter last)
    { m_data.insert(m_data.end(), first, last); }

    size_t read(void * buf, size_t size) final override {
        assert(size > 0u);
        const size_t dataLeft = m_data.size() - m_pos;
        if (dataLeft == 0u)
            return 0u;
        const size_t toRead = std::min(size, dataLeft);
        ::memcpy(buf, m_data.data() + m_pos, toRead);
        m_pos += toRead;
        return toRead;
    }

    void writeToFileDescriptor(const int fd,
                               const char * const filename) final override
    { writeToFileDescriptor(fd, filename, m_data.data(), m_data.size()); }

    static void writeToFileDescriptor(const int fd,
                                      const char * const filename,
                                      const char * buf,
                                      size_t size)
    {
        do {
            const auto r = ::write(fd, buf, size);
            if (r > 0) {
                assert(static_cast<size_t>(r) <= size);
                size -= static_cast<size_t>(r);
                if (size == 0u)
                    return;
                buf += r;
            } else {
                assert(r == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    NESTED_SYSTEM_ERROR(OutputFileException,
                                        "write() failed to output file",
                                        filename);
            }
        } while (size > 0u);
    }

private: /* Fields: */

    std::vector<char> m_data;
    size_t m_pos = 0u;

};

class FileInputData final: public InputData {

public: /* Methods: */

    inline FileInputData(const int fd, const char * const filename)
        : m_fd(fd)
        , m_filename(filename)
    {}

    inline FileInputData(const char * const filename)
        : m_fd(open(filename))
        , m_filename(filename)
    {}

    inline ~FileInputData() noexcept final override { ::close(m_fd); }

    inline size_t read(void * buf, size_t size) final override {
        assert(size > 0u);
        for (;;) {
            const ssize_t r = ::read(m_fd, buf, size);
            if (r >= 0)
                return r;
            assert(r == -1);
            if ((errno != EAGAIN) && (errno != EINTR))
                NESTED_SYSTEM_ERROR(InputFileException,
                                    "Unable to read() from input file",
                                    m_filename);
        }
    }

    void writeToFileDescriptor(const int fd,
                               const char * const filename) final override
    {
        for (;;) {
            const auto rr = ::read(m_fd, buf8k, buf8k_size);
            if (rr == 0u) {
                return;
            } else if (rr > 0u) {
                BufferInputData::writeToFileDescriptor(fd,
                                                       filename,
                                                       buf8k,
                                                       static_cast<size_t>(rr));
            } else {
                assert(rr == -1);
                if ((errno != EAGAIN) && (errno != EINTR))
                    NESTED_SYSTEM_ERROR(InputFileException,
                                        "Unable to read() given input file",
                                        m_filename);
            }
        }
    }

    static int open(const char * filename) {
        char * const realPath = ::realpath(filename, nullptr);
        if (!realPath)
            NESTED_SYSTEM_ERROR(InputFileOpenException,
                                "realpath() failed",
                                filename);
        SHAREMIND_SCOPE_EXIT(::free(realPath));
        const int fd = ::open(realPath, O_RDONLY);
        if (fd != -1)
            return fd;
        NESTED_SYSTEM_ERROR(InputFileOpenException,
                            "Unable to open() given input file",
                            filename);
    }

private: /* Fields: */

    int m_fd;
    const char * const m_filename;

};

class InputStream {

private: /* Types: */

    enum State { INIT, BUFFER, FILE, STDIN };

public: /* Methods: */

    inline ~InputStream() noexcept { for (auto const p : m_data) delete p; }

    template <typename ... Args> inline void writeData(Args && ... args) {
        BufferInputData & buffer =
                (m_state == BUFFER)
                ? *static_cast<BufferInputData *>(*m_data.rbegin())
                : [this]() -> BufferInputData & {
                    const auto bit = new BufferInputData{};
                    try {
                        m_data.push_back(bit);
                        m_state = BUFFER;
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
        const auto fit = new FileInputData{std::forward<Args>(args)...};
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
        value = bigEndian ? hostToBigEndian(value) : hostToLittleEndian(value);
        char data[sizeof(value)];
        ::memcpy(data, &value, sizeof(value));
        writeData(data, data + sizeof(value));
    }

    template <typename T, bool bigEndian = false>
    inline void writeIntegral(const char * const input) {
        std::istringstream iss{std::string{input}};
        T integer;
        if ((iss >> integer).fail())
            throw WriteIntegralArgumentException{};
        writeIntegral<T, bigEndian>(integer);
    }

    inline void readData(void * buf, size_t size) {
        assert(buf);
        assert(size > 0u);
        while (!m_data.empty()) {
            InputData * const i = m_data.front();
            const size_t r = i->read(buf, size);
            assert(r <= size);
            if (r == size)
                return;
            m_data.pop_front();
            delete i;
            buf = static_cast<char *>(buf) + r;
            size -= r;
        }
        throw InputException();
    }

    inline uint64_t readSwapUint64() {
        char buf[sizeof(uint64_t)];
        readData(buf, sizeof(uint64_t));
        uint64_t out;
        ::memcpy(&out, buf, sizeof(uint64_t));
        return littleEndianToHost(out);
    }

    inline size_t readSize() {
        static_assert(std::numeric_limits<uint64_t>::max()
                      <= std::numeric_limits<size_t>::max(), "");
        return readSwapUint64();
    }

    inline std::string readString() {
        const size_t size = readSwapUint64();
        if (size == 0u)
            return {};
        std::string str;
        str.resize(size);
        readData(&str[0u], size);
        return str;
    }

    inline sharemind::IController::ValueMap readArguments() {
        sharemind::IController::ValueMap args;
        for (;;) {
            std::string argName;
            {
                char buf[sizeof(uint64_t)];
                // Peek:
                try {
                    readData(buf, 1u);
                } catch (const InputException &) {
                    break;
                }
                readData(&buf[1u], sizeof(uint64_t) - 1u);
                uint64_t out;
                ::memcpy(&out, buf, sizeof(uint64_t));
                const size_t size = littleEndianToHost(out);
                argName.resize(size);
                readData(&argName[0u], size);
            }
            if (args.find(argName) != args.end())
                throw InputException();
            std::string pdName{readString()};
            std::string typeName{readString()};
            const size_t size = readSize();
            void * data = ::operator new(size);
            try {
                readData(static_cast<char *>(data), size);
                auto * const value = new sharemind::IController::Value{
                        std::move(pdName),
                        std::move(typeName),
                        data,
                        size,
                        sharemind::IController::Value::TAKE_OWNERSHIP};
                try {
                    data = nullptr;
                    #ifndef NDEBUG
                    const auto r =
                    #endif
                    #if defined(SHAREMIND_GCC_VERSION) \
                            && SHAREMIND_GCC_VERSION < 40800
                            args.insert(std::move(argName), value);
                    #else
                            args.emplace(std::move(argName), value);
                    #endif
                    assert(r.second);
                } catch (...) {
                    delete value;
                    throw;
                }
            } catch (...) {
                ::operator delete(data);
                throw;
            }
        }
        return args;
    }

    void writeToFileDescriptor(const int fd, const char * const filename) {
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

int openOutFile(const char * const filename, const int openFlag) {
    const int fd = ::open(filename,
                          O_WRONLY | O_CREAT | openFlag,
                          S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd == -1)
        NESTED_SYSTEM_ERROR(OutputFileOpenException,
                            "Unable to open() given output file",
                            filename);
    return fd;
}

struct CommandLineArgs {
    bool justExit = false;
    bool haveStdin = false;
    const char * configurationFilename = nullptr;
    const char * bytecodeFilename = nullptr;
    const char * outFilename = nullptr;
    int outOpenFlag = O_EXCL;
};

inline void printUsage() {
    using namespace std;
    cerr << "Usage: " << programName
         << " [OPTIONS] FILENAME" << endl
         << "Runs the bytecode specified by FILENAME in an execution context "
            "specified by the given configuration file given by the --conf= "
            "argument." << endl << endl
         << "Required arguments:" << endl << endl
         << "  --conf=FILENAME, -c  Reads the configuration file from the "
            "given location." << endl << endl
         << "Optional arguments:" << endl << endl
         << "  --help, --usage, -h  Displays this help and exits successfully."
         << endl << endl
         << "  --version, -V        Outputs version information and exits "
            "successfully." << endl << endl
         << "  --stdin, -t          Writes the contents from the standard "
            "input to the argument stream. Can be given only once."
         << endl << endl
         << "  --cstr=STRING, -s    Writes the literal STRING to the argument "
            "stream." << endl << endl
         << "  --xstr=HEXBYTES, -x  Writes the given hexadecimal bytes to the "
            "argument stream." << endl << endl
         << "  --int16=VALUE, --int32=VALUE, --int64=VALUE, --uint16=VALUE"
            ", --uint32=VALUE, --uint64=VALUE" << endl
         << "                       Writes the decimal VALUE to the argument "
            "stream as a little-endian value of the respective type."
         << endl << endl
         << "  --bint16=VALUE, --bint32=VALUE, --bint64=VALUE, --buint16=VALUE"
            ", --buint32=VALUE, --buint64=VALUE" << endl
         << "                       Writes the decimal VALUE to the argument "
            "stream as a big-endian value of the respective type."
         << endl << endl
         << "  --size=VALUE, -z     Identical to --uint64=VALUE."
         << endl << endl
         << "  -2                   Identical to --size=2 --uint16=VALUE."
         << endl << endl
         << "  -4                   Identical to --size=4 --uint32=VALUE."
         << endl << endl
         << "  -8                   Identical to --size=8 --uint64=VALUE."
         << endl << endl
         << "  --str=STRING, -S     Identical to --size=VALUE --cstr=STRING, "
            "where VALUE is the length of the given STRING." << endl << endl
         << "  --cfile=FILENAME, -i" << endl
         << "                       Writes the given binary file to the "
            "argument stream." << endl << endl
         << "  --file=FILENAME, -I  Identical to --size=VALUE "
            "--cfile=FILENAME, where VALUE is the size of the given file."
         << endl << endl
         << "  --outFile=FILENAME, -o" << endl
         << "                       Writes the output to the given file "
            "instead of the standard output." << endl << endl
         << "  --force, -f          Overwrites (truncates) the file given by "
            "--outFile=FILENAME if the file already exists." << endl << endl
         << "  --append, -a         Appends to the file given by "
            "--outFile=FILENAME if the file already exists." << endl << endl
         << "  --discard, -d        Identical to --append --outFile=/dev/null."
         << endl << endl
         << "  --printArgs, -p      Stops processing any further arguments, "
            "outputs the argument stream and exits successfully."
         << endl << endl;
}

inline CommandLineArgs parseCommandLine(const int argc,
                                        const char * const argv[])
{
    assert(argc >= 1);
    programName = argv[0u];
    CommandLineArgs r;
    InputStream inputData;
    for (size_t i = 1u; i < static_cast<size_t>(argc); i++) {
        const char * opt = argv[i];
        if (opt[0u] != '-') {
            if (r.bytecodeFilename)
                throw UsageException{"Multiple bytecode FILENAME arguments "
                                     "given!"};
            r.bytecodeFilename = opt;
            continue;
        }

        const char * argument = nullptr;
        opt++;
        if (opt[0u] != '-') {
            if (opt[1u] != '\0')
                goto parseCommandLine_invalid;

#define SHORTOPT(name,label) case name: goto parseCommandLine_ ## label
#define SHORTOPT_ARG(name,sName,aName,label) \
    case name: \
        if (++i >= static_cast<size_t>(argc)) \
            throw UsageException{sName " option is missing " aName \
                                 " argument"}; \
        argument = argv[i]; \
        goto parseCommandLine_ ## label

            switch (opt[0u]) {
                SHORTOPT_ARG('c', "A -c", "a FILENAME", conf);
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
    if ((strcmp(opt, name) == 0)) { \
        goto parseCommandLine_ ## label; \
    } else (void) 0
#define LONGOPT_ARG(name,label) \
    if ((strncmp(opt, name "=", sizeof(name)) == 0) \
        && (opt[sizeof(name)] != '\0')) { \
        argument = opt + sizeof(name); \
        goto parseCommandLine_ ## label; \
    } else (void) 0

        LONGOPT_ARG("conf", conf);
        LONGOPT("help", help);
        LONGOPT("usage", help);
        LONGOPT("version", version);
        LONGOPT("stdin", stdin);
        LONGOPT("cstr", cstr);
        LONGOPT("xstr", xstr);

#define HANDLE_INTARG(type) LONGOPT_ARG(#type, type); \
                            LONGOPT_ARG("b" #type, b ## type)
        HANDLE_INTARG(int16);
        HANDLE_INTARG(int32);
        HANDLE_INTARG(int64);
        HANDLE_INTARG(uint16);
        HANDLE_INTARG(uint32);
        HANDLE_INTARG(uint64);

        LONGOPT_ARG("size", size);
        LONGOPT_ARG("str", str);
        LONGOPT_ARG("cfile", cfile);
        LONGOPT_ARG("file", file);
        LONGOPT_ARG("outFile", outFile);
        LONGOPT("printArgs", printArgs);
        LONGOPT("force", force);
        LONGOPT("append", append);
        LONGOPT_ARG("discard", discard);

parseCommandLine_invalid:

        throw UsageException{"Unrecognized argument given!",
                             "Unrecognized argument given: ",
                             argv[i]};

parseCommandLine_conf:

        assert(argument);
        if (r.configurationFilename)
            throw UsageException{"Multiple --conf=FILENAME arguments given!"};
        r.configurationFilename = argument;
        continue;

parseCommandLine_help:

        printUsage();
        throw GracefulException{};

parseCommandLine_version:

        std::cerr << "Emulator " SHAREMIND_EMULATOR_VERSION << std::endl;
        throw GracefulException{};

parseCommandLine_stdin:

        if (r.haveStdin)
            throw UsageException{"Multiple --stdin arguments given!"};
        inputData.writeFile(STDIN_FILENO, "<STDIN>");
        r.haveStdin = true;
        continue;

parseCommandLine_cstr:

        inputData.writeData(argument, argument + strlen(argument));
        continue;

parseCommandLine_xstr:

        for (const char * str = argument; *str; str += 2u) {
            const auto getVal = [=](const char s) {
                switch (s) {
                case 'a' ... 'f': return (s - 'a') + 0xa;
                case 'A' ... 'F': return (s - 'A') + 0xA;
                case '0' ... '9': return (s - '0') + 0x0;
                default:
                    throw UsageException{
                        "Invalid --xstr=HEXBYTES argument given!",
                        "Invalid --xstr=HEXBYTES argument given: ",
                        argument};
                }
            };
            inputData.writeData((getVal(*str) * 0xf) + getVal(*(str + 1u)));
        }
        continue;

#define PROCESS_INTARG__(argname,type,big) \
    parseCommandLine_ ## argname: \
        try { \
            inputData.writeIntegral<type ## _t, big>(argument); \
        } catch (const WriteIntegralArgumentException &) { \
            throw UsageException{ \
                        "Invalid --" #argname "=VALUE argument given!", \
                        "Invalid --" #argname "=VALUE argument given: ", \
                        argument}; \
        } \
        continue;

#define PROCESS_INTARG(type) \
    PROCESS_INTARG__(type, type, false) \
    PROCESS_INTARG__(b ## type, type, true)
PROCESS_INTARG(int16)
PROCESS_INTARG(int32)
PROCESS_INTARG(int64)
PROCESS_INTARG(uint16)
PROCESS_INTARG(uint32)
parseCommandLine_size:
PROCESS_INTARG(uint64)

#define PROCESS_SINT(width,bitwidth) \
    parseCommandLine_ ## width: \
        inputData.writeIntegral<uint64_t>(width ## u); \
        goto parseCommandLine_uint ## bitwidth

PROCESS_SINT(2, 16);
PROCESS_SINT(4, 32);
PROCESS_SINT(8, 64);

parseCommandLine_str:

        {
            const auto size = strlen(argument);
            if (size > std::numeric_limits<uint64_t>::max())
                throw InputStringTooBigException{};
            inputData.writeIntegral(static_cast<uint64_t>(size));
            if (size > 0u)
                inputData.writeData(argument, argument + size);
        }
        continue;

parseCommandLine_cfile:

        inputData.writeFile(argument);
        continue;

parseCommandLine_file:

        {
            const int fd = FileInputData::open(argument);
            struct ::stat st;
            const auto ret = fstat(fd, &st);
            if (ret != 0) {
                assert(ret == -1);
                NESTED_SYSTEM_ERROR(InputFileOpenException,
                                    "Unable to fstat() given input file",
                                    argument);
            }
            static_assert(std::numeric_limits<decltype(st.st_size)>::max()
                          <= std::numeric_limits<uint64_t>::max(),
                          "");
            const uint64_t size =
                    hostToLittleEndian(static_cast<uint64_t>(st.st_size));
            inputData.writeData(&size, sizeof(size));
            inputData.writeFile(fd, argument);
        }
        continue;

parseCommandLine_outFile:

        if (r.outFilename)
            throw UsageException{"Multiple --output=FILENAME arguments given!"};
        r.outFilename = argument;
        continue;

#define SETOUTFILEFLAG(thisFlag,sThisFlag,otherFlag,sOtherFlag) \
    do { \
        if (r.outOpenFlag == (otherFlag)) \
            throw UsageException{"Can't use both --" sOtherFlag " and --" \
                                 sThisFlag "!"}; \
        r.outOpenFlag = (thisFlag); \
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


        inputData.writeToFileDescriptor(r.outFilename
                                        ? openOutFile(r.outFilename,
                                                      r.outOpenFlag)
                                        : STDOUT_FILENO,
                                        r.outFilename);
        throw GracefulException{};

    }
    if (!r.bytecodeFilename)
        throw UsageException{"No bytecode FILENAME argument given!"};
    if (!r.configurationFilename)
        throw UsageException{"No --conf=FILENAME argument given!"};
    processArguments = inputData.readArguments();
    return r;
}

inline void printException__(const std::exception & e,
                             const size_t levelNow,
                             size_t & totalLevels) noexcept
{
    try {
        std::rethrow_if_nested(e);
    } catch (const std::exception & e2) {
        printException__(e2, levelNow + 1u, ++totalLevels);
    }
    std::cerr << "Error " << (totalLevels - levelNow + 1u) << " of "
              << totalLevels << ": " << e.what() << std::endl;
}

inline void printException(const std::exception & e) noexcept {
    size_t levels = 1u;
    printException__(e, 1u, levels);
}

ModuleApi modapi;

} // namespace sharemind {

int main(int argc, char * argv[]) {
    using namespace sharemind;
    try {
        {
            struct sigaction sa;
            sa.sa_handler = SIG_IGN;
            auto r = sigemptyset(&sa.sa_mask);
            if (r != 0) {
                assert(r == -1);
                NESTED_SYSTEM_ERROR2(SigEmptySetException());
            }
            sa.sa_flags = 0;
            for (const int s : {SIGPIPE, SIGXFSZ}) {
                r = sigaction(s, &sa, nullptr);
                if (r != 0) {
                    assert(r == -1);
                    NESTED_SYSTEM_ERROR2(SigActionException());
                }
            }

            r = sigaction(SIGPIPE, &sa, nullptr);
        }

        CommandLineArgs cmdLine{parseCommandLine(argc, argv)};
        const Configuration conf(cmdLine.configurationFilename);
        for (const auto & m : conf.moduleList()) {
            Module * const module = [&]() {
                try {
                    return new Module{modapi,
                                      m.filename.c_str(),
                                      m.configurationFile.c_str()};
                } catch (...) {
                    NESTED_THROW_CONCAT_EXCEPTION(
                                ModuleLoadException,
                                "Failed to load module",
                                m.filename);
                }
            }();
            try {
                module->init();
            } catch (...) {
                NESTED_THROW_CONCAT_EXCEPTION(
                            ModuleInitException,
                            "Failed to initialize module",
                            m.filename);
            }
        }
        SHAREMIND_SCOPE_EXIT(while (modapi.numPds() > 0u) delete modapi.pd(0u));
        for (const auto & pd : conf.protectionDomainList()) {
            Pdk * const pdk = modapi.findPdk(pd.kind.c_str());
            if (!pdk)
                throw PdkNotFoundException{};
            Pd * const protectionDomain = [&]() {
                try {
                    return new Pd{*pdk,
                                  pd.name.c_str(),
                                  pd.configurationFile.c_str()};
                } catch (...) {
                    NESTED_THROW_CONCAT_EXCEPTION(
                                PdCreateException,
                                "Failed to create protection domain",
                                pd.name);
                }
            }();
            try {
                protectionDomain->start();
            } catch (...) {
                NESTED_THROW_CONCAT_EXCEPTION(
                            PdStartException,
                            "Failed to start protection domain",
                            pd.name);
            }
        }

        Vm vm{[](const char * name) -> SharemindSyscallWrapper {
                  const auto it = staticSyscallWrappers.find(name);
                  if (it != staticSyscallWrappers.end())
                      return it->second;
                  return modapi.syscallWrapper(name);
              },
              [](const char * name) -> SharemindPd * {
                  Pd * const pd = modapi.findPd(name);
                  return pd ? pd->cPtr() : nullptr;
              }};
        Program program{vm};
        try {
            program.loadFromFile(cmdLine.bytecodeFilename);
        } catch (const Program::Exception & e) {
            const auto pos =
                    static_cast<const char *>(program.lastParsePosition());
            if (e.code() == SHAREMIND_VM_PREPARE_UNDEFINED_BIND) {
                std::cerr << "System call binding was: " << pos << std::endl;
            } else if (e.code() == SHAREMIND_VM_PREPARE_UNDEFINED_PDBIND) {
                std::cerr << "Protection domain binding was: " << pos
                          << std::endl;
            }
            throw;
        }

        const int fd = [&cmdLine] {
            if (!cmdLine.outFilename) {
                assert(processResultsStream == STDOUT_FILENO);
                return -1;
            }
            const int fd = openOutFile(cmdLine.outFilename,
                                       cmdLine.outOpenFlag);
            processResultsStream = fd;
            return fd;
        }();
        SHAREMIND_SCOPE_EXIT(if (fd != -1) ::close(fd));

        {
            Process process{program};
            try {
                process.run();
            } catch (...) {
                std::cerr << "At section " << process.currentCodeSection()
                          << ", block " << process.currentIp() << '.'
                          << std::endl;
                throw;
            }

            std::cerr << "Process returned status: " << process.returnValue()
                      << std::endl;
        }
    } catch (const std::exception & e) {
        printException(e);
        return EXIT_FAILURE;
    } catch (const GracefulException &) {
        return EXIT_SUCCESS;
    }

    return EXIT_SUCCESS;
}
