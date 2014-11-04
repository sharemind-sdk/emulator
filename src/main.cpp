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
#include <sharemind/Concat.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/Exception.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <sharemind/libvm/libvmcxx.h>
#include <sharemind/ScopeExit.h>
#include <sstream>
#include <sys/stat.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
#include "Configuration.h"
#include "Syscalls.h"


/// \todo handle SIGXFSZ and SIGPIPE

#ifndef SHAREMIND_EMULATOR_VERSION
#error SHAREMIND_EMULATOR_VERSION not defined!
#endif

namespace sharemind {


SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, UsageException);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     PdkNotFoundException,
                                     "Protection domain kind not found!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     InputStringTooBigException,
                                     "Input string too big!");
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, OutputFileOpenException);
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, InputFileOpenException);
struct GracefulException {};
struct WriteIntegralArgumentException {};

const char * programName = nullptr;

SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     InputException,
                                     "Invalid input to program!");

struct InputData {
    virtual ~InputData() noexcept {}
    virtual size_t read(void * buf, size_t size) = 0;
};

class FileInputData final: public InputData {

public: /* Methods: */

    inline FileInputData(const int fd) : m_fd(fd) {}
    inline FileInputData(const char * const filename) : m_fd(open(filename)) {}
    inline ~FileInputData() noexcept final override { ::close(m_fd); }

    inline size_t read(void * buf, size_t size) final override {
        assert(size > 0u);
        for (;;) {
            const ssize_t r = ::read(m_fd, buf, size);
            if (r >= 0)
                return r;
            assert(r == -1);
            if ((errno != EAGAIN) && (errno != EINTR))
                throw std::system_error(errno, std::system_category());
        }
    }

    static int open(const char * filename) {
        char * const realPath = ::realpath(filename, nullptr);
        if (!realPath)
            throw std::system_error(errno, std::system_category());
        SHAREMIND_SCOPE_EXIT(::free(realPath));
        const int fd = ::open(realPath, O_RDONLY);
        if (fd != -1)
            return fd;
        try {
            throw std::system_error(errno, std::system_category());
        } catch (...) {
            std::throw_with_nested(
                        InputFileOpenException(
                            "Unable to open() given input file!",
                            "Unable to open() given input file: ",
                            filename));
        }
    }

private: /* Fields: */

    int m_fd;

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

private: /* Fields: */

    std::vector<char> m_data;
    size_t m_pos = 0u;

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
                    const auto bit = new BufferInputData();
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
        const auto fit = new FileInputData(std::forward<Args>(args)...);
        try {
            m_data.push_back(fit);
            m_state = FILE;
        } catch (...) {
            delete fit;
            throw;
        }
    }

    template <typename T>
    inline void writeIntegral(T value, bool bigEndian = false) {
        value = bigEndian ? hostToBigEndian(value) : hostToLittleEndian(value);
        char data[sizeof(value)];
        ::memcpy(data, &value, sizeof(value));
        writeData(data, data + sizeof(value));
    }

    template <typename T>
    inline void writeIntegral(const char * const input, bool bigEndian = false)
    {
        std::istringstream iss{std::string{input}};
        T integer;
        if ((iss >> integer).fail())
            throw WriteIntegralArgumentException{};
        writeIntegral(integer, bigEndian);
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
                            args.emplace(std::move(argName), value);
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

private: /* Fields: */

    State m_state = INIT;
    std::list<InputData *> m_data;

};

struct CommandLineArgs {
    bool justExit = false;
    InputStream inputData;
    const char * configurationFilename = nullptr;
    const char * bytecodeFilename = nullptr;
    const char * outFilename = nullptr;
    bool forceOutFile = false;
};

inline void printUsage() {
    using namespace std;
    cerr << "Usage: " << programName
         << " [OPTIONS] FILENAME" << endl
         << "Runs the bytecode specified by FILENAME in an execution context "
            "specified by the given configuration file given by the --conf= "
            "argument." << endl << endl
         << "Required arguments:" << endl << endl
         << "  --conf=FILENAME     Reads the configuration file from the given "
            "location." << endl << endl
         << "Optional arguments:" << endl << endl
         << "  --help, --usage     Display this help and exit."
         << endl << endl
         << "  --version           Output version information and exit."
         << endl << endl
         << "  --stdin             Continue reading the argument stream from "
            "stdin." << endl << endl
         << "  --cstr=STRING       Writes the literal STRING to the argument "
            "stream." << endl << endl
         << "  --xstr=HEXBYTES     Writes the given hexadecimal bytes to the "
            "argument stream." << endl << endl
         << "  --int16=VALUE, --int32=VALUE, --int64=VALUE, --uint16=VALUE"
            ", --uint32=VALUE, --uint64=VALUE" << endl
         << "                      Writes the decimal VALUE to the argument "
            "stream as a little-endian value of the respective type."
         << endl << endl
         << "  --bint16=VALUE, --bint32=VALUE, --bint64=VALUE, --buint16=VALUE"
            ", --buint32=VALUE, --buint64=VALUE" << endl
         << "                      Writes the decimal VALUE to the argument "
            "stream as a big-endian value of the respective type."
         << endl << endl
         << "  --size=VALUE        Identical to --uint64=VALUE." << endl << endl
         << "  --str=STRING        Identical to --size=VALUE --cstr=STRING, "
            "where VALUE is the length of the given STRING." << endl << endl
         << "  --cfile=FILENAME     Writes the given binary file to the "
            "argument stream." << endl << endl
         << "  --file=FILENAME     Identical to --size=VALUE --cfile=FILENAME, "
            "where VALUE is the size of the given file." << endl << endl
         << "  --outFile=FILENAME  Writes the output to the given file instead "
            "of the standard output." << endl << endl
         << "  --forceOutFile      Overwrites the file given by "
            "--outFile=FILENAME if the file already exists." << endl << endl;
}

inline CommandLineArgs parseCommandLine(const int argc,
                                        const char * const argv[])
{
    assert(argc >= 1);
    programName = argv[0u];
    CommandLineArgs r;
    for (size_t i = 1u; i < static_cast<size_t>(argc); i++) {
        if (argv[i][0u] == '-') {
            if ((strncmp(argv[i] + 1u, "-conf=", 6u) == 0)
                && (argv[i][7u] != '\0'))
            {
                if (r.configurationFilename)
                    throw UsageException{
                        "Multiple --conf=FILENAME arguments given!"};
                r.configurationFilename = argv[i] + 7u;
            } else if (strcmp(argv[i] + 1u, "-stdin") == 0) {
                r.inputData.writeFile(STDIN_FILENO);
            } else if ((strcmp(argv[i] + 1u, "-help") == 0)
                       || (strcmp(argv[i] + 1u, "-usage") == 0)) {
                printUsage();
                throw GracefulException{};
            } else if ((strcmp(argv[i] + 1u, "-version") == 0)) {
                std::cerr << "Emulator " SHAREMIND_EMULATOR_VERSION
                          << std::endl;
                throw GracefulException{};
            } else if (strncmp(argv[i] + 1u, "-cstr=", 6u) == 0) {
                const char * const str = argv[i] + 7u;
                const auto size = strlen(str);
                r.inputData.writeData(str, str + size);
            } else if (strncmp(argv[i] + 1u, "-xstr=", 6u) == 0) {
                for (const char * str = argv[i] + 7u; *str; str += 2u) {
                    const auto getVal = [=](const char s) {
                        switch (s) {
                        case 'a' ... 'f': return (s - 'a') + 0xa;
                        case 'A' ... 'F': return (s - 'A') + 0xA;
                        case '0' ... '9': return (s - '0') + 0x0;
                        default:
                            throw UsageException{
                                "Invalid --xstr=HEXBYTES argument given!",
                                "Invalid --xstr=HEXBYTES argument given: ",
                                argv[i]};
                        }
                    };
                    r.inputData.writeData((getVal(*str) * 0xf)
                                           + getVal(*(str + 1u)));
                }
            }
            #define PROCESS_INTARG__(argname,type,big) \
                else if (strncmp(argv[i] + 1u, \
                                 "-" argname "=", \
                                 1u + sizeof(argname)) == 0) \
                { \
                    try { \
                        r.inputData.writeIntegral<type ## _t>( \
                                argv[i] + 2u + sizeof(argname), \
                                (big)); \
                    } catch (const WriteIntegralArgumentException &) { \
                        throw UsageException{ \
                                    "Invalid --" argname "=VALUE argument " \
                                    "given!", \
                                    "Invalid --" argname "=VALUE argument " \
                                    "given: ", \
                                    argv[i]}; \
                    } \
                }
            #define PROCESS_INTARG(type) \
                PROCESS_INTARG__(#type,type,false) \
                PROCESS_INTARG__("b" #type,type,true)
            PROCESS_INTARG(int16)
            PROCESS_INTARG(int32)
            PROCESS_INTARG(int64)
            PROCESS_INTARG(uint16)
            PROCESS_INTARG(uint32)
            PROCESS_INTARG(uint64)
            else if (strncmp(argv[i] + 1u, "-size=", 6u) == 0) {
                r.inputData.writeIntegral<uint64_t>(argv[i] + 7u);
            } else if (strncmp(argv[i] + 1u, "-str=", 5u) == 0) {
                const char * const str = argv[i] + 6u;
                const auto size = strlen(str);
                if (size > std::numeric_limits<uint64_t>::max())
                    throw InputStringTooBigException{};
                r.inputData.writeIntegral(static_cast<uint64_t>(size));
                r.inputData.writeData(str, str + size);
            } else if (strncmp(argv[i] + 1u, "-cfile=", 7u) == 0) {
                r.inputData.writeFile(argv[i] + 8u);
            } else if (strncmp(argv[i] + 1u, "-file=", 6u) == 0) {
                const char * const fileName = argv[i] + 7u;
                const int fd = FileInputData::open(fileName);
                struct ::stat st;
                const auto ret = fstat(fd, &st);
                if (ret != 0) {
                    assert(ret == -1);
                    try {
                        throw std::system_error(errno, std::system_category());
                    } catch (...) {
                        std::throw_with_nested(
                                    InputFileOpenException(
                                        "Unable to fstat() given input file!",
                                        "Unable to fstat() given input file: ",
                                        fileName));
                    }
                }
                static_assert(std::numeric_limits<decltype(st.st_size)>::max()
                              <= std::numeric_limits<uint64_t>::max(),
                              "");
                const uint64_t size =
                        hostToLittleEndian(static_cast<uint64_t>(st.st_size));
                r.inputData.writeData(&size, sizeof(size));
                r.inputData.writeFile(fd);
            } else if (strncmp(argv[i] + 1u, "-outFile=", 9u) == 0) {
                if (r.outFilename)
                    throw UsageException{"Multiple --output=FILENAME "
                                         "arguments given!"};
                r.outFilename = argv[i] + 10u;
            } else if (strcmp(argv[i] + 1u, "-forceOutFile") == 0) {
                r.forceOutFile = true;
            } else {
                throw UsageException{"Unrecognized argument given!",
                                     "Unrecognized argument given: ",
                                     argv[i]};
            }
        } else {
            if (r.bytecodeFilename)
                throw UsageException{"Multiple bytecode FILENAME arguments "
                                     "given!"};
            r.bytecodeFilename = argv[i];
        }
    }
    if (!r.bytecodeFilename)
        throw UsageException{"No bytecode FILENAME argument given!"};
    if (!r.configurationFilename)
        throw UsageException{"No --conf=FILENAME argument given!"};
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
        CommandLineArgs cmdLine{parseCommandLine(argc, argv)};
        processArguments = cmdLine.inputData.readArguments();

        const Configuration conf(cmdLine.configurationFilename);

        for (const auto & m : conf.moduleList())
            (new Module(modapi,
                        m.filename.c_str(),
                        m.configurationFile.c_str()))->init();
        SHAREMIND_SCOPE_EXIT(while (modapi.numPds() > 0u) delete modapi.pd(0u));
        for (const auto & pd : conf.protectionDomainList()) {
            Pdk * const pdk = modapi.findPdk(pd.kind.c_str());
            if (!pdk)
                throw PdkNotFoundException{};
            (new Pd(*pdk, pd.name.c_str(), pd.configurationFile.c_str()))
                    ->start();
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
            const int openFlags = cmdLine.forceOutFile
                                ? O_WRONLY | O_CREAT | O_TRUNC
                                : O_WRONLY | O_CREAT | O_EXCL;
            const int fd = ::open(cmdLine.outFilename,
                                  openFlags,
                                  S_IRUSR | S_IWUSR | S_IRGRP);
            if (fd == -1) {
                try {
                    throw std::system_error(errno, std::system_category());
                } catch (...) {
                    std::throw_with_nested(
                                OutputFileOpenException(
                                    "Unable to open() given output file!",
                                    "Unable to open() given output file: ",
                                    cmdLine.outFilename));
                }
            }
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
