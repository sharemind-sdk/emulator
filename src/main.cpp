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
#include <cstring>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <iostream>
#include <iosfwd>
#include <boost/iostreams/categories.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <memory>
#include <sharemind/Concat.h>
#include <sharemind/EndianMacros.h>
#include <sharemind/Exception.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <sharemind/libvm/libvmcxx.h>
#include <sharemind/ScopeExit.h>
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

const char * programName = nullptr;

struct CommandLineArgs {
    bool justExit = false;
    std::vector<char> preInput;
    bool argsFromStdin = false;
    const char * configurationFilename = nullptr;
    const char * bytecodeFilename = nullptr;
    const char * outFilename = nullptr;
    bool forceOutFile = false;
};

SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, UsageException);
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     PdkNotFoundException,
                                     "Protection domain kind not found!");
SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(std::exception,
                                     InputStringTooBigException,
                                     "Input string too big!");
SHAREMIND_DEFINE_EXCEPTION_CONCAT(std::exception, OutputFileOpenException);
struct GracefulException {};
struct WriteIntegralArgumentException {};

template <typename T>
inline void writeIntegralArgument(std::vector<char> & v,
                                  T value,
                                  bool bigEndian = false) {
    value = bigEndian ? hostToBigEndian(value) : hostToLittleEndian(value);
    char data[sizeof(value)];
    memcpy(data, &value, sizeof(value));
    v.insert(v.end(), data, data + sizeof(value));
}

template <typename T>
inline void writeIntegralArgument(std::vector<char> & v,
                                  const char * const input,
                                  bool bigEndian = false)
{
    std::istringstream iss{std::string{input}};
    T integer;
    if ((iss >> integer).fail())
        throw WriteIntegralArgumentException{};
    writeIntegralArgument(v, integer, bigEndian);
}

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
                r.argsFromStdin = true;
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
                r.preInput.insert(r.preInput.end(),
                                  str,
                                  str + size);
            } else if (strncmp(argv[i] + 1u, "-xstr=", 6u) == 0) {
                for (const char * str = argv[i] + 7u; *str; str += 2u) {
                    const auto getVal = [&](const char s) {
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
                    r.preInput.push_back((getVal(*str) * 0xf)
                                         + getVal(*(str + 1u)));
                }
            }
            #define PROCESS_INTARG__(argname,type,big) \
                else if (strncmp(argv[i] + 1u, \
                                 "-" argname "=", \
                                 1u + sizeof(argname)) == 0) \
                { \
                    try { \
                        writeIntegralArgument<type ## _t>( \
                                r.preInput, \
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
                writeIntegralArgument<uint64_t>(r.preInput, argv[i] + 7u);
            } else if (strncmp(argv[i] + 1u, "-str=", 5u) == 0) {
                const char * const str = argv[i] + 6u;
                const auto size = strlen(str);
                if (size > std::numeric_limits<uint64_t>::max())
                    throw InputStringTooBigException{};
                writeIntegralArgument(r.preInput,
                                      static_cast<uint64_t>(size));
                r.preInput.insert(r.preInput.end(),
                                  str,
                                  str + size);
            } else if (strncmp(argv[i] + 1u, "-cfile=", 7u) == 0) {
                char * const realPath = ::realpath(argv[i] + 8u, nullptr);
                if (!realPath)
                    throw std::system_error(errno, std::system_category());
                SHAREMIND_SCOPE_EXIT(::free(realPath));
                std::ifstream f(realPath, std::ios::in | std::ios::binary);
                r.preInput.insert(r.preInput.end(),
                                  std::istreambuf_iterator<char>(f),
                                  std::istreambuf_iterator<char>());
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

class MySource {

public: /* Types: */

    using char_type = typename std::istream::char_type;
    using category = boost::iostreams::source_tag;

public: /* Methods: */

    inline MySource(const char_type * data,
                    const size_t size,
                    std::istream * inputStream)
        : m_preInput(data)
        , m_preInputLeft(size)
        , m_inputStream(inputStream)
    {}

    std::streamsize read(char_type * dest, std::streamsize n) {
        using uss = std::make_unsigned<decltype(n)>::type;
        assert(n > 0);
        std::streamsize r;
        if (m_preInputLeft > 0u) {
            if (m_preInputLeft >= static_cast<uss>(n)) {
                std::copy(m_preInput, m_preInput + n, dest);
                if (m_preInputLeft == static_cast<uss>(n)) {
                    m_preInputLeft = 0u;
                } else {
                    m_preInput += n;
                    m_preInputLeft -= n;
                }
                return n;
            }

            r = m_preInputLeft;
            std::copy(m_preInput, m_preInput + r, dest);
            m_preInputLeft = 0u;
            if (!m_inputStream)
                return r;
            n -= r;
            assert(n > 0);
            dest += r;
        } else {
            if (!m_inputStream)
                return -1;
            r = 0;
        }
        try {
            const auto oldExcept = m_inputStream->exceptions();
            m_inputStream->exceptions(std::ios::eofbit
                                      | std::ios::failbit
                                      | std::ios::badbit);
            try {
                return r + m_inputStream->readsome(dest, n);
            } catch (const std::ios_base::failure &) {
                m_inputStream->exceptions(oldExcept);
                if (m_inputStream->eof())
                    return r ? r : -1;
                throw;
            } catch (...) {
                m_inputStream->exceptions(oldExcept);
                throw;
            }
        } catch (...) {
            if (r)
                return r;
            throw;
        }
    }

private: /* Fields: */

    const char_type * m_preInput;
    size_t m_preInputLeft;
    std::istream * m_inputStream;

};
using MySourceStream = boost::iostreams::stream<MySource>;


} // namespace sharemind {

int main(int argc, char * argv[]) {
    using namespace sharemind;
    try {
        const CommandLineArgs cmdLine{parseCommandLine(argc, argv)};

        static const constexpr auto noStdCin =
                static_cast<decltype(&std::cin)>(nullptr);
        {
            MySourceStream myInput{cmdLine.preInput.data(),
                                   cmdLine.preInput.size(),
                                   cmdLine.argsFromStdin ? &std::cin : noStdCin};
            ProcessArguments::instance.init(myInput);
        }

        const Configuration conf(cmdLine.configurationFilename);

        for (const auto & m : conf.moduleList())
            (new Module(modapi,
                        m.filename.c_str(),
                        m.configurationFile.c_str()))->init();
        const auto destroyPds = []{
            while (modapi.numPds() > 0u)
                delete modapi.pd(0u);
        };
        try {
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
                    std::cerr << "System call binding was: " << pos
                              << std::endl;
                } else if (e.code() == SHAREMIND_VM_PREPARE_UNDEFINED_PDBIND) {
                    std::cerr << "Protection domain binding was: " << pos
                              << std::endl;
                }
                throw;
            }

            const int fd = [&cmdLine] {
                if (!cmdLine.outFilename) {
                    assert(ProcessResults::outputStream == STDOUT_FILENO);
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
                                        "Unable to open given output file!",
                                        "Unable to open given output file: ",
                                        cmdLine.outFilename));
                    }
                }
                ProcessResults::outputStream = fd;
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

                std::cerr << "Process returned status: "
                          << process.returnValue() << std::endl;
            }
            destroyPds();
        } catch (...) {
            destroyPds();
            throw;
        }
    } catch (const std::exception & e) {
        printException(e);
        return EXIT_FAILURE;
    } catch (const GracefulException &) {
        return EXIT_SUCCESS;
    }

    return EXIT_SUCCESS;
}
