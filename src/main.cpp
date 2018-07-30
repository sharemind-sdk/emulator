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

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fstream>
#include <ios>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <sharemind/AccessControlProcessFacility.h>
#include <sharemind/compiler-support/GccNoreturn.h>
#include <sharemind/Concat.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/libexecutable/Executable.h>
#include <sharemind/libfmodapi/FacilityModuleApi.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <sharemind/libprocessfacility.h>
#include <sharemind/libvm/Program.h>
#include <sharemind/libvm/Process.h>
#include <sharemind/libvm/Vm.h>
#include <sharemind/MakeUnique.h>
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/ScopeExit.h>
#include <sharemind/SimpleUnorderedStringMap.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>
#include "AccessPolicy.h"
#include "CommandLineArguments.h"
#include "EmulatorException.h"
#include "EmulatorConfiguration.h"
#include "Syscalls.h"


using sharemind::assertReturn;
using sharemind::Executable;
using sharemind::FacilityModuleApi;
using sharemind::makeUnique;
using sharemind::Module;
using sharemind::ModuleApi;
using sharemind::Pd;
using sharemind::Pdpi;
using sharemind::Program;
using sharemind::Process;
using sharemind::SimpleUnorderedStringMap;
using sharemind::Vm;

namespace {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"
#endif
DEFINE_EXCEPTION_STR(FacilityModuleLoadException);
DEFINE_EXCEPTION_STR(ModuleLoadException);
DEFINE_EXCEPTION_STR(ModuleInitException);
DEFINE_EXCEPTION_STR(PdCreateException);
DEFINE_EXCEPTION_STR(PdStartException);
DEFINE_EXCEPTION_CONST_MSG(PdkNotFoundException,
                           "Protection domain kind not found!");
DEFINE_EXCEPTION_CONST_MSG(MultipleLinkingUnitsNotSupportedException,
                           "Sharemind Executables with multiple linking units "
                           "are currently not supported!");
DEFINE_EXCEPTION_STR(UndefinedPdBindException);
DEFINE_EXCEPTION_STR(ProgramLoadException);
DEFINE_EXCEPTION_CONST_MSG(SigEmptySetException, "sigemptyset() failed!");
DEFINE_EXCEPTION_CONST_MSG(SigActionException, "sigaction() failed!");
DEFINE_EXCEPTION_CONST_MSG(ModuleImplementationLimitsReachedException,
                           "Module implementation limits reached!");
DEFINE_EXCEPTION_CONST_MSG(ModuleErrorException, "Programming fault in the module!");
DEFINE_EXCEPTION_CONST_MSG(ModuleGeneralErrorException,
                           "General runtime error in the module!");
DEFINE_EXCEPTION_CONST_MSG(ModuleInvalidCallException,
                           "The system call was called improperly by the "
                           "bytecode!");
DEFINE_EXCEPTION_CONST_MSG(ModuleMissingFacilityException,
                           "A required facility was not provided by "
                           "Sharemind!");
DEFINE_EXCEPTION_CONST_MSG(ModuleInvalidPdConfiguration,
                           "The protection domain configuration given was "
                           "invalid or erroneous!");
DEFINE_EXCEPTION_CONST_MSG(ModuleInvalidModuleConfiguration,
                           "The module configuration given was invalid or "
                           "erroneous!");
DEFINE_EXCEPTION_CONST_MSG(ModuleAccessDeniedException,
                           "Access denied by module!");
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#pragma GCC diagnostic pop

inline void printException_(std::exception const & e,
                            std::size_t const levelNow,
                            std::size_t & totalLevels) noexcept
{
    try {
        std::rethrow_if_nested(e);
    } catch (std::exception const & e2) {
        printException_(e2, levelNow + 1u, ++totalLevels);
    }
    std::cerr << "Error " << (totalLevels - levelNow + 1u) << " of "
              << totalLevels << ": " << e.what() << std::endl;
}

inline void printException(std::exception const & e) noexcept {
    std::size_t levels = 1u;
    printException_(e, 1u, levels);
}

FacilityModuleApi fmodapi;
ModuleApi modapi;

std::uint64_t const localPid = 0u;

class Pdpis {

public: /* Methods: */

    void addPdpi(std::shared_ptr<Pd> pdPtr,
                 std::shared_ptr<FacilityModuleApi::PdpiFacilityFinder> ff)
    {
        assert(ff);
        struct SmartPdpi {
            SmartPdpi(std::shared_ptr<Pd> pdPtr_,
                      std::shared_ptr<FacilityModuleApi::PdpiFacilityFinder> ff)
                : pdPtr(std::move(pdPtr_))
                , pdpi(*pdPtr)
            {
                pdpiFacilities.reserve(ff->pdpiFacilityMap().size());
                for (auto const & fp : ff->pdpiFacilityMap()) {
                    pdpi.setFacility(fp.first.c_str(), fp.second.get());
                    pdpiFacilities.emplace_back(std::move(fp.second));
                }
            }
            std::shared_ptr<Pd> pdPtr;

            /** \todo Remove this when libmodapi supports passing facilities by
                      smart pointers: */
            std::vector<std::shared_ptr<void> > pdpiFacilities;
            Pdpi pdpi;
        };
        auto smartPdpi(std::make_shared<SmartPdpi>(std::move(pdPtr),
                                                   std::move(ff)));
        auto & pdpi = smartPdpi->pdpi;
        m_pdpis.emplace_back(
                    std::shared_ptr<Pdpi>(std::move(smartPdpi), &pdpi));
    }

    void startAll() {
        m_pdpiInfos.resize(m_pdpis.size());
        auto infoIt = m_pdpiInfos.begin();
        for (auto it = m_pdpis.begin(); it != m_pdpis.end(); ++it, ++infoIt) {
            try {
                auto & pdpi = **it;
                pdpi.start();
                infoIt->pdpiHandle = pdpi.handle();
                infoIt->pdHandle = pdpi.pd()->handle();
                infoIt->pdkIndex = pdpi.pdk()->index();
                infoIt->moduleHandle = pdpi.module()->handle();
            } catch (...) {
                while (it != m_pdpis.begin())
                    (*--it)->stop();
                throw;
            }
        }
    }

    void stopAllAndClear() noexcept {
        for (auto const & pdpi : m_pdpis)
            pdpi->stop();
        m_pdpis.clear();
    }

    void clear() noexcept { m_pdpis.clear(); }

    SharemindModuleApi0x1PdpiInfo const * pdpiInfo(std::size_t index)
            const noexcept
    {
        if (index < m_pdpiInfos.size())
            return std::addressof(m_pdpiInfos[index]);
        return nullptr;
    }

private: /* Fields: */

    std::vector<std::shared_ptr<Pdpi> > m_pdpis;
    std::vector<SharemindModuleApi0x1PdpiInfo> m_pdpiInfos;

} pdpis;

class OldSyscallContext final: public SharemindModuleApi0x1SyscallContext {

public: /* Types: */

    using PublicMemoryPointer = Vm::SyscallContext::PublicMemoryPointer;

public: /* Methods: */

    OldSyscallContext(Vm::SyscallContext & context, void * moduleHandle)
        : SharemindModuleApi0x1SyscallContext{
              &context,
              nullptr, // process_internal
              moduleHandle,
              &get_pdpi_info,
              &processFacility,
              &publicAlloc,
              &publicFree,
              &publicMemPtrSize,
              &publicMemPtrData,
              &allocPrivate,
              &freePrivate,
              &reservePrivate,
              &releasePrivate}
    {}

    static SharemindModuleApi0x1PdpiInfo const * get_pdpi_info(
            SharemindModuleApi0x1SyscallContext *,
            std::uint64_t pd_index)
    { return pdpis.pdpiInfo(pd_index); }

    static void * processFacility(
            SharemindModuleApi0x1SyscallContext const * c,
            char const * facilityName)
    {
        if (auto r = fromC(c).processFacility(facilityName))
            return r.get();
        return nullptr;
    }

    static std::uint64_t publicAlloc(SharemindModuleApi0x1SyscallContext * c,
                                     std::uint64_t nBytes)
    { return fromC(c).publicAlloc(nBytes).ptr; }

    static bool publicFree(SharemindModuleApi0x1SyscallContext * c,
                           std::uint64_t ptr)
    { return fromC(c).publicFree(PublicMemoryPointer{ptr}); }

    static std::size_t publicMemPtrSize(SharemindModuleApi0x1SyscallContext * c,
                                        std::uint64_t ptr)
    { return fromC(c).publicMemPtrSize(PublicMemoryPointer{ptr}); }

    static void * publicMemPtrData(SharemindModuleApi0x1SyscallContext * c,
                                   std::uint64_t ptr)
    { return fromC(c).publicMemPtrData(PublicMemoryPointer{ptr}); }

    /* Access to dynamic memory not exposed to VM instructions: */
    static void * allocPrivate(SharemindModuleApi0x1SyscallContext *,
                               std::size_t)
    { return nullptr; }

    static void freePrivate(SharemindModuleApi0x1SyscallContext *, void *) {}

    static bool reservePrivate(SharemindModuleApi0x1SyscallContext *,
                               std::size_t)
    { return false; }

    static bool releasePrivate(SharemindModuleApi0x1SyscallContext *,
                               std::size_t)
    { return false; }

private: /* Methods: */

    static Vm::SyscallContext & fromC(
            SharemindModuleApi0x1SyscallContext * const c) noexcept
    {
        return *static_cast<Vm::SyscallContext *>(
                    assertReturn(assertReturn(c)->vm_internal));
    }

    static Vm::SyscallContext const & fromC(
            SharemindModuleApi0x1SyscallContext const * const c) noexcept
    {
        return *static_cast<Vm::SyscallContext const *>(
                    assertReturn(assertReturn(c)->vm_internal));
    }

};

class OldSyscallWrapper final: public Vm::SyscallWrapper {

public: /* Methods: */

    OldSyscallWrapper(sharemind::SyscallWrapper wrapper)
        : m_wrapper(std::move(wrapper))
    {}

    void operator()(
            std::vector<::SharemindCodeBlock> & arguments,
            std::vector<Vm::Reference> & references,
            std::vector<Vm::ConstReference> & creferences,
            ::SharemindCodeBlock * returnValue,
            Vm::SyscallContext & context) const final override
    {
        OldSyscallContext ctx(context, m_wrapper.internal);

        #define HANDLE_REFS(which,oldClass) \
            std::array<oldClass, 11u> which ## sOnStack; \
            std::unique_ptr<oldClass[]> which ## onHeap; \
            oldClass * which ## s; \
            if (which ## erences.empty()) { \
                which ## s = nullptr; \
            } else { \
                if (which ## erences.size() < which ## sOnStack.size()) { \
                    which ## s = which ## sOnStack.data(); \
                } else { \
                    if (which ## erences.size() \
                        == std::numeric_limits<std::size_t>::max()) \
                        throw std::bad_array_new_length(); \
                    which ## onHeap = \
                        makeUnique<oldClass[]>(which ## erences.size() + 1u); \
                    which ## s = which ## onHeap.get(); \
                } \
                auto ptr = which ## s; \
                for (auto const & which : which ## erences) { \
                    ptr->pData = which.data.get(); \
                    ptr->size = which.size; \
                    ++ptr; \
                } \
                ptr->pData = nullptr; \
                ptr->size = 0u; \
            }

        HANDLE_REFS(ref,  ::SharemindModuleApi0x1Reference)
        HANDLE_REFS(cref, ::SharemindModuleApi0x1CReference)
        #undef HANDLE_REFS

        auto const r = m_wrapper.callable(arguments.data(),
                                          arguments.size(),
                                          refs,
                                          crefs,
                                          returnValue,
                                          &ctx);

        switch (r) {
        case SHAREMIND_MODULE_API_0x1_OK:
            return;
        case SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY:
            throw std::bad_alloc();
        case SHAREMIND_MODULE_API_0x1_IMPLEMENTATION_LIMITS_REACHED:
            throw ModuleImplementationLimitsReachedException();
        case SHAREMIND_MODULE_API_0x1_MODULE_ERROR:
            throw ModuleErrorException();
        case SHAREMIND_MODULE_API_0x1_GENERAL_ERROR:
            throw ModuleGeneralErrorException();
        case SHAREMIND_MODULE_API_0x1_INVALID_CALL:
            throw ModuleInvalidCallException();
        case SHAREMIND_MODULE_API_0x1_MISSING_FACILITY:
            throw ModuleMissingFacilityException();
        case SHAREMIND_MODULE_API_0x1_INVALID_PD_CONFIGURATION:
            throw ModuleInvalidPdConfiguration();
        case SHAREMIND_MODULE_API_0x1_INVALID_MODULE_CONFIGURATION:
            throw ModuleInvalidModuleConfiguration();
        case SHAREMIND_MODULE_API_0x1_ACCESS_DENIED:
            throw ModuleAccessDeniedException();
        }
    }

private: /* Fields: */

    sharemind::SyscallWrapper m_wrapper;

};

SharemindProcessFacility vmProcessFacility{
    [](const SharemindProcessFacility *) noexcept { return "0"; },
    [](const SharemindProcessFacility *) noexcept -> void const *
            { return &localPid; },
    [](const SharemindProcessFacility *) noexcept
            { return sizeof(localPid); },
    [](const SharemindProcessFacility *) noexcept -> void const *
            { return &localPid; },
    [](const SharemindProcessFacility *) noexcept -> SharemindGlobalIdSizeType
    {
        static_assert(sizeof(localPid)
                      <= std::numeric_limits<SharemindGlobalIdSizeType>::max(),
                      "");
        return sizeof(localPid);
    },
    [](const SharemindProcessFacility *) noexcept -> char const *
            { return ""; },
    [](const SharemindProcessFacility *) noexcept -> char const *
            { return ""; }
};

class AccessControlProcessFacilityImpl final
        : public sharemind::AccessControlProcessFacility
{

public: /* Types: */

    using ObjectPermissionsNamespaces =
            AccessPolicy::ObjectPermissionsNamespaces;

public: /* Methods: */

    AccessControlProcessFacilityImpl(EmulatorConfiguration const & conf,
                                     std::string const & user) noexcept
        : m_perms(
            [&conf, &user]() noexcept {
                auto const & userMapping = conf.accessPolicy().userMapping();
                auto const it = userMapping.find(user);
                return (it != userMapping.end()) ? it->second : nullptr;
            }())
    {}

    std::shared_ptr<ObjectPermissions const> getCurrentPermissions(
            PreparedPredicate const & rulesetNamePredicate) const final override
    {
        if (!m_perms)
            return nullptr;
        auto const it = m_perms->find(rulesetNamePredicate);
        if (it == m_perms->end())
            return nullptr;
        return std::shared_ptr<ObjectPermissions const>(m_perms, &it->second);
    }

private: /* Fields: */

    std::shared_ptr<ObjectPermissionsNamespaces> m_perms;

};

} // anonymous namespace

int main(int argc, char * argv[]) {
    try {
        {
            struct sigaction sa;
            sa.sa_handler = SIG_IGN;
            auto r = sigemptyset(&sa.sa_mask);
            if (r != 0) {
                assert(r == -1);
                NESTED_SYSTEM_ERROR2(SigEmptySetException{});
            }
            sa.sa_flags = 0;
            for (int const s : {SIGPIPE, SIGXFSZ}) {
                r = sigaction(s, &sa, nullptr);
                if (r != 0) {
                    assert(r == -1);
                    NESTED_SYSTEM_ERROR2(SigActionException{});
                }
            }

            r = sigaction(SIGPIPE, &sa, nullptr);
        }

        auto const cmdLine(parseCommandLine(argc, argv));
        if (cmdLine.justExit)
            return EXIT_SUCCESS;

        std::shared_ptr<EmulatorConfiguration const> conf(
                    cmdLine.configurationFilename
                    ? makeUnique<EmulatorConfiguration>(
                          cmdLine.configurationFilename)
                    : makeUnique<EmulatorConfiguration>());
        AccessControlProcessFacilityImpl aclFacility(*conf,
                                                     cmdLine.user
                                                     ? cmdLine.user
                                                     : conf->defaultUser());
        for (auto const & fm : conf->facilityModuleList()) {
            try {
                fmodapi.addModule(fm.filename, fm.configurationFile);
            } catch (...) {
                throwWithNestedConcatException<FacilityModuleLoadException>(
                            "Failed to load facility module \"",
                            fm.filename,
                            "\"!");
            }
        }

        /** \todo Remove this when libmodapi supports passing facilities by
                  smart pointers: */
        std::map<Module *,
                 std::pair<decltype(fmodapi.createModuleFacilityFinder()),
                           std::vector<std::shared_ptr<void> > > >
                moduleFacilityInfo;
        for (auto const & m : conf->moduleList()) {
            Module & module = [&]() -> Module & {
                try {
                    return modapi.loadModule(m.filename.c_str(),
                                             m.configurationFile.c_str());
                } catch (...) {
                    throwWithNestedConcatException<ModuleLoadException>(
                                "Failed to load module \"",
                                m.filename,
                                "\"!");
                }
            }();
            try {
                auto moduleFacilityFinder(fmodapi.createModuleFacilityFinder());
                auto const & facilityMap(
                            moduleFacilityFinder->moduleFacilityMap());
                std::vector<std::shared_ptr<void> > facilities;
                facilities.reserve(facilityMap.size());
                for (auto & fp : facilityMap) {
                    module.setFacility(fp.first.c_str(), fp.second.get());
                    facilities.emplace_back(std::move(fp.second));
                }
                using P = decltype(moduleFacilityInfo)::value_type::second_type;
                moduleFacilityInfo.emplace(
                            &module,
                            P(std::piecewise_construct,
                              std::make_tuple(std::move(moduleFacilityFinder)),
                              std::make_tuple(std::move(facilities))));
                module.init();
            } catch (...) {
                throwWithNestedConcatException<ModuleInitException>(
                            "Failed to initialize module \"",
                            m.filename,
                            "\"!");
            }

            /// \todo Should the module be destroyed, these are left dangling:
            for (std::size_t i = 0u; i < module.numSyscalls(); ++i) {
                auto * syscall = module.syscall(i);
                assert(syscall);
                syscallWrappers.emplace(
                            syscall->signature(),
                            std::make_shared<OldSyscallWrapper>(
                                syscall->wrapper()));
            }
        }

        modapi.setPdpiFacility("ProcessFacility", &vmProcessFacility);

        /** \todo Remove this when libmodapi supports passing facilities by
                  smart pointers: */
        std::map<Pd *,
                 std::pair<
                        std::shared_ptr<FacilityModuleApi::PdFacilityFinder>,
                        std::vector<std::shared_ptr<void> > > >
                pdFacilityInfo;
        SimpleUnorderedStringMap<std::shared_ptr<Pd> > pds;
        for (auto const & pd : conf->protectionDomainList()) {
            auto * const pdk = modapi.findPdk(pd.kind.c_str());
            if (!pdk)
                throw PdkNotFoundException{};
            auto protectionDomain([&]() {
                try {
                    return std::make_shared<Pd>(*pdk,
                                                pd.name.c_str(),
                                                pd.configurationFile.c_str());
                } catch (...) {
                    throwWithNestedConcatException<PdCreateException>(
                                "Failed to create protection domain \"",
                                pd.name,
                                "\"!");
                }
            }());
            try {
                assert(moduleFacilityInfo.find(protectionDomain->module())
                       != moduleFacilityInfo.end());
                auto pdFacilityFinder(
                        fmodapi.createPdFacilityFinder(
                            moduleFacilityInfo[
                                protectionDomain->module()].first));
                auto const & facilityMap(
                            pdFacilityFinder->pdFacilityMap());
                std::vector<std::shared_ptr<void> > facilities;
                facilities.reserve(facilityMap.size());
                for (auto & fp : facilityMap) {
                    protectionDomain->setFacility(fp.first.c_str(),
                                                  fp.second.get());
                    facilities.emplace_back(std::move(fp.second));
                }
                using P = decltype(pdFacilityInfo)::value_type::second_type;
                pdFacilityInfo.emplace(
                            protectionDomain.get(),
                            P(std::piecewise_construct,
                              std::make_tuple(std::move(pdFacilityFinder)),
                              std::make_tuple(std::move(facilities))));
                protectionDomain->start();
            } catch (...) {
                throwWithNestedConcatException<PdStartException>(
                            "Failed to start protection domain \"",
                            pd.name,
                            "\"!");
            }
            pds.emplace(std::piecewise_construct,
                        std::make_tuple(pd.name),
                        std::make_tuple(std::move(protectionDomain)));
        }

        Vm vm;
        vm.setSyscallFinder(
                    [](std::string const & name) {
                        auto const it = syscallWrappers.find(name);
                        return (it != syscallWrappers.end())
                                ? it->second
                                : nullptr;
                    });


        Program program;
        try {
            Executable executable;
            {
                std::ifstream exeFile(cmdLine.bytecodeFilename);
                exeFile >> executable;
            }
            {
                if (executable.linkingUnits.size() > 1u)
                    throw MultipleLinkingUnitsNotSupportedException();
                auto const & linkingUnit = executable.linkingUnits.front();
                if (auto s = std::move(linkingUnit.pdBindingsSection)) {
                    auto const & pdBindings = s->pdBindings;
                    for (auto it = pdBindings.begin();
                         it != pdBindings.end();
                         ++it)
                    {
                        auto const pdIt(pds.find(*it));
                        if (pdIt == pds.end()) {
                            pdpis.clear();
                            std::ostringstream oss;
                            oss << "Found bindings for undefined protection "
                                   "domains: " << *it;
                            while (++it != pdBindings.end())
                                if (pds.find(*it) == pds.end())
                                    oss << ", " << *it;
                            throw UndefinedPdBindException(oss.str());
                        }
                        assert(pdFacilityInfo.find(pdIt->second.get())
                               != pdFacilityInfo.end());
                        pdpis.addPdpi(
                                pdIt->second,
                                fmodapi.createPdpiFacilityFinder(
                                    pdFacilityInfo[pdIt->second.get()].first));
                    }
                }
            }

            program = Program(vm, std::move(executable));
        } catch (...) {
            throwWithNestedConcatException<ProgramLoadException>(
                        "Failed to load program bytecode \"",
                        cmdLine.bytecodeFilename,
                        "\"!");
        }

        int const fd = [&cmdLine] {
            if (!cmdLine.outFilename) {
                assert(processResultsStream == STDOUT_FILENO);
                return -1;
            }
            int const fd_ = openOutFile(cmdLine.outFilename,
                                        cmdLine.outOpenFlag);
            processResultsStream = fd_;
            return fd_;
        }();
        SHAREMIND_SCOPE_EXIT(if (fd != -1) ::close(fd));

        {
            auto processFacilities(
                fmodapi.createProcessFacilityFinder()->processFacilityMap());
            processFacilities.emplace("ProcessFacility",
                                      std::shared_ptr<void>(
                                          std::shared_ptr<void>(),
                                          &vmProcessFacility));
            processFacilities.emplace("AccessControlProcessFacility",
                                      std::shared_ptr<void>(
                                          std::shared_ptr<void>(),
                                          &aclFacility));

            Process process(program);
            process.setFacilityFinder(
                        [&processFacilities](char const * name) noexcept
                                -> std::shared_ptr<void>
                        {
                            auto const it(processFacilities.find(name));
                            if (it != processFacilities.end())
                                return it->second;
                            return nullptr;
                        });

            pdpis.startAll();
            try {
                process.run();
            } catch (...) {
                pdpis.stopAllAndClear();
                std::cerr << "At section " << process.currentCodeSectionIndex()
                          << ", block 0x"
                          << std::hex << process.currentIp() << std::dec
                          << '.' << std::endl;
                throw;
            }
            pdpis.stopAllAndClear();

            std::cerr << "Process returned status: "
                      << process.returnValue().int64[0] << std::endl;
        }
    } catch (std::exception const & e) {
        printException(e);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
