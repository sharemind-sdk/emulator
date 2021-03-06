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

#ifndef SHAREMIND_EMULATOR_EMULATORCONFIGURATION_H
#define SHAREMIND_EMULATOR_EMULATORCONFIGURATION_H

#include <sharemind/libconfiguration/Configuration.h>

#include <exception>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <string>
#include <utility>
#include <vector>
#include "AccessPolicy.h"


/** \brief Parses and stores the configuration for a miner from a file. */
class __attribute__ ((visibility("internal"))) EmulatorConfiguration
    : public sharemind::Configuration
{

public: /* Types: */

    SHAREMIND_DECLARE_EXCEPTION_NOINLINE(sharemind::Exception, Exception);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception, ParseException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   AccessPolicyLoadException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   DuplicatePdNameException);
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(Exception,
                                                   EmptyPdNameException);

    struct FacilityModuleEntry {
        std::string filename;
        std::string configurationFile;
    };

    struct ModuleEntry {
        std::string filename;
        std::string configurationFile;
    };

    struct ProtectionDomainEntry {
        std::string name;
        std::string kind;
        std::string configurationFile;
    };

public: /* Methods: */

    /**
     * \brief Attempts to the miner configuration from a list of default paths
     *        from defaultTryPaths().
     */
    EmulatorConfiguration();

    /**
     * \brief Attempts to load the miner configuration from the given file.
     * \param[in] filename The filename to load the configuration from.
     */
    EmulatorConfiguration(std::string const & filename);

    /**
     * \brief Attempts to the miner configuration from the given list of paths.
     * \param[in] tryPaths The paths to try to load the configuration file from.
     */
    EmulatorConfiguration(std::vector<std::string> const & tryPaths);

    std::string const & accessPolicyFilename() const noexcept
    { return m_accessPolicyFilename; }

    AccessPolicy const & accessPolicy() const noexcept
    { return m_accessPolicy; }

    std::string const & defaultUser() const noexcept
    { return m_defaultUser; }

    /** \returns a vector of try paths consisting of the XDG configuration paths
                 suffixed with /sharemind/emulator.conf, and the path
                 /etc/sharemind/emulator.conf. */
    static std::vector<std::string> const & defaultTryPaths();

    /** \returns a vector of try paths for the access policy file, consisting of
                 the XDG configuration paths suffixed with
                 /sharemind/emulator-access-control.conf, and the path
                 /etc/sharemind/emulator-access-control.conf. */
    static std::vector<std::string> const & defaultAccessPolicyTryPaths();

    inline std::vector<FacilityModuleEntry> const & facilityModuleList()
            const noexcept
    { return m_facilityModuleList; }

    inline std::vector<ModuleEntry> const & moduleList() const noexcept
    { return m_moduleList; }

    inline std::vector<ProtectionDomainEntry> const & protectionDomainList()
            const noexcept
    { return m_protectionDomainList; }

private: /* Fields: */

    std::string m_accessPolicyFilename;
    AccessPolicy m_accessPolicy;

    /** The default user to use for access control. */
    std::string m_defaultUser;

    /** The facility module list: */
    std::vector<FacilityModuleEntry> m_facilityModuleList;

    /** The module list: */
    std::vector<ModuleEntry> m_moduleList;

    /** The protection domain list: */
    std::vector<ProtectionDomainEntry> m_protectionDomainList;

}; /* class EmulatorConfiguration { */

#endif /* SHAREMIND_EMULATOR_EMULATORCONFIGURATION_H */
