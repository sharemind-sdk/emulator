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

#ifndef SHAREMIND_EMULATOR_CONFIGURATION_H
#define SHAREMIND_EMULATOR_CONFIGURATION_H

#include <exception>
#include <sharemind/Exception.h>
#include <string>
#include <utility>
#include <vector>


namespace sharemind {

/** \brief Parses and stores the configuration for a miner from a file. */
class Configuration {

public: /* Types: */

    SHAREMIND_DEFINE_EXCEPTION(std::exception, Exception);
    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(Exception,
                                         ParseException,
                                         "Failed to parse configuration file!");
    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG(
            Exception,
            DuplicatePdNameException,
            "Duplicate protection domain name in configuration!");

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
     * \brief Reads the miner configuration from given section of the given file.
     * \throws Exception on parse or configuration error.
     */
    Configuration(std::string const & filename);

    inline std::vector<FacilityModuleEntry> const & facilityModuleList()
            const noexcept
    { return m_facilityModuleList; }

    inline std::vector<ModuleEntry> const & moduleList() const noexcept
    { return m_moduleList; }

    inline std::vector<ProtectionDomainEntry> const & protectionDomainList()
            const noexcept
    { return m_protectionDomainList; }


private: /* Fields: */

    /** The facility module list: */
    std::vector<FacilityModuleEntry> m_facilityModuleList;

    /** The module list: */
    std::vector<ModuleEntry> m_moduleList;

    /** The protection domain list: */
    std::vector<ProtectionDomainEntry> m_protectionDomainList;

}; /* class Configuration { */

} /* namespace sharemind { */

#endif /* SHAREMIND_EMULATOR_CONFIGURATION_H */
