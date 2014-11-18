/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
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
    Configuration(const std::string & filename);

    inline const std::vector<FacilityModuleEntry> & facilityModuleList() const noexcept
    { return m_facilityModuleList; }

    inline const std::vector<ModuleEntry> & moduleList() const noexcept
    { return m_moduleList; }

    inline const std::vector<ProtectionDomainEntry> & protectionDomainList()
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
