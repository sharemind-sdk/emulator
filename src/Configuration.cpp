/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
 */

#include "Configuration.h"

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/xpressive/xpressive_static.hpp>


namespace sharemind {

Configuration::Configuration(const std::string & filename) {
    try {
        boost::property_tree::ptree config;
        boost::property_tree::read_ini(filename, config);

        // Load module and protection domain lists:
        for (const boost::property_tree::ptree::value_type & v : config) {
            const std::string & section(v.first);
            if (section.find("FacilityModule") == 0u) {
                m_facilityModuleList.emplace_back(
                        FacilityModuleEntry{
                            v.second.get<std::string>("File"),
                            v.second.get<std::string>("Configuration", "")});
            } else if (section.find("Module") == 0u) {
                m_moduleList.emplace_back(
                        ModuleEntry{
                            v.second.get<std::string>("File"),
                            v.second.get<std::string>("Configuration", "")});
            } else if (section.find("ProtectionDomain") == 0u) {
                ProtectionDomainEntry newProtectionDomain;
                // check if new MinerNode is unique
                for (const ProtectionDomainEntry & e : m_protectionDomainList)
                    if (e.name == newProtectionDomain.name)
                        throw DuplicatePdNameException();

                // Now we have found a unique ProtectionDomainX section.
                newProtectionDomain.name = v.second.get<std::string>("Name");
                newProtectionDomain.kind = v.second.get<std::string>("Kind");
                newProtectionDomain.configurationFile =
                        v.second.get<std::string>("Configuration");
                m_protectionDomainList.emplace_back(
                            std::move(newProtectionDomain));
            }
        }
    } catch (const boost::property_tree::ptree_error & error) {
        std::throw_with_nested(ParseException());
    }
}

} // namespace sharemind {
