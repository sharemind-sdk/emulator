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

#include "EmulatorConfiguration.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/xpressive/xpressive_static.hpp>
#include <sharemind/libconfiguration/XdgBaseDirectory.h>


namespace sharemind {

EmulatorConfiguration::EmulatorConfiguration()
    : Configuration(defaultTryPaths())
{ init(); }

EmulatorConfiguration::EmulatorConfiguration(std::string const & filename)
    : Configuration(filename)
{ init(); }

EmulatorConfiguration::EmulatorConfiguration(
        std::vector<std::string> const & tryPaths)
    : Configuration(tryPaths)
{ init(); }

std::vector<std::string> const & EmulatorConfiguration::defaultTryPaths() {
    static std::vector<std::string> const tryPaths(
                Configuration::defaultSharemindToolTryPaths("emulator"));
    return tryPaths;
}

void EmulatorConfiguration::init() {
    try {
        // Load module and protection domain lists:
        for (auto const & v : *this) {
            auto const section(v.key());
            if (section.find("FacilityModule") == 0u) {
                m_facilityModuleList.emplace_back(
                        FacilityModuleEntry{
                            v.get<std::string>("File"),
                            v.get<std::string>("Configuration", "")});
            } else if (section.find("Module") == 0u) {
                m_moduleList.emplace_back(
                        ModuleEntry{
                            v.get<std::string>("File"),
                            v.get<std::string>("Configuration", "")});
            } else if (section.find("ProtectionDomain ") == 0u) {
                auto pdName(section.substr(17, section.size()));
                if (pdName.empty())
                    throw EmptyPdNameException();
                // check if new protection domain is unique
                for (ProtectionDomainEntry const & e : m_protectionDomainList)
                    if (e.name == pdName)
                        throw DuplicatePdNameException{};

                // Now we have found a unique ProtectionDomainX section.
                ProtectionDomainEntry newProtectionDomain;
                newProtectionDomain.name = pdName;
                newProtectionDomain.kind = v.get<std::string>("Kind");
                newProtectionDomain.configurationFile =
                        v.get<std::string>("Configuration");
                m_protectionDomainList.emplace_back(
                            std::move(newProtectionDomain));
            }
        }
    } catch (...) {
        std::throw_with_nested(ParseException{});
    }
}

} // namespace sharemind {
