/*
 * Copyright (C) 2018 Cybernetica
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

#ifndef SHAREMIND_EMULATOR_ACCESSPOLICY_H
#define SHAREMIND_EMULATOR_ACCESSPOLICY_H

#include <memory>
#include <sharemind/AccessControlProcessFacility.h>
#include <sharemind/Concepts.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/Hash.h>
#include <sharemind/SimpleUnorderedStringMap.h>
#include <sharemind/UnorderedMap.h>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>


class AccessPolicy {

public: /* Types: */

    SHAREMIND_DECLARE_EXCEPTION_CONST_STDSTRING_NOINLINE(sharemind::Exception,
                                                         Exception);

    using ObjectPermissions =
            sharemind::AccessControlProcessFacility::ObjectPermissions;

    /** Mapping of object permissions namespace names to object permissions
        maps: */
    using ObjectPermissionsNamespaces =
            sharemind::SimpleUnorderedStringMap<ObjectPermissions>;

    using UserMapping =
            sharemind::SimpleUnorderedStringMap<
                    std::shared_ptr<ObjectPermissionsNamespaces> >;

public: /* Methods: */

    AccessPolicy(std::vector<std::string> const & tryPaths);

    AccessPolicy(AccessPolicy &&) noexcept;
    AccessPolicy(AccessPolicy const &);

    AccessPolicy & operator=(AccessPolicy &&);
    AccessPolicy & operator=(AccessPolicy const &);

    UserMapping const & userMapping() const noexcept { return m_userMapping; }

private: /* Fields: */

    UserMapping m_userMapping;

}; /* class AccessPolicy */

#endif /* SHAREMIND_EMULATOR_ACCESSPOLICY_H */
