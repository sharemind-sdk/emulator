/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
 */

#ifndef SHAREMIND_EMULATOR_ACCESSPOLICY_H
#define SHAREMIND_EMULATOR_ACCESSPOLICY_H

#include <memory>
#include <sharemind/AccessControlProcessFacility.h>
#include <sharemind/Concepts.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <sharemind/Hash.h>
#include <sharemind/Optional.h>
#include <sharemind/SimpleUnorderedStringMap.h>
#include <sharemind/UnorderedMap.h>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>


namespace sharemind {

class ServerAuthData;

class AccessPolicy {

public: /* Types: */

    SHAREMIND_DECLARE_EXCEPTION_CONST_STDSTRING_NOINLINE(sharemind::Exception,
                                                         Exception);

    using ObjectPermissions = AccessControlProcessFacility::ObjectPermissions;

    /** Mapping of object permissions namespace names to object permissions
        maps: */
    using ObjectPermissionsNamespaces =
            SimpleUnorderedStringMap<ObjectPermissions>;

    using UserMapping =
            SimpleUnorderedStringMap<
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

} /* namespace sharemind { */

#endif /* SHAREMIND_EMULATOR_ACCESSPOLICY_H */
