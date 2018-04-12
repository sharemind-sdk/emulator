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

#include "AccessPolicy.h"

#include <algorithm>
#include <cassert>
#include <sharemind/Concat.h>
#include <sharemind/compiler-support/GccNoreturn.h>
#include <sharemind/libconfiguration/Configuration.h>
#include <sharemind/MakeUnique.h>
#include <utility>


namespace sharemind {

namespace {

template <typename ... Args>
inline AccessPolicy::Exception constructApe(Args && ... args)
{ return AccessPolicy::Exception(concat(std::forward<Args>(args)...)); }

template <typename ... Args>
SHAREMIND_GCC_NORETURN_PART1
inline void throwApe(Args && ... args) SHAREMIND_GCC_NORETURN_PART2
{ throw constructApe(std::forward<Args>(args)...); }

template <typename ... Args>
SHAREMIND_GCC_NORETURN_PART1
inline void throwWithNestedApe(Args && ... args) SHAREMIND_GCC_NORETURN_PART2
{ std::throw_with_nested(constructApe(std::forward<Args>(args)...)); }

template <typename SpecTermAdder>
void parseAccessSpecification(std::string const & specStr,
                              SpecTermAdder addTerm)
{
    /* NOTE THAT WE CONSIDER A COMMA ALSO TO BE WHITESPACE, hence strings like
        ",,alice, ,, ,,bob,," are completely valid. */
    static auto const isWhiteSpace =
            [](char const c) {
                switch (c) {
                case ' ': case '\t': case '\r': case '\n': case ',':
                    return true;
                default:
                    return false;
                }
            };

    static auto const isNegationMark = [](char const c) { return c == '!'; };

    if (specStr.empty())
        return;

    auto const end(specStr.end());
    auto s(specStr.begin());

    // Skip initial whitespace:
    while (isWhiteSpace(*s))
        if (++s == end)
            return;

    static char const unexpectedExclamationMarkStr[] =
            "Unexpected exclamation mark in access specification!";
    for (;;) { // Extract subjects:
        assert(!isWhiteSpace(*s));

        // Extract optional negation mark:
        bool subjectIsNegated;
        if (isNegationMark(*s)) {
            ++s;
            if ((s == end) || (isNegationMark(*s)))
                throwApe(unexpectedExclamationMarkStr);
            if (isWhiteSpace(*s))
                throwApe("Exclamation mark not directly followed by subject in "
                         "access specification!");
            subjectIsNegated = true;
        } else {
            subjectIsNegated = false;
        }

        // Extract subject:
        auto const subjectBegin(s);
        do {
            ++s;
            if (s == end) {
                addTerm(subjectBegin, s, subjectIsNegated);
                return;
            }
            if (isNegationMark(*s))
                throwApe(unexpectedExclamationMarkStr);
        } while (!isWhiteSpace(*s));
        addTerm(subjectBegin, s, subjectIsNegated);

        // Skip whitespace following subject:
        do {
            if (++s == end)
                return;
        } while (isWhiteSpace(*s));
    }
}

void checkValidUsername(std::string const & username) {
    if (username.empty())
        throwApe("Empty user name detected!");
    bool first = true;
    for (char const c : username) {
        switch (c) {
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        case 'G': case 'H': case 'I': case 'J': case 'K': case 'L':
        case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
        case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
        case 'Y': case 'Z':
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
        case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
        case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
        case 's': case 't': case 'u': case 'v': case 'w': case 'x':
        case 'y': case 'z':
            break;
        case '1': case '2': case '3': case '4': case '5': case '6':
        case '7': case '8': case '9': case '0':
        case '_':
            if (first)
                throwApe("Character '", c,
                         "' is not allowed as first character of username!");
            break;
        default:
            throwApe("Invalid character in user name!");
        }
        first = false;
    }
}

} // anonymous namespace

SHAREMIND_DEFINE_EXCEPTION_CONST_STDSTRING_NOINLINE(sharemind::Exception,
                                                    AccessPolicy::,
                                                    Exception);

AccessPolicy::AccessPolicy(std::vector<std::string> const & tryPaths) {
    Configuration const conf(tryPaths);
    auto loadException(constructApe("Failed to load access policies from \"",
                                    conf.filename(), "\"!"));
    try {

        /* First, we parse all users directly to m_userMapping, and all rulesets
           to rawRulesets: */
        /// \todo Are the following the most effective containers?
        using RawAccessSpecification = SimpleUnorderedStringMap<AccessResult>;
        using RawRuleset = SimpleUnorderedStringMap<RawAccessSpecification>;
        using RawRulesets = SimpleUnorderedStringMap<RawRuleset>;
        RawRulesets rawRulesets;
        for (auto const & sp : conf) {
            static char const rulesetSectionPrefix[] = "Ruleset ";
            static char const userSectionPrefix[] = "User ";
            #define SP_KEY_HAS_PREFIX(prefix) \
                std::equal(prefix, \
                           prefix + (sizeof(prefix) - 1u), \
                           sp.key().c_str())
            #define SP_KEY_WITHOUT_PREFIX(prefix) \
                sp.key().substr(sizeof(prefix) - 1u)
            if (SP_KEY_HAS_PREFIX(rulesetSectionPrefix)) {
                auto rulesetName(SP_KEY_WITHOUT_PREFIX(rulesetSectionPrefix));
                if (rulesetName.empty())
                    throwApe("Empty ruleset name detected!");
                if (rawRulesets.find(rulesetName) != rawRulesets.end())
                    throwApe("Duplicate ruleset name detected: ",
                             std::move(rulesetName));
                if (!sp.empty()) {
                    RawRuleset rules;
                    try {
                        for (auto const & rp : sp) {
                            assert(!rp.key().empty());
                            if (rules.find(rp.key()) != rules.end())
                                throwApe("Multiple rules for same object "
                                         "detected: ", rp.key());
                            std::string objectName(rp.key());
                            RawAccessSpecification spec;
                            try {
                                using SCIt = std::string::const_iterator;
                                parseAccessSpecification(
                                    rp.value<std::string>(),
                                    [&spec](SCIt const begin,
                                            SCIt const end,
                                            bool const isNegated)
                                    {
                                        std::string subject(begin, end);
                                        checkValidUsername(subject);
                                        if (spec.find(subject) != spec.end())
                                            throwApe("Duplicate subject \"",
                                                     std::move(subject),
                                                     "\"in access "
                                                     "specification!");
                                        spec.emplace(std::move(subject),
                                                     isNegated
                                                     ? AccessResult::Denied
                                                     : AccessResult::Allowed);
                                    });
                            } catch (...) {
                                throwWithNestedApe("Failure during handling of "
                                                   "rule for object \"",
                                                   std::move(objectName),
                                                   "\"!");
                            }
                            if (!spec.empty()) {
                                spec.rehash(0u);
                                rules.emplace(std::move(objectName),
                                              std::move(spec));
                            }
                        }
                    } catch (...) {
                        throwWithNestedApe(
                                    "Failure during handling of ruleset \"",
                                    std::move(rulesetName), "\"!");
                    }
                    if (!rules.empty()) {
                        rules.rehash(0u);
                        rawRulesets.emplace(std::move(rulesetName),
                                            std::move(rules));
                    }
                }
            } else if (SP_KEY_HAS_PREFIX(userSectionPrefix)) {
                auto username(SP_KEY_WITHOUT_PREFIX(userSectionPrefix));
                try {
                    checkValidUsername(username);
                } catch (...) {
                    throwWithNestedApe("Failed to parse user definition!");
                }
                if (m_userMapping.find(username) != m_userMapping.end())
                    throwApe("Duplicate user name detected: ",
                             std::move(username));

                m_userMapping.emplace(
                            std::move(username),
                            std::make_shared<ObjectPermissionsNamespaces>());
            } else {
                throwApe("Invalid section: \"", sp.key(), "\"!");
            }
        }

        /* Second, we check if all users in the access specifications in
           rawRulesets were actually defined by the [User <name>] sections, and
           at the same time remap the rulesets per-user to m_users: */
        for (auto const & rulesetPair: rawRulesets) {
            auto const & rulesetName = rulesetPair.first;
            try {
                for (auto const & rulePair: rulesetPair.second) {
                    auto const & objectName = rulePair.first;
                    try {
                        for (auto const & subjectPair: rulePair.second) {
                            auto const & subjectName = subjectPair.first;

                            // Check if subject exists:
                            auto const userPairIt(
                                        m_userMapping.find(subjectName));
                            if (userPairIt == m_userMapping.end())
                                throwApe("User \"", subjectName,
                                         "\" not defined!");

                            // Remap rule:
                            auto & userPermissions = *userPairIt->second;
                            userPermissions[rulesetName][objectName] =
                                    subjectPair.second;
                        }
                    } catch (...) {
                        throwWithNestedApe("Failure during handling of rule "
                                           "for object \"", rulePair.first,
                                           "\"!");
                    }
                }
            } catch (...) {
                throwWithNestedApe("Failure during handling of ruleset \"",
                                   std::move(rulesetPair.first), "\"!");
            }
        }
    } catch (...) {
        std::throw_with_nested(std::move(loadException));
    }
}

AccessPolicy::AccessPolicy(AccessPolicy &&) noexcept = default;

AccessPolicy::AccessPolicy(AccessPolicy const & copy) = default;

AccessPolicy & AccessPolicy::operator=(AccessPolicy &&) = default;

AccessPolicy & AccessPolicy::operator=(AccessPolicy const & copy) = default;

} /* namespace sharemind { */
