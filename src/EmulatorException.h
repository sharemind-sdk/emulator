/*
 * Copyright (C) Cybernetica
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

#ifndef SHAREMIND_EMULATOR_EMULATOREXCEPTION_H
#define SHAREMIND_EMULATOR_EMULATOREXCEPTION_H

#include <exception>
#include <sharemind/Concat.h>
#include <sharemind/Exception.h>
#include <sharemind/ExceptionMacros.h>
#include <system_error>
#include <utility>


SHAREMIND_DECLARE_EXCEPTION_NOINLINE(sharemind::Exception, EmulatorException);

#define DEFINE_EXCEPTION_STR(name) \
    SHAREMIND_DECLARE_EXCEPTION_CONST_STDSTRING_NOINLINE(EmulatorException, \
                                                         name); \
    SHAREMIND_DEFINE_EXCEPTION_CONST_STDSTRING_NOINLINE(EmulatorException,, \
                                                        name)
#define DEFINE_EXCEPTION_CONST_MSG(name, ...) \
    SHAREMIND_DECLARE_EXCEPTION_CONST_MSG_NOINLINE(EmulatorException, name); \
    SHAREMIND_DEFINE_EXCEPTION_CONST_MSG_NOINLINE(EmulatorException,, \
                                                  name, \
                                                  __VA_ARGS__)

template <typename Exception, typename ... Args>
Exception constructConcatException(Args && ... args)
{ return Exception(sharemind::concat(std::forward<Args>(args)...)); }

template <typename Exception, typename ... Args>
SHAREMIND_GCC_NORETURN_PART1
inline void throwConcatException(Args && ... args) SHAREMIND_GCC_NORETURN_PART2
{ throw constructConcatException<Exception>(std::forward<Args>(args)...); }

template <typename Exception, typename ... Args>
SHAREMIND_GCC_NORETURN_PART1
inline void throwWithNestedConcatException(Args && ... args)
        SHAREMIND_GCC_NORETURN_PART2
{
    std::throw_with_nested(
                constructConcatException<Exception>(
                    std::forward<Args>(args)...));
}

#define NESTED_SYSTEM_ERROR(Exception,str,...) \
    do { \
        try { \
            throw std::system_error{errno, std::system_category()}; \
        } catch (...) { \
            throwWithNestedConcatException<Exception>(str, __VA_ARGS__); \
        } \
    } while(false)

#define NESTED_SYSTEM_ERROR2(...) \
    do { \
        try { \
            throw std::system_error{errno, std::system_category()}; \
        } catch (...) { \
            std::throw_with_nested(__VA_ARGS__); \
        } \
    } while(false)

#endif /* SHAREMIND_EMULATOR_EMULATOREXCEPTION_H */
