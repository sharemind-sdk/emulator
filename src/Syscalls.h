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

#ifndef SHAREMIND_EMULATOR_SYSCALLS_H
#define SHAREMIND_EMULATOR_SYSCALLS_H

#include <map>
#include <sharemind/Datum.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <sharemind/SimpleUnorderedStringMap.h>
#include <string>


namespace sharemind {

extern std::map<std::string, SharemindSyscallWrapper const> const
       staticSyscallWrappers __attribute__((visibility("internal")));
extern SimpleUnorderedStringMap<Datum> processArguments
        __attribute__((visibility("internal")));
extern int processResultsStream __attribute__((visibility("internal")));

} /* namespace sharemind { */

#endif /* SHAREMIND_EMULATOR_SYSCALLS_H */
