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

#include <memory>
#include <sharemind/libvm/Vm.h>
#include "CommandLineArguments.h"


#define EMULATOR_SYSCALL(name) \
    void name( \
            std::vector<::SharemindCodeBlock> & args, \
            std::vector<sharemind::Vm::Reference> & refs, \
            std::vector<sharemind::Vm::ConstReference> & crefs, \
            SharemindCodeBlock * const returnValue, \
            sharemind::Vm::SyscallContext & c)

EMULATOR_SYSCALL(blockingRandomize) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(blockingURandomize) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(nonblockingRandomize) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(nonblockingURandomize) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(Process_logMicroseconds)
        __attribute__((visibility("internal")));
EMULATOR_SYSCALL(Process_argument) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(Process_setResult) __attribute__((visibility("internal")));
EMULATOR_SYSCALL(Process_logString) __attribute__((visibility("internal")));

extern CommandLineArguments::ProcessArguments processArguments
        __attribute__((visibility("internal")));

extern int processResultsStream __attribute__((visibility("internal")));

#endif /* SHAREMIND_EMULATOR_SYSCALLS_H */
