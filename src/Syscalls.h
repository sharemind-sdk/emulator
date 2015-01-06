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
#include <sharemind/controller/IController.h>
#include <sharemind/libmodapi/libmodapicxx.h>
#include <string>


namespace sharemind {

extern const std::map<std::string, const SharemindSyscallWrapper>
       staticSyscallWrappers;
extern IController::ValueMap processArguments;
extern int processResultsStream;

} /* namespace sharemind { */

#endif /* SHAREMIND_EMULATOR_SYSCALLS_H */
