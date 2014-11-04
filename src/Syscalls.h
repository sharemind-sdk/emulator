/*
 * This file is a part of the Sharemind framework.
 * Copyright (C) Cybernetica AS
 *
 * All rights are reserved. Reproduction in whole or part is prohibited
 * without the written consent of the copyright owner. The usage of this
 * code is subject to the appropriate license agreement.
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

class ProcessArguments: public IController::ValueMap {

public: /* Methods: */

    using IController::ValueMap::operator=;

public: /* Fields: */

    static ProcessArguments instance;

};

struct ProcessResults {

    static int outputStream;

};

} /* namespace sharemind { */

#endif /* SHAREMIND_EMULATOR_SYSCALLS_H */
