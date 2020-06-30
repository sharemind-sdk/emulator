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

#ifndef SHAREMIND_EMULATOR_COMMANDLINEARGUMENTS_H
#define SHAREMIND_EMULATOR_COMMANDLINEARGUMENTS_H

#include <fcntl.h>
#include <sharemind/Datum.h>
#include <sharemind/SimpleUnorderedStringMap.h>


struct CommandLineArguments {

/* Types: */

    using ProcessArguments =
            sharemind::SimpleUnorderedStringMap<sharemind::Datum>;

/* Methods: */

    CommandLineArguments();

    void init(int const argc, char const * const argv[]);

/* Types: */

    ProcessArguments m_processArguments;
    char const * m_configurationFilename = nullptr;
    char const * m_user = nullptr;
    char const * m_bytecodeFilename = nullptr;
    char const * m_outFilename = nullptr;
    int m_outOpenFlag = O_EXCL;
    bool m_justExit = false;

};

int openOutFile(char const * const filename, int const openFlag);

#endif /* SHAREMIND_EMULATOR_COMMANDLINEARGUMENTS_H */
