/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.exceptions

import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.word.Word

class CacheConflictException(
    message: String,
    val inputPrefix: Word<SshSymbol>,
    val inputSuffix: Word<SshSymbol>,
    val expectedOutput: Word<ResponseFingerprint>,
    val actualOutput: Word<ResponseFingerprint>
) : Exception(message) {
    init {
        if (inputSuffix.length() != expectedOutput.length() || inputSuffix.length() != actualOutput.length()) {
            throw IllegalArgumentException("Input suffix, expected and actual output words are not of equal length")
        }
    }
}
