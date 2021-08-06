/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

import de.rub.nds.sshattacker.core.protocol.common.Message
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.LoggerCompanion

class GenericMessageSymbol(private val message: Message<*>) : SshSymbol() {

    companion object : LoggerCompanion()

    override fun execute(state: State): ResponseFingerprint {
        LOGGER.trace("Sending message: ${message.toCompactString()}")
        message.getPreparator(state.sshContext).prepare()
        sendMessage(message, state)
        Thread.sleep(100)
        return retrieveMessages(state)
    }

    override fun toString(): String {
        return "${javaClass.simpleName}[message=${message.toCompactString()}]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GenericMessageSymbol

        if (message.javaClass != other.message.javaClass) return false

        return true
    }

    override fun hashCode(): Int {
        return message.javaClass.hashCode()
    }
}
