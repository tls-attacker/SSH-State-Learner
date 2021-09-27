/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms.symbols

import de.rub.nds.sshattacker.core.protocol.common.Message
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

/**
 * A generic message symbol implementation representing a single message being sent as well as capturing the SSH
 * peers response by performing a single retrieve action.
 *
 * @param message The message to send when this symbol is executed.
 * @param retrieveDelay The delay between sending the message and retrieving the peers' response. By default, this value
 *                      is initialized to 150 ms.
 */
class GenericMessageSymbol(private val message: Message<*>, private val retrieveDelay: Long = 150) : AbstractSshSymbol() {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Executes the GenericMessageSymbolImpl by sending the message as well as retrieving the peers' response.
     *
     * @param state The state of the SSH attacker to execute this symbol on.
     * @return The remote peers' response fingerprint.
     */
    override fun execute(state: State): ResponseFingerprint {
        LOGGER.trace("Sending message: ${message.toCompactString()}")
        message.getPreparator(state.sshContext).prepare()
        sendMessage(message, state)
        Thread.sleep(retrieveDelay)
        return retrieveMessages(state)
    }

    /**
     * Serializes the symbol implementation into a human-readable form for easier debugging and visualization.
     *
     * @return A string representing this symbol.
     */
    override fun toString(): String {
        return message.toCompactString()
    }
}
