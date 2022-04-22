/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms.symbols

import de.rub.nds.sshattacker.core.protocol.common.SshMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

/**
 * A generic message symbol implementation representing a single message being sent wrapped in the binary packet
 * protocol (BPP) as well as capturing the SSH peers response by performing a single retrieve action.
 *
 * @param message The message to send when this symbol is executed.
 * @param retrieveDelay The delay between sending the message and retrieving the peers' response. By default, this value
 *                      is initialized to 150 ms.
 */
class BppMessageSymbol(private val message: SshMessage<*>, private val retrieveDelay: Long = 150) : AbstractSshSymbol() {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Executes the BppMessageSymbol by sending the message as well as retrieving the peers' response. If the context
     * is not initialized to send binary packets, the packet layer type and packet layer will be changed to binary
     * packet.
     *
     * @param state The state of the SSH attacker to execute this symbol on.
     * @return The remote peers' response fingerprint.
     */
    override fun execute(state: State): ResponseFingerprint {
        LOGGER.trace("Sending message as binary packet: ${message.toCompactString()}")
        message.getHandler(state.sshContext).preparator.prepare()
        sendMessage(message, state)
        Thread.sleep(retrieveDelay)
        return retrieveMessages(state)
    }

    /**
     * Serializes the symbol implementation into a human-readable form for easier debugging and visualization.
     *
     * @return A string representing this symbol.
     */
    override fun toString(): String =
        "${message.toCompactString()} (binary packet)"
}
