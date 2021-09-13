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

/**
 * A generic message symbol representing a single message being sent as well as capturing the SSH peers response by
 * performing a single retrieve action.
 *
 * @param message The message to send when this symbol is executed.
 * @param receiveDelay A delay to wait between sending and retrieving. If no delay is being used, chances are that the
 *                     resulting response fingerprint is incomplete and thus inconsistent.
 */
class GenericMessageSymbol(private val message: Message<*>, private val receiveDelay: Long) : SshSymbol() {

    companion object : LoggerCompanion()

    /**
     * A generic message symbol representing a single message being sent as well as capturing the SSH peers response by
     * performing a single retrieve action.
     *
     * @param message The message to send when this symbol is executed.
     */
    constructor(message: Message<*>) : this(message, DEFAULT_RECEIVE_DELAY)

    /**
     * Executes the GenericMessageSymbol by sending the message as well as retrieving the peers' response after
     * the specified receive delay.
     *
     * @param state The state of the SSH attacker to execute this symbol on.
     * @return The remote peers' response fingerprint.
     */
    override fun execute(state: State): ResponseFingerprint {
        LOGGER.trace("Sending message: ${message.toCompactString()}")
        message.getPreparator(state.sshContext).prepare()
        sendMessage(message, state)
        Thread.sleep(receiveDelay)
        return retrieveMessages(state)
    }

    /**
     * Serializes the symbol into a human-readable form for easier debugging and visualization.
     *
     * @return A string representing this symbol.
     */
    override fun toString(): String {
        return "${javaClass.simpleName}[message=${message.toCompactString()}]"
    }

    /**
     * Checks whether the provided object matches this one. Two GenericMessageClasses are considered equal
     * if their message class is equal.
     *
     * @return True when the provided object is equivalent to this instance. False otherwise.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GenericMessageSymbol

        if (message.javaClass != other.message.javaClass) return false

        return true
    }

    /**
     * Returns the hash code of the underlying message class to ensure consistency with the equals() method.
     *
     * @return Hash code of the underlying message class.
     */
    override fun hashCode(): Int {
        return message.javaClass.hashCode()
    }
}
