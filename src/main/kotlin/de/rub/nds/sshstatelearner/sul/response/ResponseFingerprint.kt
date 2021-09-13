/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.response

import de.rub.nds.sshattacker.core.protocol.common.Message
import de.rub.nds.tlsattacker.transport.socket.SocketState

/**
 * A data class representing a single response of an SSH peer. It contains the returned messages as well as
 * the socket state after retrieving these messages.
 *
 * @param messages Messages retrieved from the SSH peer.
 * @param socketState State of the underlying network socket after retrieving the messages.
 */
data class ResponseFingerprint(val messages: List<Message<*>>, var socketState: SocketState) {

    /**
     * Serializes the response fingerprint into a human-readable string.
     *
     * @return A string representing this response fingerprint.
     */
    override fun toString(): String {
        val messagesString = messages.joinToString(",") { it.toCompactString() }
        return "ResponseFingerprint[messages=[$messagesString],socketState=$socketState]"
    }

    /**
     * Checks whether the provided object is equal to this fingerprint. Two response fingerprints are considered
     * equal if both response fingerprints contain the same message types (in the same order) and their socket
     * states are equal.
     *
     * @param other The object which is being checked for equality with this.
     * @return True if both objects are considered equal. False otherwise.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass)
            return false

        other as ResponseFingerprint

        if (messages.size == other.messages.size) {
            messages.zip(other.messages).forEach {
                if (it.first.javaClass != it.second.javaClass) {
                    return false
                }
            }
        } else {
            return false
        }
        if (socketState != other.socketState)
            return false

        return true
    }

    /**
     * Computes a unique hash code based upon the socket state as well as the message classes. If the hash code
     * of two instances of this class are equal, the objects are considered equal.
     *
     * @return The hash code of this response fingerprint.
     */
    override fun hashCode(): Int {
        var result = socketState.hashCode()
        messages.forEach { result = 31 * result + it.javaClass.hashCode() }
        return result
    }
}
