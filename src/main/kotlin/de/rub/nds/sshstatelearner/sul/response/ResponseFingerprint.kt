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

data class ResponseFingerprint(val messages: List<Message<*>>, var socketState: SocketState) {

    override fun toString(): String {
        val messagesString = messages.joinToString(",") { it.toCompactString() }
        return "ResponseFingerprint[messages=[$messagesString],socketState=$socketState]"
    }

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

    override fun hashCode(): Int {
        var result = socketState.hashCode()
        messages.forEach { result = 31 * result + it.javaClass.hashCode() }
        return result
    }
}
