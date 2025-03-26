/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.response

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler

/**
 * A utility object capable of extracting the ResponseFingerprint from a given SSH attacker state and receive action.
 */
object ResponseExtractor {
    /**
     * Extracts the response fingerprint of the receiving action from the provided state.
     *
     * @param state The state of the SSH attacker.
     * @param action The receiving action to extract the response fingerprint for.
     * @return A response fingerprint indicating the received messages as well as the socket state.
     */
    fun getFingerprint(state: State, action: ReceivingAction): ResponseFingerprint {
        val messages = action.receivedMessages
        normalizeUnknownMessages(messages)
        val socketState = extractSocketState(state)
        return ResponseFingerprint(messages, socketState, false)
    }

    private fun normalizeUnknownMessages(messages: List<ProtocolMessage<*>>) {
        for (message in messages) {
            if (message is UnknownMessage) {
                message.setMessageId(0)
                message.setPayload(ByteArray(0))
            }
        }
    }

    /**
     * Extracts the response fingerprint of the last receiving action executed on the provided state.
     *
     * @param state The state of the SSH attacker.
     */
    fun getFingerprint(state: State): ResponseFingerprint {
        val action = state.workflowTrace.lastReceivingAction
        return getFingerprint(state, action)
    }

    /**
     * Extracts the socket state of the underlying transport handler.
     *
     * @param state The state of the SSH attacker.
     */
    private fun extractSocketState(state: State): SocketState {
        return when (val transportHandler = state.sshContext.transportHandler) {
            is TcpTransportHandler -> transportHandler.socketState
            else -> {
                TODO("Unsupported transport handler, unable to extract socket state")
            }
        }
    }
}
