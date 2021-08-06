/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.response

import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler

object ResponseExtractor {
    fun getFingerprint(state: State, action: ReceivingAction): ResponseFingerprint {
        val messages = action.receivedMessages
        val socketState = extractSocketState(state)
        return ResponseFingerprint(messages, socketState)
    }

    fun getFingerprint(state: State): ResponseFingerprint {
        val action = state.workflowTrace.lastReceivingAction
        return getFingerprint(state, action)
    }

    private fun extractSocketState(state: State): SocketState {
        return when (val transportHandler = state.sshContext.transportHandler) {
            is TcpTransportHandler -> transportHandler.socketState
            else -> {
                TODO("Unsupported transport handler, unable to extract socket state")
            }
        }
    }
}
