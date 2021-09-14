/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

import de.learnlib.api.exception.SULException
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException
import de.rub.nds.sshattacker.core.protocol.common.Message
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.protocol.util.SendMessageHelper
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.GenericReceiveAction
import de.rub.nds.sshstatelearner.sul.response.ResponseExtractor
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import java.io.IOException

/**
 * An abstract superclass to all SSH related symbols.
 */
abstract class AbstractSshSymbolImpl {

    /**
     * Executes the symbol on the provided state and returns the output of the SSH peer.
     *
     * @param state The state of the SSH attacker to execute this symbol on.
     * @return The response fingerprint returned by the SSH peer.
     */
    abstract fun execute(state: State): ResponseFingerprint

    /**
     * A simple wrapper to send a single message to the SSH peer.
     *
     * @param message Message to send.
     * @param state The state of the SSH attacker to send this message on.
     */
    protected fun sendMessage(message: Message<*>, state: State) {
        val helper = SendMessageHelper()
        try {
            if (message is VersionExchangeMessage) {
                helper.sendVersionExchangeMessage(message, state.sshContext)
            } else {
                helper.sendMessage(message, state.sshContext)
            }
        } catch (e: IOException) {
            throw SULException(e)
        }
    }

    /**
     * A simple wrapper to retrieve messages from the SSH peer.
     *
     * @param state The state of the SSH attacker to retrieve messages on.
     * @return The response fingerprint returned by the SSH peer.
     */
    protected fun retrieveMessages(state: State): ResponseFingerprint {
        try {
            if (state.sshContext.transportHandler.isClosed) {
                return ResponseFingerprint(listOf(), SocketState.CLOSED)
            }
        } catch (e: IOException) {
            throw SULException(e)
        }
        try {
            val action = GenericReceiveAction("client")
            try {
                action.execute(state)
            } catch (e: AdjustmentException) {
            }
            return ResponseExtractor.getFingerprint(state, action)
        } catch (e: IOException) {
            throw SULException(e)
        }
    }
}
